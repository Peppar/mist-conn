#include <map>
#include <list>
#include <cassert>

#include <boost/system/system_error.hpp>
#include <boost/throw_exception.hpp>

#include "socket.hpp"

#include "error/nghttp2.hpp"
#include "error/mist.hpp"

#include "memory/nghttp2.hpp"

#include "h2/session.hpp"
#include "h2/stream.hpp"

namespace mist
{
namespace h2
{

Session::Session(Socket &sock, bool isServer)
  : sock(sock),
    h2session(to_unique<nghttp2_session>()),
    _isServer(isServer),
    _sending(false),
    _stopped(false),
    _insideCallback(false)
{
  /* Create the nghttp2_session_callbacks object */
  c_unique_ptr<nghttp2_session_callbacks> cbs
    = to_unique<nghttp2_session_callbacks>();
  {
    nghttp2_session_callbacks *cbsPtr = nullptr;
    nghttp2_session_callbacks_new(&cbsPtr);
    cbs = to_unique(cbsPtr);
  }
  
  /* Set on error callback */
  nghttp2_session_callbacks_set_error_callback(cbs.get(),
    [](nghttp2_session */*session*/, const char *message, std::size_t length,
       void *user_data) -> int
  {
    Session &sess = *static_cast<Session *>(user_data);
    std::cerr << "nghttp signalled error: " << std::string(message, length) << std::endl;
    return 0;
  });
  
  /* Set on begin headers callback */
  nghttp2_session_callbacks_set_on_begin_headers_callback(cbs.get(),
    [](nghttp2_session */*session*/, const nghttp2_frame *frame,
       void *user_data) -> int
  {
    Session &sess = *static_cast<Session *>(user_data);
    
    /* Detect new push streams */
    if (frame->hd.type == NGHTTP2_PUSH_PROMISE)
      sess.createPushStream(frame->push_promise.promised_stream_id);
    
    return 0;
  });
  
  /* Set on header callback */
  nghttp2_session_callbacks_set_on_header_callback(cbs.get(),
    [](nghttp2_session */*session*/, const nghttp2_frame *frame,
       const uint8_t *name, size_t namelen,
       const uint8_t *value, size_t valuelen, uint8_t flags,
       void *user_data) -> int
  {
    /* Delegate header to stream */      
    Session &sess = *static_cast<Session *>(user_data);
    boost::optional<Stream&> stream = sess.stream(frame->hd.stream_id);
    if (!stream)
      return 0;
    
    return stream->onHeader(frame, name, namelen, value, valuelen, flags);
  });
  
  /* Set on stream frame send callback */
  nghttp2_session_callbacks_set_on_frame_send_callback(cbs.get(),
    [](nghttp2_session */*session*/, const nghttp2_frame *frame,
       void *user_data) -> int
  {
    /* Delegate send event to stream */   
    Session &sess = *static_cast<Session *>(user_data);
    boost::optional<Stream&> stream = sess.stream(frame->hd.stream_id);
    if (!stream)
      return 0;
    
    return stream->onFrameSend(frame);
  });
  
  /* Set on frame not send callback */
  nghttp2_session_callbacks_set_on_frame_not_send_callback(cbs.get(),
    [](nghttp2_session */*session*/, const nghttp2_frame *frame,
       int errorCode, void *user_data) -> int
  {
    /* Delegate frame not send event to stream */   
    Session &sess = *static_cast<Session *>(user_data);
    boost::optional<Stream&> stream = sess.stream(frame->hd.stream_id);
    if (!stream)
      return 0;
    
    return stream->onFrameNotSend(frame, errorCode);
  });
  
  /* Set on frame receive callback */
  nghttp2_session_callbacks_set_on_frame_recv_callback(cbs.get(),
    [](nghttp2_session */*session*/, const nghttp2_frame *frame,
       void *user_data) -> int
  {
    /* Delegate frame receive event to stream */
    Session &sess = *static_cast<Session *>(user_data);
    boost::optional<Stream&> stream = sess.stream(frame->hd.stream_id);
    if (!stream)
      return 0;
    
    return stream->onFrameRecv(frame);
  });
  
  /* Set on data chunk receive callback */
  nghttp2_session_callbacks_set_on_data_chunk_recv_callback(cbs.get(),
    [](nghttp2_session */*session*/, uint8_t flags, int32_t stream_id,
       const uint8_t *data, size_t len, void *user_data) -> int
  {
    /* Delegate data chunk event to stream */
    Session &sess = *static_cast<Session *>(user_data);
    boost::optional<Stream&> stream = sess.stream(stream_id);
    if (!stream)
      return 0;

    return stream->onDataChunkRecv(flags, data, len);
  });

  /* Set on stream close callback */
  nghttp2_session_callbacks_set_on_stream_close_callback(cbs.get(),
    [](nghttp2_session */*session*/, int32_t stream_id,
       uint32_t error_code, void *user_data) -> int
  {
    /* Delegate stream close event to stream */   
    Session &sess = *static_cast<Session *>(user_data);
    boost::optional<Stream&> stream = sess.stream(stream_id);
    if (!stream)
      return 0;
    
    auto rv = stream->onStreamClose(error_code);
    
    /* Remove from the list of streams */
    sess.closeStream(stream.get());
    return rv;
  });
  
  /* Create the nghttp2_session and assign it to h2session */
  {
    nghttp2_session *sessPtr = nullptr;
    int rv;
    if (isServer) {
      rv = nghttp2_session_server_new(&sessPtr, cbs.get(), this);
    } else {
      rv = nghttp2_session_client_new(&sessPtr, cbs.get(), this);
    }
    if (rv) {
      BOOST_THROW_EXCEPTION(boost::system::system_error(
        make_nghttp2_error(static_cast<nghttp2_error>(rv)),
        "Unable to create nghttp2 session"));
    }
    h2session = to_unique(sessPtr);
  }
  
  /* Send connection settings */
  {
    std::vector<nghttp2_settings_entry> iv{
      {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100},
    };
    // if (!isServer)
    // iv.emplace_back(nghttp2_settings_entry{NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, NGHTTP2_INITIAL_WINDOW_SIZE});
    auto rv = nghttp2_submit_settings(h2session.get(), NGHTTP2_FLAG_NONE,
                                      iv.data(), iv.size());
    if (rv) {
      BOOST_THROW_EXCEPTION(boost::system::system_error(
        make_nghttp2_error(static_cast<nghttp2_error>(rv)),
        "Unable to send HTTP/2 settings"));
    }
  }
  
  /* Bind the socket read callback */
  {
    using namespace std::placeholders;
    sock.read(std::bind(&Session::readCallback, this, _1, _2, _3));
  }
  
  /* Write the first data */
  signalWrite();
  
  /* TODO: Figure out why this is necessary */
  /*const std::uint32_t windowSize = 256 * 1024 * 1024;
  std::array<nghttp2_settings_entry, 2> iv{
      {{NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100},
       // typically client is just a *sink* and just process data as
       // much as possible.  Use large window size by default.
      {NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, windowSize}}};
  nghttp2_submit_settings(h2session.get(), NGHTTP2_FLAG_NONE,
                          iv.data(), iv.size());
  
  // Increase connection window size up to window_size
  nghttp2_submit_window_update(h2session.get(), NGHTTP2_FLAG_NONE, 0,
                               windowSize - NGHTTP2_INITIAL_CONNECTION_WINDOW_SIZE);
*/
}

boost::optional<Stream&> 
Session::stream(std::int32_t streamId) {
  auto it = _streams.find(streamId);
  if (it == _streams.end())
    return boost::none;
  return *it->second;
}

bool
Session::isStopped() const 
{
  return _stopped;
}

bool
Session::isServer() const
{
  return _isServer;
}

std::unique_ptr<Stream>
Session::createStream()
{
  return std::make_unique<Stream>(*this);
}

Stream &
Session::insertStream(std::unique_ptr<Stream> strm)
{
  assert (strm->hasValidStreamId());
  assert (!stream(strm->streamId() && "Stream ID already taken"));
  
  auto it = _streams.emplace(std::make_pair(strm->streamId(),
                             std::move(strm)));
  
  assert (it.second);
  return *(it.first->second);
}

void
Session::createPushStream(std::int32_t streamId)
{
  auto strm = createStream();
  strm->setStreamId(streamId);
  insertStream(std::move(strm));
}

bool Session::alive() const
{
  return nghttp2_session_want_read(h2session.get())
      || nghttp2_session_want_write(h2session.get())
      || _sending;
}

void Session::setOnError(error_callback cb)
{
  _onError = std::move(cb);
}

void
Session::error(boost::system::error_code ec)
{
  if (_onError)
    _onError(ec);
  stop();
}

void Session::closeStream(Stream &stream)
{
}

void
Session::stop()
{
  if (_stopped)
    return;
  
  _stopped = true;
  sock.close();
}

void
Session::shutdown() 
{
  if (_stopped)
    return;

  nghttp2_session_terminate_session(h2session.get(), NGHTTP2_NO_ERROR);
  signalWrite();
}

namespace
{

nghttp2_nv make_nghttp2_nv(const char *name, const char *value,
                           std::size_t nameLength, std::size_t valueLength,
                           std::uint8_t flags)
{
  return nghttp2_nv{
    const_cast<std::uint8_t *>(
      reinterpret_cast<const std::uint8_t*>(name)),
    const_cast<std::uint8_t *>(
      reinterpret_cast<const std::uint8_t*>(value)),
    nameLength, valueLength, flags
  };
}

nghttp2_nv make_nghttp2_nv(std::string name, const std::string &value,
                           bool noIndex = false)
{
  return make_nghttp2_nv(name.data(), value.data(), name.length(), value.length(),
                         noIndex ? NGHTTP2_NV_FLAG_NO_INDEX : NGHTTP2_NV_FLAG_NONE);
}

template <std::size_t N>
nghttp2_nv make_nghttp2_nv(const char(&name)[N], const std::string &value,
                           bool noIndex = false)
{
  return make_nghttp2_nv(name, value.data(), N - 1, value.length(),
                         NGHTTP2_NV_FLAG_NO_COPY_NAME
                         | (noIndex ? NGHTTP2_NV_FLAG_NO_INDEX : 0));
}

template <std::size_t N, std::size_t M>
nghttp2_nv make_nghttp2_nv(const char(&name)[N], const char(&value)[M],
                           bool noIndex = false)
{
  return make_nghttp2_nv(name, value, N - 1, M - 1,
                         NGHTTP2_NV_FLAG_NO_COPY_NAME | NGHTTP2_NV_FLAG_NO_COPY_VALUE
                         | (noIndex ? NGHTTP2_NV_FLAG_NO_INDEX : 0));
}

template <std::size_t N>
nghttp2_nv make_nghttp2_nv(std::string name, const char(&value)[N],
                           bool noIndex = false)
{
  return make_nghttp2_nv(name.data(), value, name.length(), N - 1,
                         NGHTTP2_NV_FLAG_NO_COPY_VALUE
                         | (noIndex ? NGHTTP2_NV_FLAG_NO_INDEX : 0));
}

}

boost::optional<Request&>
Session::submit(boost::system::error_code &ec,
                const std::string &method,
                const std::string &path,
                const std::string &authority,
                header_map headers,
                generator_callback cb)
{
  ec.clear();
  std::unique_ptr<Stream> strm = createStream();
  Request &req = strm->request();
  
  auto nvs = std::vector<nghttp2_nv>();
  nvs.reserve(headers.size() + 4);
  nvs.emplace_back(make_nghttp2_nv(":method", method));
  nvs.emplace_back(make_nghttp2_nv(":path", path));
  nvs.emplace_back(make_nghttp2_nv(":scheme", "https"));
  if (authority.length())
    nvs.emplace_back(make_nghttp2_nv(":authority", authority));
  
  for (auto &h : headers) {
    nvs.emplace_back(make_nghttp2_nv(h.first, h.second.first));
  }
  
  nghttp2_data_provider *prdptr = nullptr;
  nghttp2_data_provider prd;

  if (cb) {
    req.setOnRead(std::move(cb));
    prd.source.ptr = strm.get();
    prd.read_callback =
      [](nghttp2_session */*session*/, std::int32_t stream_id, std::uint8_t *data,
         std::size_t length, std::uint32_t *flags, nghttp2_data_source *source,
         void *userp) -> ssize_t {
        Stream &strm = *static_cast<Stream *>(source->ptr);
        return strm.request().onRead(data, length, flags);
      };
    prdptr = &prd;
  }
  
  std::int32_t streamId = nghttp2_submit_request(h2session.get(), nullptr,
                                                 nvs.data(), nvs.size(),
                                                 prdptr, strm.get());
  if (streamId < 0) {
    ec = make_nghttp2_error(static_cast<nghttp2_error>(streamId));
    return boost::none;
  }

  signalWrite();

  strm->setStreamId(streamId);
  return insertStream(std::move(strm)).request();
}

namespace
{

struct FrameGuard {
  FrameGuard(bool &flag) : _flag(flag) { assert (!_flag); _flag = true; }
  ~FrameGuard() { assert (_flag); _flag = false; }
  bool &_flag;
};

}

void
Session::signalWrite()
{
  if (_insideCallback)
    return;
  write();
}
  
/*
 * Write.
 */
void
Session::write()
{
  if (_sending)
    /* There is already a send in progress */
    return;
    
  _sending = true;
  
  const uint8_t *data;
  std::size_t length;
  {
    FrameGuard guard(_insideCallback);
    
    auto nsend = nghttp2_session_mem_send(h2session.get(), &data);

    if (nsend < 0) {
      /* Error */
      error(make_nghttp2_error(static_cast<nghttp2_error>(nsend)));
      return;
    } else if (nsend == 0) {
      /* No more data to send */
      _sending = false;
      return;
    } else {
      length = nsend;
    }
  }
  sock.write(data, length,
    [=] // , anchor(shared_from_this())
    (std::size_t nsent, boost::system::error_code ec)
  {
    _sending = false;
    if (ec) {
      error(make_nghttp2_error(static_cast<nghttp2_error>(length)));
    } else if (length != nsent) {
      error(make_mist_error(MIST_ERR_ASSERTION));
    }
    write();
  });
}

/*
 * Read.
 */
void
Session::readCallback(const std::uint8_t *data, std::size_t length,
                      boost::system::error_code ec)
{
  if (ec) {
    /* Read error */
    error(ec);
    return;
  }
  
  if (length == 0) {
    /* Socket closed */
    stop();
    return;
  }
  
  {
    FrameGuard guard(_insideCallback);
    auto nrecvd = nghttp2_session_mem_recv(h2session.get(), data, length);
    if (nrecvd < 0) {
      error(make_nghttp2_error(static_cast<nghttp2_error>(nrecvd)));
    } else if (nrecvd != length) {
      error(make_nghttp2_error(NGHTTP2_ERR_PROTO));
    }
  }
  
  signalWrite();
}

nghttp2_session *
Session::nghttp2Session()
{
  return h2session.get();
}

}
}
