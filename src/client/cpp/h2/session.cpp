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

/*
 * Session
 */
Session::Session(Socket &sock, bool isServer)
  : sock(sock),
    h2session(to_unique<nghttp2_session>()),
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
  
  /* Set on begin headers callback */
  nghttp2_session_callbacks_set_on_begin_headers_callback(cbs.get(),
    [](nghttp2_session */*session*/, const nghttp2_frame *frame,
       void *user_data) -> int
  {
    /* Stream may not yet exist; let the session handle this */
    static_cast<Session *>(user_data)->onBeginHeaders(frame);
  });

  /* Set on stream close callback */
  nghttp2_session_callbacks_set_on_stream_close_callback(cbs.get(),
    [](nghttp2_session */*session*/, std::int32_t stream_id,
       std::uint32_t error_code, void *user_data) -> int
  {
    static_cast<Session *>(user_data)->onStreamClose(stream_id, error_code);
  });
  
  /* Set on error callback */
  nghttp2_session_callbacks_set_error_callback(cbs.get(),
    [](nghttp2_session */*session*/, const char *message, std::size_t length,
       void *user_data) -> int
  {
    Session &sess = *static_cast<Session *>(user_data);
    std::cerr << "nghttp signalled error: " << std::string(message, length) << std::endl;
    return 0;
  });
  
  /* Set on header callback */
  nghttp2_session_callbacks_set_on_header_callback(cbs.get(),
    [](nghttp2_session */*session*/, const nghttp2_frame *frame,
       const std::uint8_t *name, std::size_t namelen,
       const std::uint8_t *value, std::size_t valuelen, std::uint8_t flags,
       void *user_data) -> int
  {
    Session &session = *static_cast<Session *>(user_data);
    auto stream = session.stream<ClientStream>(frame->hd.stream_id);
    if (!stream)
      return 0;
    return stream->onFrameSend(frame, name, namelen, value, valuelen, flags);
  });
  
  /* Set on stream frame send callback */
  nghttp2_session_callbacks_set_on_frame_send_callback(cbs.get(),
    [](nghttp2_session */*session*/, const nghttp2_frame *frame,
       void *user_data) -> int
  {
    Session &session = *static_cast<Session *>(user_data);
    auto stream = session.stream<ClientStream>(frame->hd.stream_id);
    if (!stream)
      return 0;
    return stream->onFrameSend(frame);
  });
  
  /* Set on frame not send callback */
  nghttp2_session_callbacks_set_on_frame_not_send_callback(cbs.get(),
    [](nghttp2_session */*session*/, const nghttp2_frame *frame,
       int errorCode, void *user_data) -> int
  {
    Session &session = *static_cast<Session *>(user_data);
    auto stream = session.stream<Stream>(frame->hd.stream_id);
    if (!stream)
      return 0;
    return stream->onFrameNotSend(frame, errorCode);
  });
  
  /* Set on frame receive callback */
  nghttp2_session_callbacks_set_on_frame_recv_callback(cbs.get(),
    [](nghttp2_session */*session*/, const nghttp2_frame *frame,
       void *user_data) -> int
  {
    Session &session = *static_cast<Session *>(user_data);
    auto stream = session.stream<ClientStream>(frame->hd.stream_id);
    if (!stream)
      return 0;
    return stream->onFrameRecv(frame, errorCode);
  });
  
  /* Set on data chunk receive callback */
  nghttp2_session_callbacks_set_on_data_chunk_recv_callback(cbs.get(),
    [](nghttp2_session */*session*/, std::uint8_t flags,
       std::int32_t stream_id, const std::uint8_t *data, std::size_t len,
       void *user_data) -> int
  {
    Session &session = *static_cast<Session *>(user_data);
    auto stream = session.stream<ClientStream>(stream_id);
    if (!stream)
      return 0;
    return stream->onDataChunkRecv(data, len);
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

bool
Session::isStopped() const 
{
  return _stopped;
}

bool
Session::alive() const
{
  return nghttp2_session_want_read(h2session.get())
      || nghttp2_session_want_write(h2session.get())
      || _sending;
}

void
Session::setOnError(error_callback cb)
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
 * ClientSession
 */

ClientSession::ClientSession(Socket &sock)
  : Session(sock, false)
    {}

boost::optional<ClientRequest&>
ClientSession::submit(boost::system::error_code &ec,
                      // const std::string &method,
                      // const std::string &path,
                      // const std::string &scheme,
                      // const std::string &authority,
                      header_map headers,
                      generator_callback cb)
{
  ec.clear();
  auto strm = std::make_unique<ClientStream>(*this);
  ClientRequest &req = strm->request();
  
  // req.setMethod(method);
  // req.setPath(path);
  // req.setScheme(scheme);
  // req.setAuthority(authority);
  req.setHeaders(std::move(headers));
  auto nvs = req.makeHeaderNv();

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

int
ClientSession::onBeginHeaders(const nghttp2_frame *frame)
{
  if (frame->hd.type == NGHTTP2_PUSH_PROMISE) {
    /* Server created a push stream */
    auto strm = std::make_unique<ClientStream>(*this);
    strm->setStreamId(streamId);
    insertStream(std::move(strm));
  }
  return 0;
}

int
ClientSession::onStreamClose(std::int32_t stream_id, std::uint32_t error_code)
{
  auto stream = stream<ClientStream>(frame->hd.stream_id)
  return stream.onStreamClose(error_code);
}

/*
 * ServerSession
 */
ServerSession::ServerSession(Socket &sock)
  : Session(sock, true)
    {}

void
ServerSession::setOnRequest(request_callback cb)
{
  _onRequest = std::move(cb);
}

int
ServerSession::onBeginHeaders(const nghttp2_frame *frame)
{
  if (frame->hd.type == NGHTTP2_HEADERS
      && frame->headers.cat == NGHTTP2_HCAT_REQUEST) {
    /* Client created a stream */
    auto strm = std::make_unique<ServerStream>(*this);
    strm->setStreamId(frame->hd.stream_id);
    insertStream(std::move(strm));
  }
  return 0;
}

int
ServerSession::onStreamClose(std::int32_t stream_id, std::uint32_t error_code)
{
  auto stream = stream<ClientStream>(frame->hd.stream_id)
  return stream.onStreamClose(error_code);
}

}
}
