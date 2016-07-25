#include <cstddef>

#include <nghttp2/nghttp2.h>

#include "h2/session.hpp"
#include "h2/stream.hpp"

namespace mist
{
namespace h2
{

Stream::Stream(Session &session)
  : _session(session),
    _streamId(-1)
  {}

Session &
Stream::session()
{
  return _session;
}

bool
Stream::hasValidStreamId() const
{
  /* TODO: 0x0 is the control stream, do we touch it directly? */
  return _streamId >= 0;
}

std::int32_t
Stream::streamId() const
{
  return _streamId;
}

void
Stream::setStreamId(std::int32_t streamId)
{
  assert (!hasValidStreamId() && "May set stream id only once");
  _streamId = streamId;
}

void
Stream::setOnClose(close_callback cb)
{
  _onClose = std::move(cb);
}

void
Stream::close(boost::system::error_code ec)
{
  /* TODO: rst_stream? */
  if (_onClose)
    _onClose(ec);
}

// void
// Stream::cancel(std::uint32_t errorCode)
// {
  // if (session().isStopped()) {
    // /* The whole session is stopped */
    // return;
  // }

  // nghttp2_submit_rst_stream(session().nghttp2Session(), NGHTTP2_FLAG_NONE, streamId(), errorCode);

  // session().signalWrite();
// }

// void
// Stream::resume()
// {
  // if (session().isStopped()) {
    // /* The whole session is stopped */
    // return;
  // }
  
  // nghttp2_session_resume_data(session().nghttp2Session(), streamId());
  
  // session().signalWrite();
// }

/*
 * ClientStream
 */

ClientStream::ClientStream(Session &session)
  : Stream(session),
    _request(*this),
    _response(*this)
    {}

ClientRequest &
ClientStream::request()
{
  return _request;
}

ClientResponse &
ClientStream::response()
{
  return _response;
}

int
ClientStream::onHeader(const nghttp2_frame *frame, const std::uint8_t *name,
                       std::size_t namelen, const std::uint8_t *value,
                       std::size_t valuelen, std::uint8_t flags)
{
  switch (frame->hd.type) {
  case NGHTTP2_HEADERS:
    return response().onHeader(frame, name, namelen, value, valuelen, flags);
  case NGHTTP2_PUSH_PROMISE:
    return request().onHeader(frame, name, namelen, value, valuelen, flags);
  }
  return 0;
}

int
ClientStream::onFrameRecv(const nghttp2_frame *frame)
{
  switch (frame->hd.type) {
  case NGHTTP2_DATA: {
    if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM)
      /* No data */
      response().onData(nullptr, 0);
    
    break;
  }
  case NGHTTP2_HEADERS: {
    int statusCode = response().statusCode();
    bool expectsFinalResponse = statusCode >= 100 && statusCode < 200;
    
    if (frame->headers.cat == NGHTTP2_HCAT_HEADERS &&
        !expectsFinalResponse) {
      // Ignore trailers
      return 0;
    }

    if (expectsFinalResponse) {
      // Wait for final response
      return 0;
    }
    
    request().onResponse(response());
    
    if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
      response().onData(nullptr, 0);
    }
    
    break;
  }
  }
  return 0;
}

int
ClientStream::onFrameSend(const nghttp2_frame *frame)
{
  return 0;
}

int
ClientStream::onFrameNotSend(const nghttp2_frame *frame, int errorCode)
{
  return 0;
}

int
ClientStream::onDataChunkRecv(std::uint8_t flags, const std::uint8_t *data, std::size_t length)
{
  response().onData(data, length);

  return 0;
}

int
ClientStream::onStreamClose(std::uint32_t errorCode)
{
  close(make_nghttp2_error(static_cast<nghttp2_error>(errorCode)));

  return 0;
}

boost::system::error_code
ClientStream::submit(std::string method,
                     std::string path,
                     std::string scheme,
                     std::string authority,
                     header_map headers,
                     generator_callback cb)
{
  std::vector<nghttp2_nv> nvs;
  
  /* Make the header vector */
  {
    /* Special and mandatory headers */
    headers.insert({":method", {std::move(method), false}});
    headers.insert({":path", {std::move(path), false}});
    headers.insert({":scheme", {std::move(scheme), false}});
    headers.insert({":authority", {std::move(authority), false}});
    request().setHeaders(std::move(headers));
    nvs = request().makeHeaderNv();
  }

  /* Set the data provider, if applicable */
  nghttp2_data_provider *prdptr = nullptr;
  nghttp2_data_provider prd;
  if (cb) {
    request().setOnRead(std::move(cb));
    prd.source.ptr = this;
    prd.read_callback =
      [](nghttp2_session */*session*/, std::int32_t stream_id, std::uint8_t *data,
         std::size_t length, std::uint32_t *flags, nghttp2_data_source *source,
         void *userp) -> ssize_t {
        ClientStream &strm = *static_cast<ClientStream *>(source->ptr);
        return strm.request().onRead(data, length, flags);
      };
    prdptr = &prd;
  }
  
  /* Submit */
  {
    std::int32_t streamId = nghttp2_submit_request(session().nghttp2Session(),
                                                   nullptr,
                                                   nvs.data(), nvs.size(),
                                                   prdptr, this);
    if (streamId < 0) {
      return make_nghttp2_error(static_cast<nghttp2_error>(streamId));
    }

    setStreamId(streamId);
  }
  return boost::system::error_code();
}

void
ClientStream::onPush(ClientRequest &pushRequest)
{
  request().onPush(pushRequest);
}

/*
 * ServerStream
 */

ServerStream::ServerStream(Session &session)
  : Stream(session),
    _request(*this),
    _response(*this)
    {}

ServerRequest &
ServerStream::request()
{
  return _request;
}

ServerResponse &
ServerStream::response()
{
  return _response;
}

boost::system::error_code
ServerStream::submit(std::uint16_t statusCode,
                     header_map headers,
                     generator_callback cb)
{
  std::vector<nghttp2_nv> nvs;
  
  /* Make the header vector */
  {
    /* Special and mandatory headers */
    headers.insert({":status", {std::to_string(statusCode), false}});

    response().setHeaders(std::move(headers));
    nvs = response().makeHeaderNv();
  }

  /* Set the data provider, if applicable */
  nghttp2_data_provider *prdptr = nullptr;
  nghttp2_data_provider prd;
  if (cb) {
    response().setOnRead(std::move(cb));
    prd.source.ptr = this;
    prd.read_callback =
      [](nghttp2_session */*session*/, std::int32_t stream_id, std::uint8_t *data,
         std::size_t length, std::uint32_t *flags, nghttp2_data_source *source,
         void *userp) -> ssize_t {
        ServerStream &strm = *static_cast<ServerStream *>(source->ptr);
        return strm.response().onRead(data, length, flags);
      };
    prdptr = &prd;
  }
  
  /* Submit */
  {
    auto rv = nghttp2_submit_response(session().nghttp2Session(), streamId(),
                                      nvs.data(), nvs.size(), prdptr);
    if (rv) {
      return make_nghttp2_error(static_cast<nghttp2_error>(rv));
    }
  }
  
  return boost::system::error_code();
}

// void 
// ServerStream::end(std::string data = "")
// {
  // session().end(data);
// }

// void 
// ServerStream::end(generator_callback cb)
// {
  // session().end(std::move(cb));
// }

// void 
// ServerStream(header_map trailers)
// {
  // session().writeTrailers(std::move(trailers));
// }
  
int
ServerStream::onHeader(const nghttp2_frame *frame, const std::uint8_t *name,
                       std::size_t namelen, const std::uint8_t *value,
                       std::size_t valuelen, std::uint8_t flags)
{
  switch (frame->hd.type) {
  case NGHTTP2_HEADERS:
    if (frame->headers.cat != NGHTTP2_HCAT_REQUEST)
      return 0;
    
    return request().onHeader(frame, name, namelen, value, valuelen, flags);
  }
  return 0;
}

int
ServerStream::onFrameRecv(const nghttp2_frame *frame)
{
  switch (frame->hd.type) {
  case NGHTTP2_DATA: {
    if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM)
      /* No data */
      request().onData(nullptr, 0);
    break;
  }
  case NGHTTP2_HEADERS: {
    if (frame->headers.cat != NGHTTP2_HCAT_REQUEST)
      return 0;

    if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM)
      request().onData(nullptr, 0);
    
    break;
  }
  }
  return 0;
}

int
ServerStream::onFrameSend(const nghttp2_frame *frame)
{
  return 0;
}

int
ServerStream::onFrameNotSend(const nghttp2_frame *frame, int errorCode)
{
  return 0;
}

int
ServerStream::onDataChunkRecv(std::uint8_t flags, const std::uint8_t *data,
                              std::size_t length)
{
  request().onData(data, length);

  return 0;
}

int
ServerStream::onStreamClose(std::uint32_t errorCode)
{
  close(make_nghttp2_error(static_cast<nghttp2_error>(errorCode)));

  return 0;
}

}
}
