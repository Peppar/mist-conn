#include <cstddef>

#include <nghttp2/nghttp2.h>

#include "h2/session.hpp"
#include "h2/stream.hpp"

namespace mist
{
namespace h2
{

Stream::Stream(Session &session)
  : _session(session), _streamId(-1), _request(*this), _response(*this),
    _stopped(false)  {}

Session &
Stream::session()
{
  return _session;
}

Request &
Stream::request()
{
  return _request;
}

Response &
Stream::response()
{
  return _response;
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


/*
namespace
{
nghttp2_nv make_nghttp2_nv(std::string name, std::string value, bool sensitive)
{
  return nghttp2_nv {
    const_cast<std::uint8_t *>(
      reinterpret_cast<const std::uint8_t*>(name.data())),
    const_cast<std::uint8_t *>(
      reinterpret_cast<const std::uint8_t*>(value.data())),
    name.length(), value.length(),
    sensitive ? NGHTTP2_NV_FLAG_NO_INDEX : NGHTTP2_NV_FLAG_NONE
  };
}
}

void
Stream::writeTrailer(const header_map &headers, boost::system::error_code &ec)
{
  ec.clear();
  
  std::vector<nghttp2_nv> nvs;
  nvs.reserve(headers.size());
  for (auto &header : headers) {
    nvs.push_back(make_nghttp2_nv(header.first, header.second.first, header.second.second));
  }
  auto rv = nghttp2_submit_trailer(session().nghttp2Session(), streamId(), nvs.data(),
                                   nvs.size());
                                   
  if (rv != 0) {
    ec = make_nghttp2_error(static_cast<nghttp2_error>(rv));
    return;
  }
 
  session().signalWrite();
}
*/

void
Stream::cancel(std::uint32_t errorCode)
{
  if (_stopped) {
    /* Already stopped */
    return;
  }

  /* TODO: Check for error */
  nghttp2_submit_rst_stream(session().nghttp2Session(), NGHTTP2_FLAG_NONE, streamId(), errorCode);
  
  session().signalWrite();
}

void
Stream::resume()
{
  if (_stopped) {
    /* Already stopped */
    return;
  }
  
  /* TODO: Check for error */
  nghttp2_session_resume_data(session().nghttp2Session(), streamId());

  session().signalWrite();
}

int
Stream::onHeader(const nghttp2_frame *frame, const std::uint8_t *name,
                 std::size_t namelen, const std::uint8_t *value,
                 std::size_t valuelen, std::uint8_t flags)
{
  switch (frame->hd.type) {
  case NGHTTP2_HEADERS:
    return response().onHeader(frame, name, namelen, value, valuelen, flags);
  case NGHTTP2_PUSH_PROMISE:
    return request().onPushHeader(frame, name, namelen, value, valuelen, flags);
  }
  return 0;
}

int
Stream::onFrameRecv(const nghttp2_frame *frame)
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
  case NGHTTP2_PUSH_PROMISE: {
    auto pushStream = session().stream(
      frame->push_promise.promised_stream_id);
    if (!pushStream)
      return 0;
    
    request().onPush(pushStream->request());
    
    break;
  }
  }
  return 0;
}

int
Stream::onDataChunkRecv(std::uint8_t flags, const std::uint8_t *data, std::size_t length)
{
  response().onData(data, length);

  return 0;
}

int
Stream::onStreamClose(std::uint32_t errorCode)
{
  request().onClose(make_nghttp2_error(static_cast<nghttp2_error>(errorCode)));
  
  return 0;
}

}
}
