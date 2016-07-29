#include <boost/system/error_code.hpp>
#include <nghttp2/nghttp2.h>

#include "error/nghttp2.hpp"

namespace mist
{

namespace
{

class nghttp2_error_category : public boost::system::error_category
{
  const char *name() const noexcept
  {
    return "nghttp2";
  }
  
  std::string message(int ev) const
  {
    switch (ev) {
    case NGHTTP2_ERR_INVALID_ARGUMENT:
      return "NGHTTP2_ERR_INVALID_ARGUMENT";
    case NGHTTP2_ERR_BUFFER_ERROR:
      return "NGHTTP2_ERR_BUFFER_ERROR";
    case NGHTTP2_ERR_UNSUPPORTED_VERSION:
      return "NGHTTP2_ERR_UNSUPPORTED_VERSION";
    case NGHTTP2_ERR_WOULDBLOCK:
      return "NGHTTP2_ERR_WOULDBLOCK";
    case NGHTTP2_ERR_PROTO:
      return "NGHTTP2_ERR_PROTO";
    case NGHTTP2_ERR_INVALID_FRAME:
      return "NGHTTP2_ERR_INVALID_FRAME";
    case NGHTTP2_ERR_EOF:
      return "NGHTTP2_ERR_EOF";
    case NGHTTP2_ERR_DEFERRED:
      return "NGHTTP2_ERR_DEFERRED";
    case NGHTTP2_ERR_STREAM_ID_NOT_AVAILABLE:
      return "NGHTTP2_ERR_STREAM_ID_NOT_AVAILABLE";
    case NGHTTP2_ERR_STREAM_CLOSED:
      return "NGHTTP2_ERR_STREAM_CLOSED";
    case NGHTTP2_ERR_STREAM_CLOSING:
      return "NGHTTP2_ERR_STREAM_CLOSING";
    case NGHTTP2_ERR_STREAM_SHUT_WR:
      return "NGHTTP2_ERR_STREAM_SHUT_WR";
    case NGHTTP2_ERR_INVALID_STREAM_ID:
      return "NGHTTP2_ERR_INVALID_STREAM_ID";
    case NGHTTP2_ERR_INVALID_STREAM_STATE:
      return "NGHTTP2_ERR_INVALID_STREAM_STATE";
    case NGHTTP2_ERR_DEFERRED_DATA_EXIST:
      return "NGHTTP2_ERR_DEFERRED_DATA_EXIST";
    case NGHTTP2_ERR_START_STREAM_NOT_ALLOWED:
      return "NGHTTP2_ERR_START_STREAM_NOT_ALLOWED";
    case NGHTTP2_ERR_GOAWAY_ALREADY_SENT:
      return "NGHTTP2_ERR_GOAWAY_ALREADY_SENT";
    case NGHTTP2_ERR_INVALID_HEADER_BLOCK:
      return "NGHTTP2_ERR_INVALID_HEADER_BLOCK";
    case NGHTTP2_ERR_INVALID_STATE:
      return "NGHTTP2_ERR_INVALID_STATE";
    case NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE:
      return "NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE";
    case NGHTTP2_ERR_FRAME_SIZE_ERROR:
      return "NGHTTP2_ERR_FRAME_SIZE_ERROR";
    case NGHTTP2_ERR_HEADER_COMP:
      return "NGHTTP2_ERR_HEADER_COMP";
    case NGHTTP2_ERR_FLOW_CONTROL:
      return "NGHTTP2_ERR_FLOW_CONTROL";
    case NGHTTP2_ERR_INSUFF_BUFSIZE:
      return "NGHTTP2_ERR_INSUFF_BUFSIZE";
    case NGHTTP2_ERR_PAUSE:
      return "NGHTTP2_ERR_PAUSE";
    case NGHTTP2_ERR_TOO_MANY_INFLIGHT_SETTINGS:
      return "NGHTTP2_ERR_TOO_MANY_INFLIGHT_SETTINGS";
    case NGHTTP2_ERR_PUSH_DISABLED:
      return "NGHTTP2_ERR_PUSH_DISABLED";
    case NGHTTP2_ERR_DATA_EXIST:
      return "NGHTTP2_ERR_DATA_EXIST";
    case NGHTTP2_ERR_SESSION_CLOSING:
      return "NGHTTP2_ERR_SESSION_CLOSING";
    case NGHTTP2_ERR_HTTP_HEADER:
      return "NGHTTP2_ERR_HTTP_HEADER";
    case NGHTTP2_ERR_HTTP_MESSAGING:
      return "NGHTTP2_ERR_HTTP_MESSAGING";
    case NGHTTP2_ERR_REFUSED_STREAM:
      return "NGHTTP2_ERR_REFUSED_STREAM";
    case NGHTTP2_ERR_INTERNAL:
      return "NGHTTP2_ERR_INTERNAL";
    case NGHTTP2_ERR_CANCEL:
      return "NGHTTP2_ERR_CANCEL";
    case NGHTTP2_ERR_FATAL:
      return "NGHTTP2_ERR_FATAL";
    case NGHTTP2_ERR_NOMEM:
      return "NGHTTP2_ERR_NOMEM";
    case NGHTTP2_ERR_CALLBACK_FAILURE:
      return "NGHTTP2_ERR_CALLBACK_FAILURE";
    case NGHTTP2_ERR_BAD_CLIENT_MAGIC:
      return "NGHTTP2_ERR_BAD_CLIENT_MAGIC";
    case NGHTTP2_ERR_FLOODED:
      return "NGHTTP2_ERR_FLOODED";
    default:
      return "Unknown nghttp2 error " + std::to_string(ev);
    }
  }
} instance;

}

const boost::system::error_category &nghttp2_category() noexcept
{
  return instance;
}

boost::system::error_code make_nghttp2_error(std::uint32_t ev)
{
  return boost::system::error_code(static_cast<nghttp2_error>(ev),
                                   nghttp2_category());
}

}
