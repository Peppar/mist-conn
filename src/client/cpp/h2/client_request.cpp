#include <cstddef>
#include <string>

#include "h2/client_request.hpp"
#include "h2/lane.hpp"
#include "h2/stream.hpp"
#include "h2/types.hpp"
#include "h2/util.hpp"

namespace mist
{
namespace h2
{
  
ClientRequest::ClientRequest(ClientStream &stream)
  : _stream(stream)
    {}

ClientStream &
ClientResponse::stream()
{
  return _stream;
}

void 
ClientRequest::setOnResponse(client_response_callback cb)
{
  _onResponse = std::move(cb);
}

void
ClientRequest::onResponse(Response &response)
{
  if (_onResponse)
    _onResponse(response);
}

void 
ClientRequest::setOnPush(client_request_callback cb)
{
  _onPush = std::move(cb);
}

void
ClientRequest::onPush(ClientRequest &request)
{
  if (_onPush)
    _onPush(request);
}

void 
ClientRequest::setOnRead(generator_callback cb)
{
  _onRead = std::move(cb);
}

generator_callback::result_type
ClientRequest::onRead(std::uint8_t *data, std::size_t length, std::uint32_t *flags)
{
  if (_onRead) {
    return _onRead(data, length, flags);
  } else {
    *flags |= NGHTTP2_DATA_FLAG_EOF;
    return 0;
  }
}

}
}
