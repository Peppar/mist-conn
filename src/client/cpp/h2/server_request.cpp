#include <cstddef>
#include <string>

#include <nghttp2/nghttp2.h>

#include "h2/client_request.hpp"
#include "h2/lane.hpp"
#include "h2/stream.hpp"
#include "h2/types.hpp"
#include "h2/util.hpp"

namespace mist
{
namespace h2
{
  
ServerRequest::ServerRequest(ServerStream &stream)
  : _stream(stream)
    {}

ServerStream &
ServerRequest::stream()
{
  return _stream;
}

void
ServerRequest::setOnData(data_callback cb)
{
  _onData = std::move(cb);
}

void
ServerRequest::onData(const std::uint8_t *data, std::size_t length)
{
  if (_onData)
    _onData(data, length);
}

} // namespace h2
} // namespace mist
