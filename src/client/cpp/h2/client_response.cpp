#include <cstddef>
#include <string>

#include "h2/client_response.hpp"
#include "h2/lane.hpp"
#include "h2/stream.hpp"
#include "h2/types.hpp"
#include "h2/util.hpp"

namespace mist
{
namespace h2
{
  
ClientResponse::ClientResponse(ClientStream &stream)
  : _stream(stream)
    {}

ClientStream &
ClientResponse::stream()
{
  return _stream;
}

void
ClientResponse::setOnData(data_callback cb)
{
  _onData = std::move(cb);
}

void
ClientResponse::onData(const std::uint8_t *data, std::size_t length)
{
  if (_onData)
    _onData(data, length);
}

}
}
