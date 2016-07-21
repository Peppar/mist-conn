#include <cstddef>
#include <string>

#include "h2/server_response.hpp"
#include "h2/lane.hpp"
#include "h2/stream.hpp"
#include "h2/types.hpp"
#include "h2/util.hpp"

namespace mist
{
namespace h2
{
  
ServerResponse::ServerResponse(ClientStream &stream)
  : _stream(stream)
    {}

ServerStream &
ServerResponse::stream()
{
  return _stream;
}

void 
ServerResponse::setOnRead(generator_callback cb)
{
  _onRead = std::move(cb);
}

generator_callback::result_type
ServerResponse::onRead(std::uint8_t *data, std::size_t length, std::uint32_t *flags)
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
