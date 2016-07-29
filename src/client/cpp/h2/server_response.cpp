#include <cstddef>
#include <string>

#include <nghttp2/nghttp2.h>

#include "h2/server_response.hpp"
#include "h2/lane.hpp"
#include "h2/stream.hpp"
#include "h2/types.hpp"
#include "h2/util.hpp"

namespace mist
{
namespace h2
{
  
ServerResponse::ServerResponse(ServerStream &stream)
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

// void 
// ServerResponse::writeHeaders(int statusCode, header_map headers)
// {
  // session().writeHeaders(statusCode, std::move(headers));
// }

// void 
// ServerResponse::end(std::string data = "")
// {
  // session().end(data);
// }

// void 
// ServerResponse::end(generator_callback cb)
// {
  // session().end(std::move(cb));
// }

// void 
// writeTrailers(header_map trailers)
// {
  // session().writeTrailers(std::move(trailers));
// }
  
}
}
