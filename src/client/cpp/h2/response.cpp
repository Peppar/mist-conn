#include <cstddef>
#include <string>

#include <nghttp2/nghttp2.h>

#include "h2/response.hpp"
#include "h2/util.hpp"

namespace mist
{
namespace h2
{
  
Response::Response(Stream &stream)
  : _stream(stream), _statusCode(0), _contentLength(0) {}

int
Response::onHeader(const nghttp2_frame *frame, const std::uint8_t *name,
                   std::size_t namelen, const std::uint8_t *value,
                   std::size_t valuelen, std::uint8_t flags)
{
  bool expectsFinalResponse = statusCode() >= 100 && statusCode() < 200;

  if (frame->headers.cat == NGHTTP2_HCAT_HEADERS &&
      !expectsFinalResponse) {
    /* Ignore trailers */
    return 0;
  }
  
  /* TODO: Optimize */
  std::string n((const char*)name, namelen);
  std::string v((const char*)value, valuelen);
  
  if (n == ":status") {
    auto parsedValue = parseDecimal<decltype(_statusCode)>(v);
    if (parsedValue)
      _statusCode = parsedValue.get();
  } else if (n == "content-length") {
    auto parsedValue = parseDecimal<decltype(_contentLength)>(v);
    if (parsedValue)
      _contentLength = parsedValue.get();
  } else {
    bool sensitive(flags & NGHTTP2_NV_FLAG_NO_INDEX);
    _headers.emplace(std::make_pair(n, header_value{v, sensitive}));
  }
  return 0;
}

void
Response::setOnData(data_callback cb)
{
  _onData = std::move(cb);
}

void
Response::onData(const std::uint8_t *data, std::size_t length)
{
  if (_onData)
    _onData(data, length);
}

const header_map &
Response::headers() const
{
  return _headers;
}

std::int64_t
Response::contentLength() const
{
  return _contentLength;
}

int
Response::statusCode() const
{
  return _statusCode;
}

}
}
