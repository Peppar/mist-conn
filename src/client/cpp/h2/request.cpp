#include <type_traits>

#include "h2/request.hpp"
#include "h2/stream.hpp"
#include "h2/util.hpp"

namespace mist
{
namespace h2
{
  
Request::Request(Stream &stream)
  : _stream(stream),
    _contentLength(0),
    _statusCode(0), 
    {}

/*
void
Request::writeTrailer(header_map headers, boost::system::error_code &ec)
{
  stream().writeTrailer(std::move(headers), ec);
}
*/

void
Request::cancel(std::uint32_t errorCode)
{
  stream().cancel(errorCode);
}

void 
Request::setOnResponse(response_callback cb)
{
  _onResponse = std::move(cb);
}

void
Request::onResponse(Response &response)
{
  if (_onResponse)
    _onResponse(response);
}

void 
Request::setOnPush(request_callback cb)
{
  _onPush = std::move(cb);
}

void
Request::onPush(Request &request)
{
  if (_onPush)
    _onPush(request);
}

void 
Request::setOnClose(close_callback cb)
{
  _onClose = std::move(cb);
}

void
Request::onClose(boost::system::error_code ec)
{
  if (_onClose)
    _onClose(ec);
}

void 
Request::setOnRead(generator_callback cb)
{
  _onRead = std::move(cb);
}

generator_callback::result_type
Request::onRead(std::uint8_t *data, std::size_t length, std::uint32_t *flags)
{
  if (_onRead) {
    return _onRead(data, length, flags);
  } else {
    *flags |= NGHTTP2_DATA_FLAG_EOF;
    return 0;
  }
}

int
Request::onPushHeader(const nghttp2_frame *frame, const std::uint8_t *name,
                      std::size_t namelen, const std::uint8_t *value,
                      std::size_t valuelen, std::uint8_t flags)
{
  /* TODO: Optimize */
  std::string n((const char*)name, namelen);
  std::string v((const char*)value, valuelen);
  
  if (n == ":status") {
    /* int at least 16 bits, sufficient for status code */
    auto parsedValue = parseDecimal<decltype(_statusCode)>(v);
    if (parsedValue)
      _statusCode = parsedValue.get();
    else
      /* TODO: Malformed value; reset stream? */;
  } else if (n == "content-length") {
    auto parsedValue = parseDecimal<decltype(_contentLength)>(v);
    if (parsedValue)
      _contentLength = parsedValue.get();
    else
      /* TODO: Malformed value; reset stream? */;
  } else if (n == ":path") {
    _path = v;
  } else if (n == ":scheme") {
    /* Ignored */
  } else if (n == ":method") {
    _method = v;
  } else if (n == ":authority") {
    /* Ignored */
  } else {
    bool sensitive(flags & NGHTTP2_NV_FLAG_NO_INDEX);
    _headers.emplace(std::make_pair(n, header_value{v, sensitive}));
  }
  return 0;
}

Stream&
Request::stream() {
  return _stream;
}

const header_map&
Request::headers() const {
  return _headers;
}

}
}
