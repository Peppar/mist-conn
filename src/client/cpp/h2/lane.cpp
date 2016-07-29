#include <cstddef>
#include <string>
#include <vector>

#include <boost/system/error_code.hpp>

#include <nghttp2/nghttp2.h>

#include "h2/lane.hpp"
#include "h2/types.hpp"
#include "h2/util.hpp"

namespace mist
{
namespace h2
{
  
Lane::Lane() {}

const boost::optional<std::uint16_t> &
Lane::statusCode() const
{
  return _statusCode;
}

const boost::optional<std::uint64_t> &
Lane::contentLength() const
{
  return _contentLength;
}

const boost::optional<std::string> &
Lane::method() const
{
  return _method;
}

const boost::optional<std::string> &
Lane::path() const
{
  return _path;
}

const boost::optional<std::string> &
Lane::scheme() const
{
  return _scheme;
}

const boost::optional<std::string> &
Lane::authority() const
{
  return _authority;
}

void
Lane::setHeaders(header_map headers)
{
  /* Clear all previously parsed header fields */
  _contentLength = boost::none;
  _statusCode = boost::none;
  _method = boost::none;
  _path = boost::none;
  _scheme = boost::none;
  _authority = boost::none;
  
  _headers = std::move(headers);
  for (auto &h : _headers)
    parseHeader(h.first, h.second.first);
}

const header_map &
Lane::headers() const
{
  return _headers;
}

void
Lane::parseHeader(const std::string &name, const std::string &value)
{
  if (name == ":status") {
    _statusCode = parseDecimal<decltype(_statusCode)::value_type>(value);
    if (!_statusCode)
      /* TODO: Malformed value; reset stream? */;
  } else if (name == ":method") {
    _method = value;
  } else if (name == ":path") {
    _path = value;
  } else if (name == ":scheme") {
    _scheme = value;
  } else if (name == ":authority") {
    _authority = value;
  } else if (name == "content-length") {
    _contentLength = parseDecimal<decltype(_contentLength)::value_type>(value);
    if (!_contentLength)
      /* TODO: Malformed value; reset stream? */;
  }
}

int
Lane::onHeader(const nghttp2_frame *frame, const std::uint8_t *name,
               std::size_t namelen, const std::uint8_t *value,
               std::size_t valuelen, std::uint8_t flags)
{
  
  bool noIndex(flags & NGHTTP2_NV_FLAG_NO_INDEX);
  std::string nameStr(reinterpret_cast<const char*>(name), namelen);
  std::string valueStr(reinterpret_cast<const char*>(value), valuelen);
  
  parseHeader(nameStr, valueStr);
  
  _headers.emplace(std::make_pair(std::move(nameStr),
                                  header_value{std::move(valueStr), noIndex}));
  
  return 0;
}

}
}
