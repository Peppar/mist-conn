#include <type_traits>

#include "h2/lane.hpp"
#include "h2/util.hpp"

namespace mist
{
namespace h2
{
  
Lane::Lane()
  : _contentLength(0),
    _statusCode(0)
    {}

/*
void
Lane::writeTrailer(header_map headers, boost::system::error_code &ec)
{
  stream().writeTrailer(std::move(headers), ec);
}
*/

// void
// Lane::setStatusCode(int statusCode)
// {
  // _statusCode = statusCode;
// }

int
Lane::statusCode() const
{
  return _statusCode;
}

// void
// Lane::setContentLength(std::uint64_t contentLength)
// {
  // _contentLength = contentLength;
// }

std::uint64_t
Lane::contentLength() const
{
  return _contentLength;
}

// void
// Lane::setMethod(const std::string &method)
// {
  // _method = method;
// }

const std::string &
Lane::method() const
{
  return _method;
}

// void
// Lane::setPath(const std::string &path)
// {
  // _path = path;
// }

const std::string &
Lane::path() const
{
  return _path;
}

// void
// Lane::setScheme(const std::string &scheme)
// {
  // _scheme = scheme;
// }

const std::string &
Lane::scheme() const
{
  return _scheme;
}

// void
// Lane::setAuthority(const std::string &authority)
// {
  // _authority = authority;
// }

const std::string &
Lane::authority() const
{
  return _authority;
}

void
Lane::setHeaders(header_map headers)
{
  /* Reset all previously parsed header fields */
  _contentLength = 0;
  _statusCode = 0;
  _method.clear();
  _path.clear();
  _scheme.clear();
  _authority.clear();
  
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
    /* int at least 16 bits, sufficient for status code */
    auto parsedValue = parseDecimal<decltype(_statusCode)>(value);
    if (parsedValue)
      _statusCode = parsedValue.get();
    else
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
    auto parsedValue = parseDecimal<decltype(_contentLength)>(value);
    if (parsedValue)
      _contentLength = parsedValue.get();
    else
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
  // std::string v((const char*)value, valuelen);
  /* TODO: Optimize */
  // std::string n((const char*)name, namelen);
  // std::string v((const char*)value, valuelen);
  
  // if (n == ":status") {
    // /* int at least 16 bits, sufficient for status code */
    // auto parsedValue = parseDecimal<decltype(_statusCode)>(v);
    // if (parsedValue)
      // _statusCode = parsedValue.get();
    // else
      // /* TODO: Malformed value; reset stream? */;
  // } else if (n == "content-length") {
    // auto parsedValue = parseDecimal<decltype(_contentLength)>(v);
    // if (parsedValue)
      // _contentLength = parsedValue.get();
    // else
      // /* TODO: Malformed value; reset stream? */;
  // } else if (n == ":method") {
    // _method = v;
  // }
  // // else if (n == ":path") {
    // // setPath(v);
  // // } else if (n == ":scheme") {
    // // setScheme(v);
  // // } else if (n == ":method") {
    // // setMethod(v);
  // // } else if (n == ":authority") {
    // // setAuthority(v);
  // // } else {
  // bool sensitive(flags & NGHTTP2_NV_FLAG_NO_INDEX);
  // _headers.emplace(std::make_pair(n, header_value{v, sensitive}));
  // return 0;
}

namespace
{

nghttp2_nv make_nghttp2_nv(const char *name, const char *value,
                           std::size_t nameLength, std::size_t valueLength,
                           std::uint8_t flags)
{
  return nghttp2_nv{
    const_cast<std::uint8_t *>(
      reinterpret_cast<const std::uint8_t*>(name)),
    const_cast<std::uint8_t *>(
      reinterpret_cast<const std::uint8_t*>(value)),
    nameLength, valueLength, flags
  };
}

nghttp2_nv make_nghttp2_nv(std::string name, const std::string &value,
                           bool noIndex)
{
  return make_nghttp2_nv(name.data(), value.data(), name.length(), value.length(),
                         noIndex ? NGHTTP2_NV_FLAG_NO_INDEX : NGHTTP2_NV_FLAG_NONE);
}

template <std::size_t N>
nghttp2_nv make_nghttp2_nv(const char(&name)[N], const std::string &value,
                           bool noIndex)
{
  return make_nghttp2_nv(name, value.data(), N - 1, value.length(),
                         NGHTTP2_NV_FLAG_NO_COPY_NAME
                         | (noIndex ? NGHTTP2_NV_FLAG_NO_INDEX : 0));
}

template <std::size_t N, std::size_t M>
nghttp2_nv make_nghttp2_nv(const char(&name)[N], const char(&value)[M],
                           bool noIndex)
{
  return make_nghttp2_nv(name, value, N - 1, M - 1,
                         NGHTTP2_NV_FLAG_NO_COPY_NAME | NGHTTP2_NV_FLAG_NO_COPY_VALUE
                         | (noIndex ? NGHTTP2_NV_FLAG_NO_INDEX : 0));
}

template <std::size_t N>
nghttp2_nv make_nghttp2_nv(std::string name, const char(&value)[N],
                           bool noIndex)
{
  return make_nghttp2_nv(name.data(), value, name.length(), N - 1,
                         NGHTTP2_NV_FLAG_NO_COPY_VALUE
                         | (noIndex ? NGHTTP2_NV_FLAG_NO_INDEX : 0));
}

}

std::vector<nghttp2_nv>
Lane::makeHeaderNv() const
{
  auto nvs = std::vector<nghttp2_nv>();
  nvs.reserve(headers().size());

  for (auto &h : headers())
    nvs.emplace_back(make_nghttp2_nv(h.first, h.second.first,
                                     h.second.second));

  return std::move(nvs);
}

}
}
