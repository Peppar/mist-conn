#include <cstddef>
#include <string>
#include <vector>

#include <nghttp2/nghttp2.h>

#include "h2/types.hpp"
#include "h2/util.hpp"

namespace mist
{
namespace h2
{

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
makeHeaderNv(const header_map &headers)
{
  auto nvs = std::vector<nghttp2_nv>();
  nvs.reserve(headers.size());

  for (auto &h : headers)
    nvs.emplace_back(make_nghttp2_nv(h.first, h.second.first,
                                     h.second.second));

  return std::move(nvs);
}

} // namespace h2
} // namespace mist
