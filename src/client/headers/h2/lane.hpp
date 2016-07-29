#ifndef __MIST_HEADERS_H2_REQUEST_HPP__
#define __MIST_HEADERS_H2_REQUEST_HPP__

#include <cstddef>
#include <string>
#include <vector>

#include <boost/system/error_code.hpp>
#include <boost/optional.hpp>

#include <nghttp2/nghttp2.h>

#include "h2/types.hpp"

namespace mist
{
namespace h2
{

class Stream;

class Lane
{
private:

  Lane(const Lane &) = delete;
  Lane& operator=(const Lane &) = delete;

  boost::optional<std::uint64_t> _contentLength;
  boost::optional<std::uint16_t> _statusCode;
  boost::optional<std::string> _method;
  boost::optional<std::string> _path;
  boost::optional<std::string> _scheme;
  boost::optional<std::string> _authority;

  header_map _headers;

  void parseHeader(const std::string &name, const std::string &value);

protected:

  Lane();

  void onClose(boost::system::error_code ec);

  int onHeader(const nghttp2_frame *frame, const std::uint8_t *name,
               std::size_t namelen, const std::uint8_t *value,
               std::size_t valuelen, std::uint8_t flags);

  void setHeaders(header_map h);

public:

  const boost::optional<std::uint64_t> &contentLength() const;
  const boost::optional<std::uint16_t> &statusCode() const;
  const boost::optional<std::string> &method() const;
  const boost::optional<std::string> &path() const;
  const boost::optional<std::string> &scheme() const;
  const boost::optional<std::string> &authority() const;

  const header_map &headers() const;

};

}
}

#endif
