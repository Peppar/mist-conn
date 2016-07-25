#ifndef __MIST_HEADERS_H2_REQUEST_HPP__
#define __MIST_HEADERS_H2_REQUEST_HPP__

#include <map>
#include <list>

#include <boost/optional.hpp>

#include "error/nghttp2.hpp"
#include "error/mist.hpp"

#include "h2/types.hpp"

#include "memory/nghttp2.hpp"

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

  std::int64_t _contentLength;

  int _statusCode;

  std::string _method;

  std::string _path;

  std::string _scheme;

  std::string _authority;

  header_map _headers;

  void parseHeader(const std::string &name, const std::string &value);

protected:

  Lane();

  void onClose(boost::system::error_code ec);

  int onHeader(const nghttp2_frame *frame, const std::uint8_t *name,
               std::size_t namelen, const std::uint8_t *value,
               std::size_t valuelen, std::uint8_t flags);

  void setHeaders(mist::h2::header_map h);

public:

  std::uint64_t contentLength() const;

  int statusCode() const;

  const std::string &method() const;

  // void setMethod(const std::string &method);
  // void setPath(const std::string &path);
  const std::string &path() const;

  // void setScheme(const std::string &scheme);
  const std::string &scheme() const;

  // void setAuthority(const std::string &authority);
  const std::string &authority() const;

  const header_map &headers() const;

  std::vector<nghttp2_nv> makeHeaderNv() const;

};

}
}

#endif
