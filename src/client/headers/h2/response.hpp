#ifndef __MIST_HEADERS_H2_RESPONSE_HPP__
#define __MIST_HEADERS_H2_RESPONSE_HPP__

#include <nghttp2/nghttp2.h>

#include "h2/types.hpp"

namespace mist
{
namespace h2
{

class Stream;

class Response
{
public:
  
  Response(Stream &stream);

  void setOnData(data_callback cb);
  void onData(const std::uint8_t *data, std::size_t length);
                                         
  int onHeader(const nghttp2_frame *frame, const std::uint8_t *name,
               std::size_t namelen, const std::uint8_t *value,
               std::size_t valuelen, std::uint8_t flags);

  const header_map &headers() const;
  std::int64_t contentLength() const;
  int statusCode() const;

protected:

  Stream &_stream;
  
  std::int64_t _contentLength;
  int _statusCode;
  
  header_map _headers;
  
  data_callback _onData;
  
};

}
}

#endif
