#ifndef __MIST_HEADERS_H2_REQUEST_HPP__
#define __MIST_HEADERS_H2_REQUEST_HPP__

#include <map>
#include <list>

#include <boost/optional.hpp>

#include "error/nghttp2.hpp"
#include "error/mist.hpp"

#include "h2/response.hpp"
#include "h2/types.hpp"

#include "memory/nghttp2.hpp"

namespace mist
{
namespace h2
{

class Response;
class Stream;

class Request
{
public:

  Request(Stream &stream);

  void setOnResponse(response_callback cb);
  void onResponse(Response &response);

  void setOnPush(request_callback cb);
  void onPush(Request &request);
  
  void setOnClose(close_callback cb);
  void onClose(boost::system::error_code ec);
  
  int onPushHeader(const nghttp2_frame *frame, const std::uint8_t *name,
                   std::size_t namelen, const std::uint8_t *value,
                   std::size_t valuelen, std::uint8_t flags);

  void setOnRead(generator_callback cb);
  generator_callback::result_type onRead(std::uint8_t *data, std::size_t length,
                                         std::uint32_t *flags);

  void resume();
  
  void cancel(std::uint32_t errorCode);

  void setHeaders(mist::h2::header_map h);
  const header_map &headers() const;

  Stream &stream();

  /* void writeTrailer(header_map headers, boost::system::error_code &ec); */

protected:

  Stream &_stream;
  header_map _headers;

  std::int64_t _contentLength;
  int _statusCode;
  std::string _method;
  std::string _path;
  
  data_callback _onData;
  close_callback _onClose;
  response_callback _onResponse;
  request_callback _onPush;
  generator_callback _onRead;

};

}
}

#endif
