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

class ClientResponse;
class Stream;

class ClientRequest
{
protected:

  data_callback _onData;

  close_callback _onClose;

  response_callback _onResponse;

  request_callback _onPush;

  generator_callback _onRead;

public:

  ClientRequest(Stream &stream);

  void setOnResponse(response_callback cb);
  void onResponse(Response &response);

  void setOnPush(request_callback cb);
  void onPush(Request &request);
  
  void setOnClose(close_callback cb);
  void onClose(boost::system::error_code ec);
  
  void setOnRead(generator_callback cb);
  generator_callback::result_type onRead(std::uint8_t *data, std::size_t length,
                                         std::uint32_t *flags);

};

}
}

#endif
