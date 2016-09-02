#ifndef __MIST_HEADERS_H2_CLIENT_REQUEST_HPP__
#define __MIST_HEADERS_H2_CLIENT_REQUEST_HPP__

#include <cstddef>

#include "h2/types.hpp"
#include "h2/lane.hpp"

namespace mist
{
namespace h2
{

class ClientResponse;
class ClientStream;

class ClientRequest : public RequestLane
{
private:

  ClientStream &_stream;
  
  client_response_callback _onResponse;
  
  client_request_callback _onPush;
  
  generator_callback _onRead;

protected:

  friend class ClientStream;
  
  void onResponse(ClientResponse &response);

  void onPush(ClientRequest &pushRequest);

  generator_callback::result_type onRead(std::uint8_t *data, std::size_t length,
                                         std::uint32_t *flags);

public:

  ClientRequest(ClientStream &stream);

  ClientStream &stream();

  void setOnResponse(client_response_callback cb);

  void setOnPush(client_request_callback cb);

  void setOnRead(generator_callback cb);

};

}
}

#endif
