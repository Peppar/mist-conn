#ifndef __MIST_HEADERS_H2_CLIENT_RESPONSE_HPP__
#define __MIST_HEADERS_H2_CLIENT_RESPONSE_HPP__

#include <cstddef>

#include "h2/types.hpp"
#include "h2/lane.hpp"

namespace mist
{
namespace h2
{

class ClientStream;

class ClientResponse : public ResponseLane
{
private:

  ClientStream &_stream;
  
  data_callback _onData;
  
protected:

  friend class ClientStream;
  
  void onData(const std::uint8_t *data, std::size_t length);

public:
  
  ClientResponse(ClientStream &stream);

  ClientStream &stream();

  void setOnData(data_callback cb);

};

}
}

#endif
