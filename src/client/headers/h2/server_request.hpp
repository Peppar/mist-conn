#ifndef __MIST_HEADERS_H2_SERVER_REQUEST_HPP__
#define __MIST_HEADERS_H2_SERVER_REQUEST_HPP__

#include <cstddef>

#include "h2/types.hpp"
#include "h2/lane.hpp"

namespace mist
{
namespace h2
{

class ServerStream;

class ServerRequest : public Lane
{
private:

  ServerStream &_stream;
  
  data_callback _onData;
  
protected:

  friend class ServerStream;
  
  void onData(const std::uint8_t *data, std::size_t length);

public:

  ServerRequest(ServerStream &stream);

  ServerStream &stream();

  void setOnData(data_callback cb);

};

}
}

#endif
