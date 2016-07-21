#ifndef __MIST_HEADERS_H2_SERVER_RESPONSE_HPP__
#define __MIST_HEADERS_H2_SERVER_RESPONSE_HPP__

#include "h2/types.hpp"
#include "h2/lane.hpp"

namespace mist
{
namespace h2
{

class ServerStream;

class ServerResponse : public Lane
{
private:

  ServerStream &_stream;
  
  generator_callback _onRead;

protected:

  friend class ServerStream;
  
  generator_callback::result_type onRead(std::uint8_t *data, std::size_t length,
                                         std::uint32_t *flags);

public:
  
  ServerResponse(ServerStream &stream);

  ServerStream &stream();

  void setOnRead(generator_callback cb);

};

}
}

#endif
