#ifndef __MIST_HEADERS_H2_RESPONSE_HPP__
#define __MIST_HEADERS_H2_RESPONSE_HPP__

#include <nghttp2/nghttp2.h>

#include "h2/types.hpp"

namespace mist
{
namespace h2
{

class Stream;

class Response : public Lane
{
protected:

  data_callback _onData;
  
  virtual void onData(const std::uint8_t *data, std::size_t length) override;

public:
  
  Response(Stream &stream);

  void setOnData(data_callback cb);

};

}
}

#endif
