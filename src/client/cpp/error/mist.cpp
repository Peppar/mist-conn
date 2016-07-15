#include <boost/system/error_code.hpp>
#include "error/mist.hpp"

namespace mist
{

namespace
{

class mist_error_category : public boost::system::error_category
{
  const char *name() const noexcept
  {
    return "nghttp2";
  }
  
  std::string message(int ev) const
  {
    switch (ev) {
    case MIST_ERR_ASSERTION:
      return "MIST_ERR_ASSERTION";
    case MIST_ERR_NOT_HTTP2:
      return "MIST_ERR_NOT_HTTP2";
    case MIST_ERR_NO_KEY_OR_CERT:
      return "MIST_ERR_NO_KEY_OR_CERT";
    case MIST_ERR_SOCKS_HANDSHAKE:
      return "MIST_ERR_SOCKS_HANDSHAKE";
    default:
      return "Unknown mist error " + std::to_string(ev);
    }
  }
} instance;

}

const boost::system::error_category &mist_category() noexcept
{
  return instance;
}

boost::system::error_code make_mist_error(mist_error ev)
{
  return boost::system::error_code(ev, mist_category());
}

}
