#ifndef __ERROR_MIST_HPP__
#define __ERROR_MIST_HPP__

#include <boost/system/error_code.hpp>

namespace mist
{

typedef enum {
  MIST_ERR_ASSERTION = 8000,
  MIST_ERR_NOT_HTTP2 = 8001,
  MIST_ERR_NO_KEY_OR_CERT = 8002,
  MIST_ERR_SOCKS_HANDSHAKE = 8003,
} mist_error;

const boost::system::error_category &mist_category() noexcept;

/* Creates a boost::system::error_code with the given error value */
boost::system::error_code make_mist_error(mist_error ev);

}

#endif
