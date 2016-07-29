#ifndef __ERROR_NGHTTP2_HPP__
#define __ERROR_NGHTTP2_HPP__

#include <cstddef>

#include <boost/system/error_code.hpp>

namespace mist
{

const boost::system::error_category &nghttp2_category() noexcept;

/* Creates a boost::system::error_code with the given error value */
boost::system::error_code make_nghttp2_error(std::uint32_t ev);

}

#endif
