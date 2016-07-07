#ifndef __ERROR_NSS_HPP__
#define __ERROR_NSS_HPP__

#include <boost/system/error_code.hpp>
#include <prerror.h>

const boost::system::error_category &nss_category() noexcept;

/* Create a boost::system::error_code with the given error value */
boost::system::error_code make_nss_error(PRErrorCode ev);

/* Use PR_GetError() to create a boost::system::error_code */
boost::system::error_code make_nss_error();

#endif
