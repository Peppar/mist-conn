#ifndef __MIST_HEADERS_H2_TYPES_HPP__
#define __MIST_HEADERS_H2_TYPES_HPP__

#include <cstddef>
#include <functional>
#include <map>
#include <utility>

#include <boost/system/error_code.hpp>

namespace mist
{
namespace h2
{

class Session;
class Response;
class Request;
  
using header_value = std::pair<std::string, bool>;
using header_map = std::map<std::string, header_value>;

using data_callback
  = std::function<void(const std::uint8_t *data, std::size_t length)>;

using session_callback = std::function<void(Session &session)>;
using close_callback = std::function<void(const boost::system::error_code &ec)>;
using error_callback = std::function<void(const boost::system::error_code &ec)>;
using response_callback = std::function<void(Response&)>;
using request_callback = std::function<void(Request&)>;
using generator_callback
  = std::function<ssize_t(std::uint8_t *data, std::size_t length,
                          std::uint32_t *flags)>;

}
}

#endif
