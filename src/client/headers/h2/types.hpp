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
class ClientResponse;
class ClientRequest;
class ServerResponse;
class ServerRequest;
  
using header_value = std::pair<std::string, bool>;
using header_map = std::map<std::string, header_value>;

using data_callback
  = std::function<void(const std::uint8_t *data, std::size_t length)>;

using session_callback = std::function<void(Session &session)>;
using close_callback = std::function<void(const boost::system::error_code &ec)>;
using error_callback = std::function<void(const boost::system::error_code &ec)>;
using client_response_callback = std::function<void(ClientResponse&)>;
using client_request_callback = std::function<void(ClientRequest&)>;
using server_response_callback = std::function<void(ServerResponse&)>;
using server_request_callback = std::function<void(ServerRequest&)>;
using generator_callback
  = std::function<ssize_t(std::uint8_t *data, std::size_t length,
                          std::uint32_t *flags)>;

}
}

#endif
