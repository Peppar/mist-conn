#ifndef __MIST_HEADERS_H2_TYPES_HPP__
#define __MIST_HEADERS_H2_TYPES_HPP__

#include <cstddef>
#include <functional>
#include <map>
#include <utility>

#include <boost/system/error_code.hpp>

#include <nghttp2/nghttp2.h>

namespace mist
{
namespace h2
{

class ClientSession;
class ClientResponse;
class ClientRequest;
class ServerSession;
class ServerResponse;
class ServerRequest;
  
using header_value = std::pair<std::string, bool>;
using header_map = std::map<std::string, header_value>;

using data_callback
  = std::function<void(const std::uint8_t *data, std::size_t length)>;
using generator_callback
  = std::function<ssize_t(std::uint8_t *data, std::size_t length,
                          std::uint32_t *flags)>;

using close_callback = std::function<void(const boost::system::error_code&)>;
using error_callback = std::function<void(const boost::system::error_code&)>;
using client_session_callback = std::function<void(ClientSession&)>;
using client_response_callback = std::function<void(ClientResponse&)>;
using client_request_callback = std::function<void(ClientRequest&)>;
using server_session_callback = std::function<void(ServerSession&)>;
using server_response_callback = std::function<void(ServerResponse&)>;
using server_request_callback = std::function<void(ServerRequest&)>;

}
}

#endif
