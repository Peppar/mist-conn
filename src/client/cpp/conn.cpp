#include <cstddef>
#include <functional>
#include <iostream>

#include <boost/optional.hpp>
#include <boost/system/error_code.hpp>
#include <boost/system/system_error.hpp>
#include <boost/utility/string_ref.hpp> 
 
#include "error/mist.hpp"
#include "error/nghttp2.hpp"
#include "error/nss.hpp"
#include "memory/nghttp2.hpp"
#include "memory/nss.hpp"

#include "context.hpp"
#include "socket.hpp"
#include "conn.hpp"

namespace mist
{
namespace
{

std::string to_hex(uint8_t byte)
{
  static const char *digits = "0123456789abcdef";
  std::array<char, 2> text{digits[byte >> 4], digits[byte & 0xf]};
  return std::string(text.begin(), text.end());
}

template<typename It>
std::string to_hex(It begin, It end)
{
  std::string text;
  while (begin != end)
    text += to_hex(uint8_t(*(begin++)));
  return text;
}

std::string to_hex(SECItem *item)
{
  return to_hex((uint8_t *)item->data, (uint8_t *)(item->data + item->len));
}

std::string to_hex(std::string str)
{
  return to_hex((uint8_t *)str.data(), (uint8_t *)(str.data() + str.size()));
}

}

class PeerDb
{
  // Peers
  // Lookup by public key
  // Lookup by nickname
  // Add peer
  // Remove peer
  // Certificates
  // Revokation lists
};

class Peer
{
  // Pubkey
  // nickname
  // Gateways
};

class ConnectContext
{
protected:

  mist::SSLContext sslCtx;
  
  void directConnection(mist::Socket &sock)
  {
    std::cerr << "New direct connection!" << std::endl;
    
    // Full handshake
    sock.handshake(
      [&sock](boost::system::error_code ec)
    {
      if (ec) {
        /* Handshake error, we cannot accept this connection */
        std::cerr << "Handshake error" << std::endl;
        return;
      }
      auto sessionId = to_unique(SSL_GetSessionID(sock.fileDesc()));
      std::cerr << "Session ID = " << to_hex(sessionId.get()) << std::endl;
    });
  }
  
  void torConnection(mist::Socket &sock)
  {
    std::cerr << "New Tor connection!" << std::endl;
    
    // Full handshake
    sock.handshake(
      [&sock](boost::system::error_code ec)
    {
      if (ec) {
        /* Handshake error, we cannot accept this connection */
        std::cerr << "Handshake error" << std::endl;
        return;
      }
      auto sessionId = to_unique(SSL_GetSessionID(sock.fileDesc()));
      std::cerr << "Session ID = " << to_hex(sessionId.get()) << std::endl;
      // const uint8_t *data = (const uint8_t *)"Hus";
      // sock.write(data, 3);
      // sock.read(
        // [&sock](const uint8_t *data, std::size_t length, boost::system::error_code ec)
      // {
        // if (ec)
          // std::cerr << "Error!!" << std::endl;
        // else
          // std::cerr << "Server received " << std::string((const char*)data, length) << std::endl;
      // });
    });
  }
 
  uint16_t connectTorPort;

public:

  ConnectContext(const char *nickname, uint16_t connectTorPort)
    : sslCtx(nickname), connectTorPort(connectTorPort)
  {
  }

  void serve(uint16_t listenDirectPort, uint16_t listenTorPort)
  {
    using namespace std::placeholders;
    
    sslCtx.serve(listenDirectPort,
      std::bind(&ConnectContext::directConnection, this, _1));
    sslCtx.serve(listenTorPort,
      std::bind(&ConnectContext::torConnection, this, _1));
  }

};

}
