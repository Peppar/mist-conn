#include <cstddef>
#include <iostream>
#include <functional>

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

class Connection
{
protected:

  c_unique_ptr<nghttp2_session> h2session;
  
  Socket &sock;
  
  std::size_t recvConsumer(const uint8_t *data, std::size_t length)
  {
    ssize_t nrecvd = nghttp2_session_mem_recv(h2session.get(), data, length);
    if (nrecvd < 0) {
      boost::system::error_code ec = make_nghttp2_error(nrecvd);
      std::cerr << ec.message() << std::endl;
      // if (nrecvd == NGHTTP2_ERR_NOMEM)
        // /* TODO: Out of memory. */;
        // std::cerr << "NGHTTP2_ERR_NOMEM" << std::endl;
      // else if (nrecvd == NGHTTP2_ERR_CALLBACK_FAILURE)
        // /* TODO: */
        // std::cerr << "NGHTTP2_ERR_CALLBACK_FAILURE" << std::endl;
      // else if (nrecvd == NGHTTP2_ERR_BAD_CLIENT_MAGIC)
        // /* TODO: */
        // std::cerr << "NGHTTP2_ERR_BAD_CLIENT_MAGIC" << std::endl;
      // else if (nrecvd == NGHTTP2_ERR_FLOODED)
        // /* TODO: Close the socket */
        // std::cerr << "NGHTTP2_ERR_FLOODED" << std::endl;
      return 0
    }
    return nrecvd;
  }

  struct Send
  {
    const uint8_t *data;
    std::size_t length;
  } s;
  
  ssize_t sendCallback(const uint8_t *data, std::size_t length)
  {
    
    if (!s.length) {
      auto nsend = nghttp2_session_mem_send(h2session.get(), &s.data);
      if (nsend < 0) {
        std::cerr << "nghttp2_session_mem_send signaled an error" << std::endl;
        return 0;
      }
      s.length = nsend;
    }
    std::size_t avail = std::min(s.length, length);
    std::copy(s.data, s.data + avail, data);
    s.length -= avail;
    return avail;
  }
    

  Connection(Socket &sock)
    : sock(sock), h2session(to_unique<nghttp2_session>())
  {
    using namespace std::placeholders;
    
    c_unique_ptr<nghttp2_session_callbacks> cbs;
    {
      nghttp2_session_callbacks *cbsPtr = nullptr;
      nghttp2_session_callbacks_new(&cbsPtr);
      cbs = to_unique(cbsPtr);
    }
    
    nghttp2_session_callbacks_set_send_callback(cbs.get(),
      [](nghttp2_session *h2, const uint8_t *data,
         std::size_t length, int flags, void *userp) -> ssize_t
     {
       return ((Connection *)userp)->sendCallback(data, length);
     });
     
    {
      nghttp2_session *sessPtr = nullptr;
      nghttp2_session_client_new(&sessPtr, cbs.get(), this);
      h2session = to_unique(sessPtr);
    }
    
    sock.read(
      std::bind(&Connection::recvConsumer, this, _1, _2));
  }
};

class ConnectContext
{
protected:

  mist::SSLContext sslCtx;
  
  void directConnection(mist::Socket &sock)
  {
    std::cerr << "New direct connection!" << std::endl;
  }
  
  void torConnection(mist::Socket &sock)
  {
    std::cerr << "New Tor connection!" << std::endl;
    // Full handshake
    sock.handshake(
      [&sock](bool success)
    {
      std::cerr << "Handshaked! " << success << std::endl;
      auto sessionId = to_unique(SSL_GetSessionID(sock.fileDesc()));
      std::cerr << "Session ID = " << to_hex(sessionId.get()) << std::endl;
      const uint8_t *data = (const uint8_t *)"Hus";
      sock.write(data, 3);
      sock.readContinuous(
        [&sock](const uint8_t *data, std::size_t length) -> std::size_t
      {
        std::cerr << "Server received " << std::string((const char*)data, length) << std::endl;
      });
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
