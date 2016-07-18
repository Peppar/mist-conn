#include <cstddef>
#include <functional>
#include <iostream>

#include <boost/exception/diagnostic_information.hpp> 
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

#include "h2/session.hpp"
#include "h2/stream.hpp"
#include "h2/request.hpp"
#include "h2/response.hpp"

namespace mist
{
namespace h2
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

  SSLContext sslCtx;
  
  std::list<Session> sessions;

  uint16_t connectTorPort;
  
  session_callback _sessionCb;

protected:

  Session &createSession(Socket &socket, bool isServer)
  {
    sessions.emplace_back(socket, isServer);
    return *(--sessions.end());
  }

  void directConnection(Socket &sock)
  {
    std::cerr << "New direct connection!" << std::endl;
    
    // Full handshake
    sock.handshake(
      [=, &sock](boost::system::error_code ec)
    {
      if (ec) {
        /* Handshake error, we cannot accept this connection */
        std::cerr << "Handshake error : " << ec.message() <<std::endl;
        return;
      }
      auto sessionId = to_unique(SSL_GetSessionID(sock.fileDesc()));
      std::cerr << "Session ID = " << to_hex(sessionId.get()) << std::endl;
      
      onSession(createSession(sock, true));
    });
  }
  
  void torConnection(Socket &sock)
  {
    std::cerr << "New Tor connection!" << std::endl;
    
    // Full handshake
    sock.handshake(
      [=, &sock](boost::system::error_code ec)
    {
      if (ec) {
        /* Handshake error, we cannot accept this connection */
        std::cerr << "Handshake error : " << ec.message() << std::endl;
        return;
      }
      auto sessionId = to_unique(SSL_GetSessionID(sock.fileDesc()));
      std::cerr << "Session ID = " << to_hex(sessionId.get()) << std::endl;

      onSession(createSession(sock, true));
    });
  }
 
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
  
  void connect(PRNetAddr *addr, session_callback cb)
  {
    Socket &sock = sslCtx.openClientSocket();
    sock.connect(addr,
      [=, &sock, cb(std::move(cb))](boost::system::error_code ec)
    {
      if (ec) {
        std::cerr << "Could not connect: " << ec.message() << std::endl;
      } else {
        std::cerr << "Connected! Initializing TLS..." << std::endl;
        sock.handshake(
          [=, &sock, cb(std::move(cb))](boost::system::error_code ec)
        {
          if (ec) {
            std::cerr << "Could not handshake: " << ec.message() << std::endl;
          } else {
            std::cerr << "Handshake successful!" << std::endl;
            
            cb(createSession(sock, false));
          }
        });
      }
    });
  }
  
  void setOnSession(session_callback sessionCb)
  {
    _sessionCb = std::move(sessionCb);
  }
  
  void onSession(Session &session)
  {
    if (_sessionCb)
      _sessionCb(session);
  }
  
  void exec()
  {
    sslCtx.exec();
  }

};

}
}


int
main(int argc, char **argv)
{
  //nss_init("db");
  try {
    assert(argc == 3);
    bool isServer = atoi(argv[1]);
    char *nickname = argv[2];
    int port = isServer ? 9150 : 9151;
    
    mist::h2::ConnectContext ctx(nickname, 9160);
    ctx.serve(port, isServer ? 9158 : 9159);
    ctx.setOnSession(
      [=](mist::h2::Session &session)
    {
      session.setOnRequest(
        [&session, =](mist::h2::Request &request)
      {
        
      });
    });
    /*
    sslCtx.serve(port,
      [](mist::Socket &sock)
    {
      std::cerr << "New connection !!! " << std::endl;
      sock.handshake(
        [&sock](boost::system::error_code ec)
      {
        if (ec) {
          std::cerr << "Error!!!" << std::endl;
          return;
        }
        std::cerr << "Handshaked! " << std::endl;
        auto sessionId = to_unique(SSL_GetSessionID(sock.fileDesc()));
        std::cerr << "Session ID = " << to_hex(sessionId.get()) << std::endl;
        const uint8_t *data = (const uint8_t *)"Hus";
        sock.write(data, 3);
        sock.read(
          [&sock](const uint8_t *data, std::size_t length, boost::system::error_code ec)
        {
          if (ec)
            std::cerr << "Read error!!!" << std::endl;
          std::cerr << "Server received " << std::string((const char*)data, length) << std::endl;
        });
      });
    });
    */
    if (!isServer) {
      // Try connect
      PRNetAddr addr;
      
      //if (PR_StringToNetAddr(
      //  "130.211.116.44",
      //  &addr) != PR_SUCCESS)
      //  throw new std::runtime_error("PR_InitializeNetAddr failed");
      //addr.inet.port = PR_htons(443);
      if (PR_InitializeNetAddr(PR_IpAddrLoopback, 9150, &addr) != PR_SUCCESS)
        throw new std::runtime_error("PR_InitializeNetAddr failed");
    
      //mist::Socket &sock = sslCtx.openClientSocket();
      std::cerr << "Trying to connect..." << std::endl;
      ctx.connect(&addr,
        [&ctx](mist::h2::Session &session)
      {
        session.setOnError(
          [&session](boost::system::error_code ec)
        {
          std::cerr << "Session error!!" << ec.message() << std::endl;
        });
        
        boost::system::error_code ec;
        mist::h2::header_map headers
        {
          {"accept", {"*/*", false}},
          {"accept-encoding", {"gzip, deflate", false}},
          {"user-agent", {"nghttp2/" NGHTTP2_VERSION, false}},
        };
        auto req = session.submit(ec, "GET", "/", "", headers, nullptr);
        if (ec)
          std::cerr << ec.message() << std::endl;
        if (!req) {
          std::cerr << "Could not submit" << std::endl;
          return;
        }
        
        mist::h2::Request &request = req.get();
        
        request.setOnResponse(
          [&request, &session]
          (mist::h2::Response &response)
        {
          std::cerr << "Got response!" << std::endl;
          
          response.setOnData(
            [&response, &session]
            (const std::uint8_t *data, std::size_t length)
          {
            // for (auto &kv : response.headers()) {
              // std::cerr << kv.first << ", " << kv.second << std::endl;
            // }
            std::cerr << "Got data of length " << length << std::endl;
          });
        });
      });
    }

    ctx.exec();
    //ventLoop(port, nickname, isServer ? 0 : 9150);
    //auto cert = createRootCert(privk, pubk, hashAlgTag, );
    // if (isServer) {
      // std::cerr << "Server" << std::endl;
      // server(nickname);
    // } else {
      // std::cerr << "Client" << std::endl;
      // client(nickname);
    // }
  } catch(boost::exception &e) {
    std::cerr
      << "Unexpected exception, diagnostic information follows:" << std::endl
      << boost::current_exception_diagnostic_information();
  }
}
