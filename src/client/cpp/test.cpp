#include <cstddef>
#include <functional>
#include <iostream>

#include <boost/exception/diagnostic_information.hpp>
#include <boost/filesystem.hpp>
#include <boost/optional.hpp>
#include <boost/system/error_code.hpp>
#include <boost/system/system_error.hpp>
#include <boost/utility/string_ref.hpp> 
#include <boost/variant.hpp>

#include "error/mist.hpp"
#include "error/nghttp2.hpp"
#include "error/nss.hpp"
#include "memory/nghttp2.hpp"
#include "memory/nss.hpp"

#include "io/ssl_context.hpp"
#include "io/ssl_socket.hpp"

#include "conn.hpp"

#include "tor/tor.hpp"

#include "h2/session.hpp"
#include "h2/stream.hpp"
#include "h2/client_request.hpp"
#include "h2/client_response.hpp"
#include "h2/server_request.hpp"
#include "h2/server_response.hpp"

#include <base64.h>
#include <nss.h>
#include <secerr.h>
#include <sechash.h>
#include <secitem.h>

#include <cert.h>
#include <pk11priv.h>
#include <pk11pub.h>
#include <prthread.h>

namespace
{

  mist::h2::generator_callback
    make_generator(std::string body)
  {
    std::size_t sent = 0;

    return [body, sent](std::uint8_t *data, std::size_t length,
      std::uint32_t *flags) mutable -> ssize_t
    {
      std::size_t remaining = body.size() - sent;
      if (remaining == 0) {
        //*flags |= NGHTTP2_DATA_FLAG_EOF;
        return NGHTTP2_ERR_DEFERRED;
      } else {
        std::size_t nsend = std::min(remaining, length);
        std::copy(body.data() + sent, body.data() + sent + nsend, data);
        sent += nsend;
        return nsend;
      }
    };
  }

} // namespace

int
main(int argc, char **argv)
{
  //nss_init("db");
  //try {
  assert(argc == 5);
  bool isServer = static_cast<bool>(atoi(argv[1]));
  char *nickname = argv[2];
  boost::filesystem::path rootDir(argv[3]);
  boost::filesystem::path torPath(argv[4]);

  mist::io::IOContext ioCtx;
  mist::io::SSLContext sslCtx(ioCtx, (rootDir / "key_db").string(), nickname);
  mist::ConnectContext ctx(sslCtx, (rootDir / "peers").string());

  /*ioCtx.queueJob([]() {
  while (1) {
  std::cerr << "I am job number one!" << std::endl;
  PR_Sleep(PR_MillisecondsToInterval(1000));
  }
  });*/
  const std::uint16_t directIncoming = isServer ? 8250 : 6483;
  const std::uint16_t torIncoming = isServer ? 8148 : 6480;
  const std::uint16_t torOutgoing = isServer ? 8158 : 6481;
  const std::uint16_t controlPort = isServer ? 8190 : 6482;

  ctx.serveDirect(directIncoming); // Direct incoming port
  ctx.startServeTor(
    torIncoming, // Tor incoming port
    torOutgoing, // Tor outgoing port
    controlPort, // Control port
    torPath.string(),
    //"C:\\Users\\Oskar\\Desktop\\Tor\\Browser\\TorBrowser\\Tor\\tor.exe",
    //"C:\\Users\\Oskar\\Desktop\\Tor\\Browser\\TorBrowser\\Tor");
    rootDir.string());
  //ctx.externalTor(isServer ? 9158 : 7159);
  ctx.onionAddress(
    [&ctx](const std::string &addr)
  {
    std::cerr << "Onion address is " << addr << std::endl;
    mist::Peer &peer = *ctx.findPeerByName("myself");
    /*peer.setOnionAddress(addr);
    peer.setOnionPort(443);*/
  });
  //ctx.setOnSession(
  //  [=](mist::h2::ServerSession &session)
  //{
  //  std::cerr << "Server onSession" << std::endl;
  //  session.setOnRequest(
  //    [=, &session](mist::h2::ServerRequest &request)
  //  {
  //    request.stream().setOnClose(
  //      [](boost::system::error_code ec)
  //    {
  //      std::cerr << "Server stream closed! " << ec.message() << std::endl;
  //    });
  //    std::cerr << "New request!" << std::endl;
  //    
  //    mist::h2::header_map headers
  //    {
  //      {"accept", {"*/*", false}},
  //      {"accept-encoding", {"gzip, deflate", false}},
  //      {"user-agent", {"nghttp2/" NGHTTP2_VERSION, false}},
  //    };
  //    request.stream().submit(404, std::move(headers),
  //      make_generator("Hej!!"));
  //  });
  //});
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

  auto service = ctx.newService("chat");

  service->setOnPeerConnectionStatus(
    [service](mist::Peer &peer, mist::Peer::ConnectionStatus status)
  {
    std::cerr << "On peer connection status" << std::endl;
    if (status == mist::Peer::ConnectionStatus::Connected) {

      //service->submit(peer, "GET", "hej",
      //  [service](mist::Peer &peer, mist::h2::ClientRequest &request)
      //{
      //  std::cerr << "Service could connect to peer!" << std::endl;
      //  request.setOnResponse(
      //    [](mist::h2::ClientResponse &response)
      //  {
      //    std::cerr << "On peer response : " << *response.statusCode() << std::endl;
      //    for (auto& header : response.headers()) {
      //      std::cerr << "Header " << header.first << " = " << header.second.first << std::endl;
      //    }
      //  });
      //});
      service->openWebSocket(peer, "hoj",
        [](mist::Peer &peer, std::string path, std::shared_ptr<mist::io::Socket> socket)
      {
        std::cerr << "Opened websocket" << std::endl;

        socket->read([socket](const std::uint8_t *data, std::size_t length, boost::system::error_code ec)
        {
          std::cerr << "Client got data from websocket:"
            << std::string(reinterpret_cast<const char*>(data), length)
            << std::endl;
        });

        const char *myData = "Hejsan hojsan";
        socket->write(reinterpret_cast<const std::uint8_t*>(myData), 13);
      });
    }
  });

  service->setOnPeerRequest(
    [service](const mist::Peer &peer, mist::h2::ServerRequest &request,
      std::string subPath)
  {
    std::cerr << "On peer request" << std::endl;
    for (auto& header : request.headers()) {
      std::cerr << "Header " << header.first << " = " << header.second.first << std::endl;
    }
    request.stream().submit(200, mist::h2::header_map(), nullptr);
  });

  service->setOnWebSocket(
    [service](const mist::Peer &peer, std::string path,
       std::shared_ptr<mist::io::Socket> socket)
  {
    std::cerr << "On websocket" << std::endl;

    socket->read([socket](const std::uint8_t *data, std::size_t length, boost::system::error_code ec)
    {
      std::cerr << "Server got data from websocket:"
        << std::string(reinterpret_cast<const char*>(data), length)
        << std::endl;
    });

    const char *myData = "Mossan korven";
    socket->write(reinterpret_cast<const std::uint8_t*>(myData), 13);
  });

  if (!isServer) {
    // Try connect

    //if (PR_StringToNetAddr(
    //  "130.211.116.44",
    //  &addr) != PR_SUCCESS)
    //  throw new std::runtime_error("PR_InitializeNetAddr failed");
    //addr.inet.port = PR_htons(443);
    //if (PR_InitializeNetAddr(PR_IpAddrLoopback, 9150, &addr) != PR_SUCCESS)
    //  throw new std::runtime_error("PR_InitializeNetAddr failed");

    //mist::Socket &sock = sslCtx.openClientSocket();
    ioCtx.setTimeout(10000,
      [=, &ctx]()
    {
      PRNetAddr addr;
      if (PR_InitializeNetAddr(PR_IpAddrLoopback, directIncoming, &addr) != PR_SUCCESS)
        throw new std::runtime_error("PR_InitializeNetAddr failed");

      std::cerr << "Trying to connect..." << std::endl;
      mist::Peer &peer = *ctx.findPeerByName("myself");
      ctx.connectPeerDirect(peer, &addr);
    });
    //ioCtx.setTimeout(20000,
    //  [&ctx]()
    //{
    //  std::cerr << "Trying to connect..." << std::endl;
    //  mist::Peer &peer = *ctx.findPeerByName("myself");
    //  ctx.connectPeerTor(peer,
    //    [&ctx](boost::variant<mist::PeerConnection&, boost::system::error_code> result)
    //  {
    //    if (result.which() == 0) {
    //      auto peerConn = boost::get<mist::PeerConnection&>(result);
    //      std::cerr << "Connection successful!" << std::endl;
    //      // session.setOnError(
    //      // [&session](boost::system::error_code ec)
    //      // {
    //      // std::cerr << "Session error!!" << ec.message() << std::endl;
    //      // });

    //      // boost::system::error_code ec;
    //      // mist::h2::header_map headers
    //      // {
    //      // {"accept", {"*/*", false}},
    //      // {"accept-encoding", {"gzip, deflate", false}},
    //      // {"user-agent", {"nghttp2/" NGHTTP2_VERSION, false}},
    //      // };
    //      // auto req = session.submit(ec, "GET", "/", "https", "www.hej.os",
    //      // headers);
    //      // if (ec)
    //      // std::cerr << ec.message() << std::endl;
    //      // if (!req) {
    //      // std::cerr << "Could not submit" << std::endl;
    //      // return;
    //      // }
    //      // std::cerr << "Submitted" << std::endl;

    //      // mist::h2::ClientRequest &request = req.get();

    //      // request.stream().setOnClose(
    //      // [](boost::system::error_code ec)
    //      // {
    //      // std::cerr << "Client stream closed! " << ec.message() << std::endl;
    //      // });

    //      // request.setOnResponse(
    //      // [&request, &session]
    //      // (mist::h2::ClientResponse &response)
    //      // {
    //      // std::cerr << "Got response!" << std::endl;

    //      // response.setOnData(
    //      // [&response, &session]
    //      // (const std::uint8_t *data, std::size_t length)
    //      // {
    //      // for (auto &kv : response.headers()) {
    //      // std::cerr << kv.first << ", " << kv.second.first << std::endl;
    //      // }
    //      // std::cerr << "Got data of length " << length << std::endl;
    //      // std::cerr << std::string(reinterpret_cast<const char*>(data), length) << std::endl;
    //      // });
    //      // });
    //    }
    //    else {
    //      auto ec = boost::get<boost::system::error_code>(result);
    //      std::cerr << "Error when connecting " << ec.message() << std::endl;
    //    }
    //  });
    //});
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
  //} catch(boost::exception &) {
  //  std::cerr
  //    << "Unexpected exception, diagnostic information follows:" << std::endl
  //    << boost::current_exception_diagnostic_information();
  //}
}
