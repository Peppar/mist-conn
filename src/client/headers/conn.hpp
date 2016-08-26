#ifndef __MIST_HEADERS_CONN_HPP__
#define __MIST_HEADERS_CONN_HPP__

#include <cstddef>
#include <functional>

#include <boost/optional.hpp>
#include <boost/system/error_code.hpp>
#include <boost/system/system_error.hpp>
#include <boost/variant.hpp>
 
#include "error/mist.hpp"
#include "error/nghttp2.hpp"
#include "error/nss.hpp"
#include "memory/nghttp2.hpp"
#include "memory/nss.hpp"

#include "tor/tor.hpp"

#include "h2/session.hpp"
#include "h2/stream.hpp"
#include "h2/client_request.hpp"
#include "h2/client_response.hpp"
#include "h2/server_request.hpp"
#include "h2/server_response.hpp"

#include "io/io_context.hpp"
#include "io/ssl_context.hpp"
#include "io/ssl_socket.hpp"

namespace mist
{

struct TorAddress
{
  std::string hostname;
  std::uint16_t port;
};

class Peer
{
public:

  using address_list = std::list<TorAddress>;
  enum ConnectionType { Direct, Tor };
  enum ConnectionDirection { Client, Server };

private:

  std::shared_ptr<io::SSLSocket> _socket;
  std::shared_ptr<h2::ServerSession> _serverSession;
  std::shared_ptr<h2::ClientSession> _clientSession;

  void onRequest(h2::ServerRequest &request);

  std::string _nickname;
  c_unique_ptr<CERTCertificate> _cert;
  address_list _addresses;

public:

  Peer(std::string nickname, c_unique_ptr<CERTCertificate> cert);

  void connection(std::shared_ptr<io::SSLSocket> socket,
    ConnectionType connType, ConnectionDirection connDirection);

  const std::string nickname() const;
  const CERTCertificate *cert() const;

  const address_list &addresses() const;
  void addAddress(TorAddress address);

  h2::ClientRequest&
  submit(std::string method, std::string path, std::string scheme,
    std::string authority, h2::header_map headers,
    h2::generator_callback cb = nullptr);

};

class PeerDb
{
private:

  std::map<std::string, std::unique_ptr<Peer>> peers;

public:

  boost::optional<Peer&> findByKey(SECKEYPublicKey *key);
  boost::optional<Peer&> findByNickname(std::string nickname);
  
  PeerDb(const std::string &directory);

};

class ConnectContext;

class Service
{
private:

  Service(Service &) = delete;
  Service &operator=(Service &) = delete;

  ConnectContext &_ctx;

protected:

public:

  Service(ConnectContext &ctx);

  virtual ~Service();

  virtual void onServerSession(Peer &peer, h2::ServerSession &session) = 0;
  virtual void onClientSession(Peer &peer, h2::ClientSession &session) = 0;
  virtual void onWebSocket(Peer &peer) = 0;

};

class ConnectContext
{
private:

  /* SSL context */
  io::SSLContext &_sslCtx;
  
  /* Tor controller */
  std::shared_ptr<tor::TorController> _torCtrl;
  
  /* Hidden service for incoming Tor connections */
  boost::optional<tor::TorHiddenService&> _torHiddenService;

  /* Test peer database */
  PeerDb _peerDb;

  std::vector<std::string> _directories;

protected:

  using handshake_peer_callback
    = std::function<void(boost::optional<Peer&>, boost::system::error_code)>;

  boost::optional<Peer&> findPeerByCert(CERTCertificate *cert);

  void handshakePeer(io::SSLSocket &sock, boost::optional<Peer&> knownPeer,
    handshake_peer_callback cb);

  void incomingDirectConnection(std::shared_ptr<io::SSLSocket> socket);
  
  void incomingTorConnection(std::shared_ptr<io::SSLSocket> socket);

  void tryConnectPeerTor(Peer &peer, Peer::address_list::const_iterator it);

public:

  void connectPeerDirect(Peer &peer, PRNetAddr *addr);

  void connectPeerTor(Peer &peer);

  ConnectContext(io::SSLContext &sslCtx, std::string peerdir);

  io::IOContext &ioCtx();

  io::SSLContext &sslCtx();

  void addDirectory(std::string directory);
  
  boost::optional<Peer&> findPeerByName(const std::string &nickname);

  void serveDirect(std::uint16_t directIncomingPort);

  void startServeTor(std::uint16_t torIncomingPort,
                     std::uint16_t torOutgoingPort,
                     std::uint16_t controlPort,
                     std::string executableName,
                     std::string workingDir);

  void onionAddress(std::function<void(const std::string&)> cb);

  void exec();

};

} // namespace mist

#endif
