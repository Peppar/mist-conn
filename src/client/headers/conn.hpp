#ifndef __MIST_HEADERS_CONN_HPP__
#define __MIST_HEADERS_CONN_HPP__

#include <cstddef>
#include <functional>
#include <memory>

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

class ConnectContext;

struct TorAddress
{
  std::string hostname;
  std::uint16_t port;
};

class Peer
{
public:

  using address_list = std::list<TorAddress>;
  enum class ConnectionType { Direct, Tor };
  enum class ConnectionDirection { Client, Server };
  enum class ConnectionStatus { Disconnected, Connected };

  Peer(ConnectContext &ctx, std::string nickname,
    c_unique_ptr<CERTCertificate> cert);

  void connection(std::shared_ptr<io::Socket> socket,
    ConnectionType connType, ConnectionDirection connDirection);

  void reverseConnection(std::shared_ptr<io::Socket> socket,
    ConnectionDirection connDirection);

  const std::string nickname() const;

  const CERTCertificate *cert() const;

  const address_list &addresses() const;

  void addAddress(TorAddress address);

/*  h2::ClientRequest&
  submit(std::string method, std::string path, std::string scheme,
    std::string authority, h2::header_map headers,
    h2::generator_callback cb = nullptr);*/

private:

  friend class ConnectContext;

  h2::ClientSession &clientSession();

  std::shared_ptr<io::Socket> _socket;
  std::shared_ptr<h2::ServerSession> _serverSession;
  std::shared_ptr<h2::ClientSession> _clientSession;
  std::shared_ptr<h2::ServerSession> _reverseServerSession;
  std::shared_ptr<h2::ClientSession> _reverseClientSession;

  //void onRequest(h2::ServerRequest &request);

  ConnectContext &_ctx;
  std::string _nickname;
  c_unique_ptr<CERTCertificate> _cert;
  address_list _addresses;

};

class PeerDb
{
private:

  std::map<std::string, std::unique_ptr<Peer>> peers;

public:

  boost::optional<Peer&> findByKey(SECKEYPublicKey *key);
  boost::optional<Peer&> findByNickname(std::string nickname);

  PeerDb(ConnectContext &ctx, const std::string &directory);

};

class Service : public std::enable_shared_from_this<Service>
{
public:

  using peer_connection_status_callback =
    std::function<void(Peer&, Peer::ConnectionStatus)>;

  using peer_request_callback =
    std::function<void(Peer&, h2::ServerRequest&, std::string)>;

  using peer_websocket_callback =
    std::function<void(Peer&, std::string, std::shared_ptr<io::Socket>)>;

  using peer_submit_callback =
    std::function<void(Peer&, h2::ClientRequest&)>;

  void setOnPeerConnectionStatus(peer_connection_status_callback cb);

  void setOnPeerRequest(peer_request_callback cb);

  void submit(Peer &peer, std::string method, std::string path,
    peer_submit_callback cb);

  void setOnWebSocket(peer_websocket_callback cb);

  void openWebSocket(Peer& peer, std::string path,
    peer_websocket_callback cb);

  Service(ConnectContext &ctx, std::string name);

private:

  friend class ConnectContext;

  Service(Service &) = delete;
  Service &operator=(Service &) = delete;

  ConnectContext &_ctx;

  std::string _name;

  peer_connection_status_callback _onStatus;
  void onStatus(Peer& peer, Peer::ConnectionStatus status);

  peer_request_callback _onRequest;
  void onRequest(Peer& peer, h2::ServerRequest &request,
    std::string subPath);

  peer_websocket_callback _onWebSocket;
  void onWebSocket(Peer& peer, std::string path,
    std::shared_ptr<io::Socket> socket);

};

class ConnectContext
{
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

  std::shared_ptr<Service> newService(std::string name);

private:

  friend class Peer;

  friend class Service;

  /* SSL context */
  io::SSLContext &_sslCtx;

  /* Tor controller */
  std::shared_ptr<tor::TorController> _torCtrl;

  /* Hidden service for incoming Tor connections */
  boost::optional<tor::TorHiddenService&> _torHiddenService;

  /* Test peer database */
  PeerDb _peerDb;

  std::vector<std::string> _directories;

  std::map<std::string, std::shared_ptr<Service>> _services;

  void onPeerRequest(Peer &peer, h2::ServerRequest &request);

  void onPeerConnectionStatus(Peer &peer, Peer::ConnectionStatus status);

  void initializeReverseConnection(Peer &peer);

  void serviceSubmit(Service &service, Peer &peer, std::string method,
    std::string path, Service::peer_submit_callback cb);

  void serviceOpenWebSocket(Service &service, Peer &peer, std::string path,
    Service::peer_websocket_callback cb);
};

} // namespace mist

#endif
