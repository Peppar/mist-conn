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

class Peer
{
private:

  std::string _nickname;
  c_unique_ptr<CERTCertificate> _cert;
  boost::optional<std::string> _onionAddress;
  boost::optional<std::uint16_t> _onionPort;

public:

  const std::string nickname() const;
  const CERTCertificate *cert() const;

  void setOnionAddress(std::string onionAddress);
  const boost::optional<std::string> &onionAddress() const;

  void setOnionPort(std::uint16_t onionPort);
  const boost::optional<std::uint16_t> &onionPort() const;
  
  Peer(std::string nickname, c_unique_ptr<CERTCertificate> cert);

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

class PeerConnection
{
private:

  friend class ConnectContext;
  
  ConnectContext &_context;

  enum class State {
    Unconnected,
    TorConnected,
    DirectConnecting,
    DirectConnected,
  } _state;
  
  Peer &_peer;

  std::shared_ptr<h2::Session> _session;

  void torConnection(std::shared_ptr<io::SSLSocket> socket);
  
  void directConnection(std::shared_ptr<io::SSLSocket> socket);

  void connect();

public:

  virtual ~PeerConnection();
  
  ConnectContext &context();

  virtual h2::Session &session();
  
  /*
  template<typename SessionT, typename... Args>
  SessionT &makeSession(Args&&... args)
  {
    std::unique_ptr<SessionT> session
      = std::make_unique<SessionT>(std::forward<Args>(args)...);
    
    SessionT &sessionRef = *session;
    sessions.emplace_back(std::move(session));
    
    sessionRef.
    return sessionRef;
  }

  template<typename SessionT>
  SessionT &setSession(std::unique_ptr<SessionT> session)
  {
    _session = std::move(session);
    return *static_cast<SessionT>(_session.get());
  }*/

  PeerConnection(ConnectContext &context, Peer &peer);

  Peer &peer();

};

class ConnectContext
{
public:

  using peer_connection_callback = std::function<void(PeerConnection&)>;

private:

  friend class PeerConnection;

  /* SSL context */
  io::SSLContext &_sslCtx;
  
  /* Tor controller */
  std::unique_ptr<tor::TorController> _torCtrl;
  
  /* Test peer database */
  PeerDb _peerDb;

  /* Peer to PeerConnection map */
  std::map<Peer*, std::unique_ptr<PeerConnection>> _peerConnections;

  /* Outgoing connection Tor port (SOCKS5) */
  boost::optional<std::uint16_t> _torOutgoingPort;
  
  boost::optional<tor::TorHiddenService&> _torHiddenService;

  peer_connection_callback _connectionCb;
  
  h2::server_session_callback _sessionCb;

protected:

  using handshake_peer_callback
    = std::function<void(boost::variant<PeerConnection&,
                                        boost::system::error_code>)>;

  boost::optional<Peer&> findPeerByCert(CERTCertificate *cert);

  void handshakePeer(io::SSLSocket &sock, boost::optional<Peer&> knownPeer,
                     handshake_peer_callback cb);

  void incomingDirectConnection(std::shared_ptr<io::SSLSocket> socket);
  
  void incomingTorConnection(std::shared_ptr<io::SSLSocket> socket);

public:

  ConnectContext(io::SSLContext &sslCtx, std::string peerdir);

  io::IOContext &ioCtx();

  io::SSLContext &sslCtx();
  
  boost::optional<Peer&> findPeerByName(const std::string &nickname);

  void connectPeerDirect(Peer &peer, PRNetAddr *addr,
    handshake_peer_callback cb);

  void connectPeerTor(Peer &peer, handshake_peer_callback cb);

  void serveDirect(std::uint16_t directIncomingPort);

  void startServeTor(std::uint16_t torIncomingPort,
                     std::uint16_t torOutgoingPort,
                     std::uint16_t controlPort,
                     std::string executableName,
                     std::string workingDir);

  void externalTor(std::uint16_t torOutgoingPort);

  void onionAddress(std::function<void(const std::string&)> cb);
  
  /* Returns the existing connection for the peer, or creates a new one */
  PeerConnection &peerConnection(Peer &peer);

  void setOnPeerConnection(peer_connection_callback peerCb);

  void setOnSession(h2::server_session_callback sessionCb);

  void onSession(h2::ServerSession &session);

  void exec();

};

} // namespace mist

#endif
