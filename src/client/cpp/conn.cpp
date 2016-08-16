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

std::string
hash(const std::uint8_t *begin, const std::uint8_t *end)
{
  SECOidTag hashOIDTag = SEC_OID_SHA256;
  std::array<std::uint8_t, 64> digest;
  unsigned int len;
  
  HASH_HashType hashType = HASH_GetHashTypeByOidTag(hashOIDTag);
  
  auto ctx = to_unique(HASH_Create(hashType));
  HASH_Begin(ctx.get());
  HASH_Update(ctx.get(),
    reinterpret_cast<const unsigned char *>(begin), end - begin);
  HASH_End(ctx.get(),
    reinterpret_cast<unsigned char *>(digest.data()), &len, digest.size());
  
  return std::string(reinterpret_cast<const char *>(digest.data()), len);
}

/* Taken directly from NSS source */
SECStatus
SECU_FileToItem(SECItem *dst, PRFileDesc *src)
{
    PRFileInfo info;
    PRInt32 numBytes;
    PRStatus prStatus;

    prStatus = PR_GetOpenFileInfo(src, &info);

    if (prStatus != PR_SUCCESS) {
        PORT_SetError(SEC_ERROR_IO);
        return SECFailure;
    }

    /* XXX workaround for 3.1, not all utils zero dst before sending */
    dst->data = 0;
    if (!SECITEM_AllocItem(NULL, dst, info.size))
        goto loser;

    numBytes = PR_Read(src, dst->data, info.size);
    if (numBytes != info.size) {
        PORT_SetError(SEC_ERROR_IO);
        goto loser;
    }

    return SECSuccess;
loser:
    SECITEM_FreeItem(dst, PR_FALSE);
    return SECFailure;
}

/* Taken directly from NSS source */
SECStatus
SECU_ReadDERFromFile(SECItem *der, PRFileDesc *inFile, PRBool ascii)
{
    SECStatus rv;
    if (ascii) {
        /* First convert ascii to binary */
        SECItem filedata;
        char *asc, *body;

        /* Read in ascii data */
        rv = SECU_FileToItem(&filedata, inFile);
        asc = (char *)filedata.data;
        if (!asc) {
            fprintf(stderr, "unable to read data from input file\n");
            return SECFailure;
        }

        /* check for headers and trailers and remove them */
        if ((body = strstr(asc, "-----BEGIN")) != NULL) {
            char *trailer = NULL;
            asc = body;
            body = PORT_Strchr(body, '\n');
            if (!body)
                body = PORT_Strchr(asc, '\r'); /* maybe this is a MAC file */
            if (body)
                trailer = strstr(++body, "-----END");
            if (trailer != NULL) {
                *trailer = '\0';
            } else {
                fprintf(stderr, "input has header but no trailer\n");
                PORT_Free(filedata.data);
                return SECFailure;
            }
        } else {
            body = asc;
        }
     
        /* Convert to binary */
        rv = ATOB_ConvertAsciiToItem(der, body);
        if (rv) {
            return SECFailure;
        }

        PORT_Free(filedata.data);
    } else {
        /* Read in binary der */
        rv = SECU_FileToItem(der, inFile);
        if (rv) {
            return SECFailure;
        }
    }
    return SECSuccess;
}

std::string
pubKeyHash(SECKEYPublicKey *key)
{
  auto derPubKey = to_unique(SECKEY_EncodeDERSubjectPublicKeyInfo(key));
  return hash(derPubKey->data, derPubKey->data + derPubKey->len);
}

std::string
certPubKeyHash(CERTCertificate *cert)
{
  auto pubKey = to_unique(CERT_ExtractPublicKey(cert));
  return pubKeyHash(pubKey.get());
}
}

/*
 * Peer
 */

Peer::Peer(std::string nickname, c_unique_ptr<CERTCertificate> cert)
  : _nickname(std::move(nickname)), _cert(std::move(cert))
  {}

const std::string
Peer::nickname() const
{
  return _nickname;
}

const CERTCertificate *
Peer::cert() const
{
  return _cert.get();
}

void
Peer::setOnionAddress(std::string onionAddress)
{
  _onionAddress = onionAddress;
}

const boost::optional<std::string> &
Peer::onionAddress() const
{
  return _onionAddress;
}

void
Peer::setOnionPort(std::uint16_t onionPort)
{
  _onionPort = onionPort;
}

const boost::optional<std::uint16_t> &
Peer::onionPort() const
{
  return _onionPort;
}

/*
 * PeerDb
 */
namespace
{
std::string nicknameFromFilename(const std::string &filename)
{
  std::size_t pos = filename.find_last_of('.');
  if (pos == std::string::npos)
    return filename;
  return std::string(filename.data(), filename.data() + pos);
}
}

PeerDb::PeerDb(const std::string &directory)
{
  /* Open the peer directory */
  auto dir = to_unique(PR_OpenDir(directory.c_str()));
  if (!dir)
    BOOST_THROW_EXCEPTION(boost::system::system_error(make_nss_error(),
      "Unable to open the peer directory"));

  /* Read the peer directory */
  PRDirEntry *entry;
  while (entry = PR_ReadDir(dir.get(),
                       static_cast<PRDirFlags>(PR_SKIP_BOTH|PR_SKIP_HIDDEN))) {
    std::string filename = entry->name;
    std::string fullname = directory + "/" + filename;
    
    auto file = to_unique(PR_Open(fullname.c_str(), PR_RDONLY, 0));
    if (!file)
      BOOST_THROW_EXCEPTION(boost::system::system_error(make_nss_error(),
        "Unable to open peer file " + filename));

    SECItem certDER;
    if (SECU_ReadDERFromFile(&certDER, file.get(), PR_TRUE) != SECSuccess)
      BOOST_THROW_EXCEPTION(boost::system::system_error(make_nss_error(),
        "Unable to read peer file " + filename));

    auto cert = to_unique(CERT_DecodeCertFromPackage(
                         reinterpret_cast<char *>(certDER.data), certDER.len));
    if (!cert)
      BOOST_THROW_EXCEPTION(boost::system::system_error(make_nss_error(),
        "Unable to obtain certificate from file " + filename));

    auto pubKey = to_unique(CERT_ExtractPublicKey(cert.get()));
    if (!cert)
      BOOST_THROW_EXCEPTION(boost::system::system_error(make_nss_error(),
        "Unable to obtain public key from certificate in file " + filename));

    auto nickname = nicknameFromFilename(filename);
    auto keyHash = pubKeyHash(pubKey.get());

    std::cerr << "Added peer " << nickname << " with key hash " << to_hex(keyHash) << std::endl;

    peers.insert(std::make_pair(keyHash,
                                std::make_unique<Peer>(nickname,
                                                       std::move(cert))));
  }
  if (PR_GetError() != PR_NO_MORE_FILES_ERROR) {
    BOOST_THROW_EXCEPTION(boost::system::system_error(make_nss_error(),
      "Unable to read the peer directory"));
  }
}

boost::optional<Peer&>
PeerDb::findByKey(SECKEYPublicKey *key)
{
  auto it = peers.find(pubKeyHash(key));
  if (it != peers.end()) {
    return *it->second;
  } else {
    return boost::none;
  }
}

boost::optional<Peer&>
PeerDb::findByNickname(std::string nickname)
{
  for (auto &kv : peers) {
    if (kv.second->nickname() == nickname) {
      return *kv.second;
    }
  }
  return boost::none;
}

/*
 * PeerConnection
 */
PeerConnection::PeerConnection(ConnectContext &context, Peer &peer)
  : _context(context), _peer(peer)
{
}

PeerConnection::~PeerConnection()
{
}
  
void
PeerConnection::torConnection(std::shared_ptr<io::SSLSocket> socket)
{
}
  
void
PeerConnection::directConnection(std::shared_ptr<io::SSLSocket> socket)
{
  auto sessionId = to_unique(SSL_GetSessionID(socket->fileDesc()));
  std::cerr << "Session ID = " << to_hex(sessionId.get()) << std::endl;
  if (_state != State::DirectConnecting) {
    /* We do not expect a direct connection here... */
  }
  
  /* Move the socket to a new ServerSession */
  auto session = std::make_unique<h2::ServerSession>(std::move(socket));
  h2::ServerSession &sessionR = *session;
  _session = std::move(session);
  context().onSession(sessionR);
}

void 
PeerConnection::connect()
{
}

ConnectContext &
PeerConnection::context() 
{ 
  return _context; 
}

h2::Session &
PeerConnection::session()
{
  return *_session;
}

Peer &
PeerConnection::peer()
{ 
  return _peer; 
}

/*
 * ConnectContext
 */

namespace
{

using socks_callback
  = std::function<void(std::string, boost::system::error_code)>;

/* Try to perform a SOCKS5 handshake to connect to the given
   domain name and port. */
void
handshakeSOCKS5(mist::io::Socket &sock,
                std::string hostname, std::uint16_t port,
                socks_callback cb)
{
  std::array<std::uint8_t, 3> socksReq;
  socksReq[0] = 5; /* Version */
  socksReq[1] = 1;
  socksReq[2] = 0;

  sock.write(socksReq.data(), socksReq.size());

  sock.readOnce(2,
    [=, &sock, cb(std::move(cb))]
    (const std::uint8_t *data, std::size_t length,
     boost::system::error_code ec) mutable
  {
    if (ec) {
      cb("", ec);
      return;
    }
    if (length != 2 || data[0] != 5 || data[1] != 0) {
      cb("", mist::make_mist_error(mist::MIST_ERR_SOCKS_HANDSHAKE));
      return;
    }
    
    /* Construct the SOCKS5 connect request */
    std::vector<std::uint8_t> connReq(5 + hostname.length() + 2);
    {
      auto outIt = connReq.begin();
      *(outIt++) = 5; /* Version */
      *(outIt++) = 1; /* Connect */
      *(outIt++) = 0; /* Must be zero */
      *(outIt++) = 3; /* Resolve domain name */
      *(outIt++) = static_cast<std::uint8_t>(hostname.length()); /* Domain name length */
      outIt = std::copy(hostname.begin(), hostname.end(), outIt); /* Domain name */
      *(outIt++) = static_cast<std::uint8_t>((port >> 8) & 0xff); /* Port MSB */
      *(outIt++) = static_cast<std::uint8_t>(port & 0xff); /* Port LSB */
      /* Make sure that we can count */
      assert (outIt == connReq.end());
    }
    
    sock.write(connReq.data(), connReq.size());
    
    /* Read 5 bytes; these are all the bytes we need to determine the
       final packet size */
    sock.readOnce(5,
      [=, &sock, cb(std::move(cb))]
      (const std::uint8_t *data, std::size_t length,
       boost::system::error_code ec) mutable
    {
      if (ec) {
        cb("", ec);
        return;
      }
      if (length != 5 || data[0] != 5) {
        cb("", mist::make_mist_error(mist::MIST_ERR_SOCKS_HANDSHAKE));
        return;
      }
      
      bool success = data[1] == 0;
      std::uint8_t type = data[3];
      std::uint8_t firstByte = data[4];
      
      std::size_t complLength;
      if (type == 1)
        complLength = 10 - 5;
      else if (type == 3)
        complLength = 7 + firstByte - 5;
      else if (type == 4)
        complLength = 22 - 5;
      else {
        cb("", mist::make_mist_error(mist::MIST_ERR_SOCKS_HANDSHAKE));
        return;
      }
      
      sock.readOnce(complLength,
        [=, &sock, cb(std::move(cb))]
        (const std::uint8_t *data, std::size_t length,
         boost::system::error_code ec) mutable
      {
        if (ec) {
          cb("", ec);
          return;
        }
        if (complLength != length) {
          cb("", mist::make_mist_error(mist::MIST_ERR_SOCKS_HANDSHAKE));
          return;
        }
        
        std::string address;
        if (type == 1)
          address = std::to_string(firstByte) + '.'
            + std::to_string(data[0]) + '.'
            + std::to_string(data[1]) + '.'
            + std::to_string(data[2]) + ':'
            + std::to_string((data[3] << 8) | data[4]);
        else if (type == 3)
          address = std::string(reinterpret_cast<const char*>(data),
                                firstByte) + ':'
            + std::to_string((data[firstByte] << 8) | data[firstByte + 1]);
        else if (type == 4)
          address = to_hex(firstByte) + to_hex(data[0]) + ':'
            + to_hex(data[1]) + to_hex(data[2]) + ':'
            + to_hex(data[3]) + to_hex(data[4]) + ':'
            + to_hex(data[5]) + to_hex(data[6]) + ':'
            + to_hex(data[7]) + to_hex(data[8]) + ':'
            + to_hex(data[9]) + to_hex(data[10]) + ':'
            + to_hex(data[11]) + to_hex(data[12]) + ':'
            + to_hex(data[13]) + to_hex(data[14]) + ':'
            + std::to_string((data[15] << 8) | data[16]);
        assert (address.length());
        if (!success) {
          cb(address, mist::make_mist_error(mist::MIST_ERR_SOCKS_HANDSHAKE));
        } else {
          cb(address, boost::system::error_code());
        }
      });
    });
  });
}

/* Connect the socket through a local Tor SOCKS5 proxy. */
void
connectTor(mist::io::Socket &sock, std::uint16_t torPort,
           std::string hostname, std::uint16_t port,
           socks_callback cb)
{
  /* Initialize addr to localhost:torPort */
  PRNetAddr addr;
  if (PR_InitializeNetAddr(PR_IpAddrLoopback, torPort, &addr) != PR_SUCCESS) {
    cb("", mist::make_nss_error());
    return;
  }

  sock.connect(&addr,
    [=, &sock, cb(std::move(cb))]
    (boost::system::error_code ec) mutable
  {
    if (ec) {
      cb("", ec);
      return;
    }
    handshakeSOCKS5(sock, std::move(hostname), port, std::move(cb));
  });
}

} // namespace

ConnectContext::ConnectContext(io::SSLContext &sslCtx,
                               std::string peerdir)
  : _sslCtx(sslCtx), _peerDb(std::move(peerdir))
  {}

io::IOContext &
ConnectContext::ioCtx()
{
  return sslCtx().ioCtx();
}

io::SSLContext &
ConnectContext::sslCtx()
{
  return _sslCtx;
}

boost::optional<Peer&> 
ConnectContext::findPeerByName(const std::string &nickname)
{
  return _peerDb.findByNickname(nickname);
}

boost::optional<Peer&> 
ConnectContext::findPeerByCert(CERTCertificate *cert)
{
  auto pubKey = to_unique(CERT_ExtractPublicKey(cert));
  return _peerDb.findByKey(pubKey.get());
}

void 
ConnectContext::handshakePeer(io::SSLSocket &socket,
                              boost::optional<Peer&> knownPeer,
                              handshake_peer_callback cb)
{
  /* Trick to pass the authenticated peer to the handshake done callback */
  std::shared_ptr<boost::optional<Peer&>>
    peerRef(new boost::optional<Peer&>());
  
  socket.handshake(
    /* Handshake done */
    [this, peerRef, cb(std::move(cb))]
    (boost::system::error_code ec)
  {
    if (!ec && *peerRef)
      cb(peerConnection(**peerRef));
    else
      cb(ec);
  },
    /* Authenticate peer */
    [this, peerRef, knownPeer]
    (CERTCertificate *cert)
  {
    auto peer = findPeerByCert(cert);
    if (peer && (!knownPeer || &*knownPeer == &*peer)) {
      *peerRef = peer;
      return true;
    }
    return false;
  });
}

void
ConnectContext::connectPeerDirect(Peer &peer, PRNetAddr *addr,
  handshake_peer_callback cb)
{
  std::shared_ptr<io::SSLSocket> socket = _sslCtx.openClientSocket();
  socket->connect(addr,
    [this, &peer, socket, cb(std::move(cb))]
  (boost::system::error_code ec)
  {
    if (ec) {
      cb(ec);
    }
    else {
      handshakePeer(*socket, peer, std::move(cb));
    }
  });
}

void
ConnectContext::connectPeerTor(Peer &peer, handshake_peer_callback cb)
{
  std::shared_ptr<io::SSLSocket> socket = _sslCtx.openClientSocket();
  connectTor(*socket, *_torOutgoingPort, *peer.onionAddress(), *peer.onionPort(),
    [this, &peer, socket, cb(std::move(cb))]
    (std::string connectedAddress, boost::system::error_code ec)
  {
    if (ec) {
      std::cerr << ec.message() << " while connecting to " << connectedAddress << std::endl;
      cb(ec);
    } else {
      std::cerr << "Connected to " << connectedAddress << std::endl;
      handshakePeer(*socket, peer, std::move(cb));
    }
  });

/*
  PRNetAddr addr;
  if (PR_InitializeNetAddr(PR_IpAddrLoopback, *_torOutgoingPort, &addr)
      != PR_SUCCESS)
    throw new std::runtime_error("PR_InitializeNetAddr failed");

  socket->connect(&addr,
    [this, &peer, socket, cb(std::move(cb))]
    (boost::system::error_code ec)
  {
    if (ec) {
      cb(ec);
    } else {
      
      handshakeSOCKS5(*socket, *peer.onionAddress(), *peer.onionPort()
    }
  });*/
}

void 
ConnectContext::incomingDirectConnection(std::shared_ptr<io::SSLSocket> socket)
{
  std::cerr << "New direct connection!" << std::endl;
  
  handshakePeer(*socket, boost::none,
    [socket]
    (boost::variant<PeerConnection&, boost::system::error_code> v)
  {
    if (v.which() == 0) {
      auto peerConn = boost::get<PeerConnection&>(v);
      
      peerConn.directConnection(std::move(socket));
    
    } else {
      /* Handshake error, we cannot accept this connection */
      
      auto ec = boost::get<boost::system::error_code>(v);
      std::cerr << "Handshake error : " << ec.message() <<std::endl;
    }
  });
}
  
void 
ConnectContext::incomingTorConnection(std::shared_ptr<io::SSLSocket> socket)
{
  std::cerr << "New Tor connection!" << std::endl;
  
  handshakePeer(*socket, boost::none,
    [socket]
    (boost::variant<PeerConnection&, boost::system::error_code> v)
  {
    if (v.which() == 0) {
      auto peerConn = boost::get<PeerConnection&>(v);
      
      peerConn.torConnection(socket);
    
    } else {
      /* Handshake error, we cannot accept this connection */
      
      auto ec = boost::get<boost::system::error_code>(v);
      std::cerr << "Handshake error : " << ec.message() <<std::endl;
      return;
    }
  });
  
  // sock.handshake(
    // /* Handshake done */
    // [=, &sock](boost::system::error_code ec)
  // {
    // if (ec) {
      // /* Handshake error, we cannot accept this connection */
      // std::cerr << "Handshake error : " << ec.message() << std::endl;
      // return;
    // }
    // auto sessionId = to_unique(SSL_GetSessionID(sock.fileDesc()));
    // std::cerr << "Session ID = " << to_hex(sessionId.get()) << std::endl;

    // onSession(makeInsertSession<ServerSession>(sock));
  // },
    // /* Authenticate Tor connected peer */
    // [=, &sock](CERTCertificate *cert)
  // {
    // return true;
  // });
}

void 
ConnectContext::serveDirect(std::uint16_t listenDirectPort)
{
  /* Serve the direct connection port */
  {
    using namespace std::placeholders;
    sslCtx().serve(listenDirectPort,
      std::bind(&ConnectContext::incomingDirectConnection, this, _1));
  }
}

void
ConnectContext::startServeTor(std::uint16_t torIncomingPort,
                              std::uint16_t torOutgoingPort,
                              std::uint16_t controlPort,
                              std::string executableName,
                              std::string workingDir)              
{
  /* Serve the Tor connection port */
  {
    using namespace std::placeholders;
    sslCtx().serve(torIncomingPort,
      std::bind(&ConnectContext::incomingTorConnection, this, _1));
  }

  /* Start Tor */
  {
    _torCtrl = std::make_shared<tor::TorController>(sslCtx(), executableName, workingDir);
    _torHiddenService
      = _torCtrl->addHiddenService(torIncomingPort, "mist-service");
    _torCtrl->start(torOutgoingPort, controlPort);
  }

  _torOutgoingPort = torOutgoingPort;
}

void
ConnectContext::externalTor(std::uint16_t torOutgoingPort)
{
  _torOutgoingPort = torOutgoingPort;
}

void
ConnectContext::onionAddress(std::function<void(const std::string&)> cb)
{
  _torHiddenService->onionAddress(std::move(cb));
}

/* Returns the existing connection for the peer, or creates a new one */
PeerConnection &
ConnectContext::peerConnection(Peer &peer)
{
  auto it = _peerConnections.find(&peer);
  
  if (it != _peerConnections.end()) {
    return *it->second;
  } else {
    auto connection = std::make_unique<PeerConnection>(*this, peer);
    auto rv = _peerConnections.insert(std::make_pair(&peer, std::move(connection)));
    return *(rv.first->second);
  }
}

void
ConnectContext::setOnPeerConnection(peer_connection_callback peerCb)
{
  _connectionCb = std::move(peerCb);
}

void
ConnectContext::setOnSession(h2::server_session_callback sessionCb)
{
  _sessionCb = std::move(sessionCb);
}
  
void 
ConnectContext::onSession(h2::ServerSession &session)
{
  if (_sessionCb)
    _sessionCb(session);
}

void 
ConnectContext::exec()
{
  ioCtx().exec();
}

} // namespace mist

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
    ctx.serveDirect(
      isServer ? 8250 : 7383); // Direct incoming port
    ctx.startServeTor(
      isServer ? 8148 : 7380, // Tor incoming port
      isServer ? 8158 : 7381, // Tor outgoing port
      isServer ? 8190 : 7382, // Control port
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
      peer.setOnionAddress(addr);
      peer.setOnionPort(443);
    });
    ctx.setOnSession(
      [=](mist::h2::ServerSession &session)
    {
      std::cerr << "Server onSession" << std::endl;
      session.setOnRequest(
        [=, &session](mist::h2::ServerRequest &request)
      {
        request.stream().setOnClose(
          [](boost::system::error_code ec)
        {
          std::cerr << "Server stream closed! " << ec.message() << std::endl;
        });
        std::cerr << "New request!" << std::endl;
        
        mist::h2::header_map headers
        {
          {"accept", {"*/*", false}},
          {"accept-encoding", {"gzip, deflate", false}},
          {"user-agent", {"nghttp2/" NGHTTP2_VERSION, false}},
        };
        request.stream().submit(404, std::move(headers),
          make_generator("Hej!!"));
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
      //if (PR_InitializeNetAddr(PR_IpAddrLoopback, 9150, &addr) != PR_SUCCESS)
      //  throw new std::runtime_error("PR_InitializeNetAddr failed");
    
      //mist::Socket &sock = sslCtx.openClientSocket();
      
      ioCtx.setTimeout(20000,
        [&ctx]()
      {
        std::cerr << "Trying to connect..." << std::endl;
        mist::Peer &peer = *ctx.findPeerByName("myself");
        ctx.connectPeerTor(peer,
          [&ctx](boost::variant<mist::PeerConnection&, boost::system::error_code> result)
        {
          if (result.which() == 0) {
            auto peerConn = boost::get<mist::PeerConnection&>(result);
            std::cerr << "Connection successful!" << std::endl;
            // session.setOnError(
            // [&session](boost::system::error_code ec)
            // {
            // std::cerr << "Session error!!" << ec.message() << std::endl;
            // });

            // boost::system::error_code ec;
            // mist::h2::header_map headers
            // {
            // {"accept", {"*/*", false}},
            // {"accept-encoding", {"gzip, deflate", false}},
            // {"user-agent", {"nghttp2/" NGHTTP2_VERSION, false}},
            // };
            // auto req = session.submit(ec, "GET", "/", "https", "www.hej.os",
            // headers);
            // if (ec)
            // std::cerr << ec.message() << std::endl;
            // if (!req) {
            // std::cerr << "Could not submit" << std::endl;
            // return;
            // }
            // std::cerr << "Submitted" << std::endl;

            // mist::h2::ClientRequest &request = req.get();

            // request.stream().setOnClose(
            // [](boost::system::error_code ec)
            // {
            // std::cerr << "Client stream closed! " << ec.message() << std::endl;
            // });

            // request.setOnResponse(
            // [&request, &session]
            // (mist::h2::ClientResponse &response)
            // {
            // std::cerr << "Got response!" << std::endl;

            // response.setOnData(
            // [&response, &session]
            // (const std::uint8_t *data, std::size_t length)
            // {
            // for (auto &kv : response.headers()) {
            // std::cerr << kv.first << ", " << kv.second.first << std::endl;
            // }
            // std::cerr << "Got data of length " << length << std::endl;
            // std::cerr << std::string(reinterpret_cast<const char*>(data), length) << std::endl;
            // });
            // });
          }
          else {
            auto ec = boost::get<boost::system::error_code>(result);
            std::cerr << "Error when connecting " << ec.message() << std::endl;
          }
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
  //} catch(boost::exception &) {
  //  std::cerr
  //    << "Unexpected exception, diagnostic information follows:" << std::endl
  //    << boost::current_exception_diagnostic_information();
  //}
}
