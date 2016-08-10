#include <cstddef>
#include <functional>
#include <iostream>

#include <boost/exception/diagnostic_information.hpp> 
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

#include "context.hpp"
#include "socket.hpp"
#include "conn.hpp"

#include "tor/tor.hpp"

#include "h2/session.hpp"
#include "h2/stream.hpp"
#include "h2/client_request.hpp"
#include "h2/client_response.hpp"
#include "h2/server_request.hpp"
#include "h2/server_response.hpp"

#include <sechash.h>
#include <secitem.h>
//#include <secmod.h>
//#include <secmodt.h>
//#include <secoid.h>
//#include <secport.h>

//#include <certdb.h>
//#include <cert.h>
//#include <certt.h>

//#include <keyhi.h>
//#include <pk11priv.h>
#include <pk11func.h>
#include <pk11pub.h>
//#include <secutil.h>
//#include <pkcs11t.h>

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
PeerConnection::torConnection(Socket &socket)
{
}
  
void
PeerConnection::directConnection(Socket &socket)
{
  auto sessionId = to_unique(SSL_GetSessionID(socket.fileDesc()));
  std::cerr << "Session ID = " << to_hex(sessionId.get()) << std::endl;
  if (_state != State::DirectConnecting) {
    /* We do not expect a direct connection here... */
  }
  auto session = std::make_unique<h2::ServerSession>(socket);
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
ConnectContext::ConnectContext(std::string dbdir,
                               std::string nickname,
                               std::string peerdir)
  : sslCtx(std::move(dbdir), std::move(nickname)),
    peerDb(std::move(peerdir))
{
}

boost::optional<Peer&> 
ConnectContext::findPeerByName(const std::string &nickname)
{
  return peerDb.findByNickname(nickname);
}

boost::optional<Peer&> 
ConnectContext::findPeerByCert(CERTCertificate *cert)
{
  auto pubKey = to_unique(CERT_ExtractPublicKey(cert));
  return peerDb.findByKey(pubKey.get());
}

void 
ConnectContext::handshakePeer(Socket &sock,
                              boost::optional<Peer&> knownPeer,
                              handshake_peer_callback cb)
{
  /* Trick to pass the authenticated peer to the handshake done callback */
  std::shared_ptr<boost::optional<Peer&>>
    peerRef(new boost::optional<Peer&>());
  
  sock.handshake(
    /* Handshake done */
    [=](boost::system::error_code ec)
  {
    if (!ec && *peerRef)
      cb(peerConnection(**peerRef));
    else
      cb(ec);
  },
    /* Authenticate peer */
    [=](CERTCertificate *cert) -> bool
  {
    auto peer = findPeerByCert(cert);
    if (!knownPeer || &*knownPeer == &*peer) {
      *peerRef = peer;
      return true;
    }
    return false;
  });
}

void 
ConnectContext::connectPeer(Peer &peer, PRNetAddr *addr,
                            handshake_peer_callback cb)
{
  Socket &sock = sslCtx.openClientSocket();
  sock.connect(addr,
    [this, &peer, &sock, cb(std::move(cb))](boost::system::error_code ec)
  {
    if (ec) {
      cb(ec);
    } else {
      handshakePeer(sock, peer, std::move(cb));
    }
  });
}

void 
ConnectContext::incomingDirectConnection(Socket &sock)
{
  std::cerr << "New direct connection!" << std::endl;
  
  handshakePeer(sock, boost::none,
    [&sock](boost::variant<PeerConnection&, boost::system::error_code> v)
  {
    if (v.which() == 0) {
      auto peerConn = boost::get<PeerConnection&>(v);
      
      peerConn.directConnection(sock);
    
    } else {
      /* Handshake error, we cannot accept this connection */
      
      auto ec = boost::get<boost::system::error_code>(v);
      std::cerr << "Handshake error : " << ec.message() <<std::endl;
      return;
    }
  });
}
  
void 
ConnectContext::incomingTorConnection(Socket &sock)
{
  std::cerr << "New Tor connection!" << std::endl;
  
  handshakePeer(sock, boost::none,
    [&sock](boost::variant<PeerConnection&, boost::system::error_code> v)
  {
    if (v.which() == 0) {
      auto peerConn = boost::get<PeerConnection&>(v);
      
      peerConn.torConnection(sock);
    
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
    sslCtx.serve(listenDirectPort,
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
    sslCtx.serve(torIncomingPort,
      std::bind(&ConnectContext::incomingTorConnection, this, _1));
  }

  /* Start Tor */
  {
    boost::system::error_code ec;
    torCtrl = std::make_unique<tor::TorController>(sslCtx, executableName, workingDir);
    torCtrl->addHiddenService(torIncomingPort, "mist-service");
    torCtrl->start(ec, torOutgoingPort, controlPort);
    if (ec)
      BOOST_THROW_EXCEPTION(boost::system::system_error(ec,
        "Unable to start Tor controller"));
  }

  _torOutgoingPort = torOutgoingPort;
}
  
/* Returns the existing connection for the peer, or creates a new one */
PeerConnection &
ConnectContext::peerConnection(Peer &peer)
{
  auto it = peerConnections.find(&peer);
  
  if (it != peerConnections.end()) {
    return *it->second;
  } else {
    auto connection = std::make_unique<PeerConnection>(*this, peer);
    auto rv = peerConnections.insert(std::make_pair(&peer, std::move(connection)));
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
  sslCtx.exec();
}

}

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
}

int
main(int argc, char **argv)
{
  //nss_init("db");
  try {
    assert(argc == 3);
    bool isServer = atoi(argv[1]);
    char *nickname = argv[2];
    
    mist::ConnectContext ctx("/home/mist/key_db",
      nickname,
      "/home/mist/peers");
    
    ctx.serveDirect(
      isServer ? 9150 : 9151); // Direct incoming port
    ctx.startServeTor(
      isServer ? 9148 : 9149, // Tor incoming port
      isServer ? 9158 : 9159, // Tor outgoing port
      isServer ? 9190 : 9191, // Control port
      "tor", "/home/mist/tordir");
    
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
      if (PR_InitializeNetAddr(PR_IpAddrLoopback, 9150, &addr) != PR_SUCCESS)
        throw new std::runtime_error("PR_InitializeNetAddr failed");
    
      //mist::Socket &sock = sslCtx.openClientSocket();
      std::cerr << "Trying to connect..." << std::endl;
      
      mist::Peer &peer = *ctx.findPeerByName("myself");
      
      ctx.connectPeer(peer, &addr,
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
        } else {
          auto ec = boost::get<boost::system::error_code>(result);
          std::cerr << "Error when connecting" << std::endl;
        }
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
