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

void
Peer::connection(std::shared_ptr<io::SSLSocket> socket,
  ConnectionType connType, ConnectionDirection connDirection)
{
  if (_socket) {
    /* TODO: Migrate to the new socket, if we accept this migration */
    std::cerr << "New connection to peer when already connected" << std::endl;
  }

  _socket = socket;
  if (connType == Server) {
    /* TODO */
    assert(!_serverSession);
    using namespace std::placeholders;
    _serverSession = std::make_unique<h2::ServerSession>(socket);
    _serverSession->setOnRequest(std::bind(&Peer::onRequest, this, _1));
  } else {
    /* TODO */
    assert(!_clientSession);
    _clientSession = std::make_unique<h2::ClientSession>(socket);
  }
}

void
Peer::onRequest(h2::ServerRequest &request)
{
  auto headers = request.headers();
  auto path = headers.find(":path");
  if (path != headers.end()) {
    std::cerr << "Got request for path: " << path->second.first << std::endl;
  }
}

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

const Peer::address_list&
Peer::addresses() const
{
  return _addresses;
}

void
Peer::addAddress(TorAddress address)
{
  _addresses.push_back(std::move(address));
}

h2::ClientRequest& Peer::submit(std::string method,
  std::string path, std::string scheme, std::string authority,
  h2::header_map headers, h2::generator_callback cb)
{
  assert(_clientSession);
  auto& request = _clientSession->submit(std::move(method), std::move(path),
    std::move(scheme), std::move(authority), std::move(headers),
    std::move(cb));
  /* TODO: Catch NGHTTP2 NGHTTP2_ERR_STREAM_ID_NOT_AVAILABLE and
  create a new connection */
  return request;
}

/*
 * PeerDb
 */
namespace
{
std::string
nicknameFromFilename(const std::string &filename)
{
  std::size_t pos = filename.find_last_of('.');
  if (pos == std::string::npos)
    return filename;
  return std::string(filename.data(), filename.data() + pos);
}
} // namespace

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
 * ConnectContext
 */

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

void
ConnectContext::addDirectory(std::string directory)
{
  _directories.push_back(directory);
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
  std::shared_ptr<boost::optional<Peer&>> peerRef
    = std::make_shared<boost::optional<Peer&>>(boost::none);
  
  socket.handshake(
    /* Handshake done */
    [this, peerRef, cb(std::move(cb))]
    (boost::system::error_code ec)
  {
    if (!ec && *peerRef)
      cb(**peerRef, boost::system::error_code());
    else
      cb(boost::none, ec);
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
ConnectContext::connectPeerDirect(Peer &peer, PRNetAddr *addr)
{
  std::shared_ptr<io::SSLSocket> socket = _sslCtx.openSocket();
  socket->connect(addr,
    [this, &peer, socket]
    (boost::system::error_code ec)
  {
    if (ec) {
      std::cerr << ec.message() << " while connecting to peer directly"
        << std::endl;
    } else {
      std::cerr << "Connected to peer directly" << std::endl;
      handshakePeer(*socket, peer,
        [=, &peer]
        (boost::optional<Peer&>, boost::system::error_code ec)
      {
        if (!ec) {
          peer.connection(std::move(socket), Peer::Direct, Peer::Client);
        } else {
          /* Handshake failed */
        }
      });
    }
  });
}

void
ConnectContext::tryConnectPeerTor(Peer &peer,
  Peer::address_list::const_iterator it)
{
  if (it != peer.addresses().end()) {
    const TorAddress &address = *it;

    std::shared_ptr<io::SSLSocket> socket = _sslCtx.openSocket();
    _torCtrl->connect(*socket, address.hostname, address.port,
      [=, &peer]
      (boost::system::error_code ec)
    {
      if (!ec) {
        std::cerr << "Connected to peer via tor" << std::endl;
        handshakePeer(*socket, peer,
          [=, &peer]
          (boost::optional<Peer&>, boost::system::error_code ec)
        {
          if (!ec) {
            peer.connection(std::move(socket), Peer::Tor, Peer::Client);
          } else {
            /* Handshake failed, try the next address */
            tryConnectPeerTor(peer, std::next(it));
          }
        });
      } else {
        /* Connection failed, try the next address */
        tryConnectPeerTor(peer, std::next(it));
      }
    });
  } else {
    /* All addresses tried, fail */
    std::cerr << "Unable to connect" << std::endl;
  }
}

void
ConnectContext::connectPeerTor(Peer &peer)
{
  tryConnectPeerTor(peer, peer.addresses().begin());
}

void
ConnectContext::incomingDirectConnection(std::shared_ptr<io::SSLSocket> socket)
{
  std::cerr << "New direct connection!" << std::endl;
  
  handshakePeer(*socket, boost::none,
    [socket]
    (boost::optional<Peer&> peer, boost::system::error_code ec)
  {
    if (!ec) {
      peer->connection(std::move(socket), Peer::Direct, Peer::Server);
    } else {
      /* Handshake error, we cannot accept this connection */
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
    (boost::optional<Peer&> peer, boost::system::error_code ec)
  {
    if (!ec) {
      peer->connection(socket, Peer::Tor, Peer::Server);
    } else {
      /* Handshake error, we cannot accept this connection */
      std::cerr << "Handshake error : " << ec.message() <<std::endl;
      return;
    }
  });
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
  std::uint16_t torOutgoingPort, std::uint16_t controlPort,
  std::string executableName, std::string workingDir)              
{
  /* Serve the Tor connection port */
  {
    using namespace std::placeholders;
    sslCtx().serve(torIncomingPort,
      std::bind(&ConnectContext::incomingTorConnection, this, _1));
  }

  /* Start Tor */
  {
    _torCtrl = std::make_shared<tor::TorController>(ioCtx(), executableName, workingDir);
    _torHiddenService
      = _torCtrl->addHiddenService(torIncomingPort, "mist-service");
    _torCtrl->start(torOutgoingPort, controlPort);
  }
}

void
ConnectContext::onionAddress(std::function<void(const std::string&)> cb)
{
  _torHiddenService->onionAddress(std::move(cb));
}

void 
ConnectContext::exec()
{
  ioCtx().exec();
}

} // namespace mist
