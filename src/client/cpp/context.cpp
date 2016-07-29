#include <algorithm>
#include <cassert>
#include <cstddef>
#include <iostream>
#include <string>
#include <memory>
#include <vector>
#include <list>

/* NSPR Headers */
#include <nspr.h>
#include <prthread.h>
//#include <plgetopt.h>
#include <prerror.h>
#include <prinit.h>
//#include <prlog.h>
#include <prtypes.h>
#include <plstr.h>
#include <prio.h>
#include <prnetdb.h>
#include <prinrval.h>

/* NSS headers */
#include <keyhi.h>
#include <pk11priv.h>
#include <pk11pub.h>
#include <pkcs11t.h>

#include <base64.h>

#include <nss.h>

#include <ssl.h>
#include <sslerr.h>
#include <sslproto.h>

#include <secerr.h>
#include <sechash.h>
#include <secitem.h>
#include <secmod.h>
#include <secmodt.h>
#include <secoid.h>
#include <secport.h>

#include <certdb.h>
#include <cert.h>
#include <certt.h>

#include <secasn1.h>

#include <nghttp2/nghttp2.h>

#include <boost/optional.hpp>
#include <boost/system/error_code.hpp>
#include <boost/system/system_error.hpp>
#include <boost/throw_exception.hpp>

#include "error/mist.hpp"
#include "error/nss.hpp"
#include "memory/nss.hpp"

#include "socket.hpp"
#include "context.hpp"

namespace mist
{

namespace
{

std::string to_hex(std::uint8_t byte)
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
    text += to_hex(std::uint8_t(*(begin++)));
  return text;
}

std::string to_hex(SECItem *item)
{
  return to_hex(static_cast<std::uint8_t *>(item->data),
                static_cast<std::uint8_t *>(item->data + item->len));
}

std::string to_hex(std::string str)
{
  return to_hex(static_cast<const std::uint8_t *>(str.data()),
                static_cast<const std::uint8_t *>(str.data() + str.size()));
}

std::string
hash(const std::uint8_t *begin, const std::uint8_t *end,
     SECOidTag hashOIDTag = SEC_OID_SHA256)
{
  std::array<std::uint8_t, 64> digest;
  unsigned int len;
  
  HASH_HashType hashType = HASH_GetHashTypeByOidTag(hashOIDTag);
  
  auto ctx = to_unique(HASH_Create(hashType));
  HASH_Begin(ctx.get());
  HASH_Update(ctx.get(), static_cast<const unsigned char *>(begin), end - begin);
  HASH_End(ctx.get(), static_cast<unsigned char *>(digest.data()), &len, digest.size());
  
  return std::string(static_cast<const char *>(digest.data()), len);
}

std::string certPubKeyHash(CERTCertificate *cert)
{
  auto pubKey = to_unique(CERT_ExtractPublicKey(cert));
  auto derPubKey = to_unique(SECKEY_EncodeDERSubjectPublicKeyInfo(pubKey.get()));
  return hash(derPubKey->data, derPubKey->data + derPubKey->len);
}

}

/*
 * Rendez-vous socket
 */
RdvSocket::RdvSocket(c_unique_ptr<PRFileDesc> fd, connection_callback cb)
  : fd(std::move(fd)), cb(std::move(cb)) {}
    
/* Accepts a connection from the rendez-vous socket. */
c_unique_ptr<PRFileDesc> RdvSocket::accept()
{
  assert (fd);
  c_unique_ptr<PRFileDesc> acceptedFd =
    to_unique(PR_Accept(fd.get(), nullptr, PR_INTERVAL_NO_TIMEOUT));
  if (!acceptedFd)
    BOOST_THROW_EXCEPTION(boost::system::system_error(make_nss_error(),
      "Unable to accept incoming connection"));
  
  return std::move(acceptedFd);
}

/* Initialize NSS with the given database directory */
void
SSLContext::initializeNSS(std::string dbdir)
{
  if (NSS_InitReadWrite(dbdir.c_str()) != SECSuccess)
    BOOST_THROW_EXCEPTION(boost::system::system_error(make_nss_error(),
      "Unable to initialize NSS"));
  
  /* Set the password function to delegate to SSLContext */
  PK11_SetPasswordFunc(
    [](PK11SlotInfo *info, PRBool retry, void *arg)
    -> char *
  {
    Socket &socket = *static_cast<Socket *>(arg);
    boost::optional<std::string> password
      = socket.context().getPassword(socket, info, retry);
    if (password) {
      /* Use PL_strdup; NSS will try to free the pointer later. */
      return PL_strdup(password->c_str());
    } else {
      return nullptr;
    }
  }
}

/*
 * Upgrades the NSPR socket to an SSL socket.
 */
void SSLContext::initializeSecurity(c_unique_ptr<PRFileDesc> &fd)
{
  auto sslSock = to_unique(SSL_ImportFD(nullptr, fd.get()));
  if (!sslSock)
    BOOST_THROW_EXCEPTION(boost::system::system_error(make_nss_error(),
      "Unable to wrap SSL socket"));

  /* We no longer own the old pointer */
  fd.release();
  
  fd = std::move(sslSock);

  /* All SSL sockets need SSL_SECURITY, enable it here. For sockets created
     by accepting a rendez-vous socket, this setting will be inherited */
  if (SSL_OptionSet(fd.get(), SSL_SECURITY, PR_TRUE) != SECSuccess)
    BOOST_THROW_EXCEPTION(boost::system::system_error(make_nss_error(),
      "Unable to modify SSL_SECURITY setting"));
}

namespace
{
/* Try to get the certificate and private key with the given nickname */
std::pair<c_unique_ptr<CERTCertificate>,
          c_unique_ptr<SECKEYPrivateKey>>
getAuthData(char *nickname, void *wincx)
{
  std::cerr << "get_auth_data" << std::endl;
  if (nickname) {
    auto cert = to_unique(CERT_FindUserCertByUsage(
      CERT_GetDefaultCertDB(), nickname, certUsageSSLClient,
      PR_FALSE, wincx));
      
    if (!cert)
      return std::make_pair(to_unique<CERTCertificate>(),
                            to_unique<SECKEYPrivateKey>());
    
    auto privKey = to_unique(PK11_FindKeyByAnyCert(cert.get(), wincx));
    
    if (!privKey)
      return std::make_pair(to_unique<CERTCertificate>(),
                            to_unique<SECKEYPrivateKey>());
    
    return std::make_pair(std::move(cert), std::move(privKey));
    
  } else {
    /* No name given, automatically find the right cert. */
    auto names = to_unique(CERT_GetCertNicknames(CERT_GetDefaultCertDB(),
      SEC_CERT_NICKNAMES_USER, wincx));
      
    if (names) {
      for (std::size_t i = 0; i < names->numnicknames; ++i) {
        auto cert = to_unique(CERT_FindUserCertByUsage(
          CERT_GetDefaultCertDB(), names->nicknames[i], certUsageSSLClient,
          PR_FALSE, wincx));
        
        if (!cert)
          continue;
        
        if (CERT_CheckCertValidTimes(cert.get(), PR_Now(), PR_TRUE) !=
            secCertTimeValid)
          continue;
        
        auto privKey = to_unique(PK11_FindKeyByAnyCert(cert.get(), wincx));
        
        if (!privKey)
          continue;
    
        return std::make_pair(std::move(cert), std::move(privKey));
      }
    }
  }
  
  return std::make_pair(to_unique<CERTCertificate>(),
                        to_unique<SECKEYPrivateKey>());
}
}

/* Called when NSS wants to get the client certificate */
SECStatus
SSLContext::getClientCert(Socket &socket, CERTDistNames *caNames,
                          CERTCertificate **pRetCert, SECKEYPrivateKey **pRetKey)
{
  std::cerr << "nss_get_client_cert" << std::endl;
  auto authData = getAuthData((char *)nickname, SSL_RevealPinArg(socket.fileDesc()));
  if (!authData.first || !authData.second) {
    /* Private key or certificate was not found */
    return SECFailure;
  } else {
    *pRetCert = authData.first.release();
    *pRetKey = authData.second.release();
    return SECSuccess;
  }
}

/* Called when NSS wants to authenticate the peer certificate */
SECStatus
SSLContext::authCertificate(Socket &socket, PRBool checkSig, PRBool isServer)
{
  auto cert = to_unique(SSL_PeerCertificate(fd));
  std::string pubKeyHash = certPubKeyHash(cert.get());
  std::cerr << "Public key hash = " << to_hex(pubKeyHash) << std::endl;

  /* Check certificate time validity */
  if (CERT_CheckCertValidTimes(cert.get(), PR_Now(), PR_TRUE)
      != secCertTimeValid)
    return SECFailure;

  /* TODO: Verify against revocation list */

  /* TODO: OCSP? */
  // if(conn->data->set.ssl.verifystatus) {
    // SECStatus cacheResult;

    // const SECItemArray *csa = SSL_PeerStapledOCSPResponses(fd);
    // if(!csa) {
      // failf(conn->data, "Invalid OCSP response");
      // return SECFailure;
    // }

    // if(csa->len == 0) {
      // failf(conn->data, "No OCSP response received");
      // return SECFailure;
    // }

    // cacheResult = CERT_CacheOCSPResponseFromSideChannel(
      // CERT_GetDefaultCertDB(), SSL_PeerCertificate(fd),
      // PR_Now(), &csa->items[0], arg
    // );

    // if(cacheResult != SECSuccess) {
      // failf(conn->data, "Invalid OCSP response");
      // return cacheResult;
    // }
  // }
  
  /* TODO: Verify that we actually know this private key */

  return SECSuccess;
}

/* Called when NSS wants us to supply a password */
boost::optional<std::string>
SSLContext::getPassword(Socket &socket, PK11SlotInfo *info, PRBool retry)
{
  /* Use PL_strdup; NSS will try to free the pointer later. */
  std::cerr << "password func" << std::endl;
  if (!retry)
    return "mist";
  else
    return boost::none;
}

/* Initialize the SSL socket with mist TLS settings */
void SSLContext::initializeTLS(Socket &sock)
{
  PRFileDesc *sslfd = sock.fileDesc();

  /* Set the PK11 user data to the socket pointer */
  if (SSL_SetPKCS11PinArg(sslfd, &sock) != SECSuccess)
    BOOST_THROW_EXCEPTION(boost::system::system_error(make_nss_error(),
      "Unable to set PKCS11 Pin Arg"));
  
  /* Server requests certificate from client */
  if (SSL_OptionSet(sslfd, SSL_REQUEST_CERTIFICATE, PR_TRUE) != SECSuccess)
    BOOST_THROW_EXCEPTION(boost::system::system_error(make_nss_error(),
      "Unable to modify SSL_REQUEST_CERTIFICATE option"));
      
  /* Require certificate */
  if (SSL_OptionSet(sslfd, SSL_REQUIRE_CERTIFICATE , PR_TRUE) != SECSuccess)
    BOOST_THROW_EXCEPTION(boost::system::system_error(make_nss_error(),
      "Unable to modify SSL_REQUIRE_CERTIFICATE option"));
  
  /* Disable SSLv2 */
  if (SSL_OptionSet(sslfd, SSL_ENABLE_SSL2, PR_FALSE) != SECSuccess)
    BOOST_THROW_EXCEPTION(boost::system::system_error(make_nss_error(),
      "Unable to modify SSL_ENABLE_SSL2 option"));
      
  /* Disable SSLv3 */
  if (SSL_OptionSet(sslfd, SSL_ENABLE_SSL3, PR_FALSE) != SECSuccess)
    BOOST_THROW_EXCEPTION(boost::system::system_error(make_nss_error(),
      "Unable to modify SSL_ENABLE_SSL3 option"));
      
  /* Enable TLS */
  if (SSL_OptionSet(sslfd, SSL_ENABLE_TLS, PR_TRUE) != SECSuccess)
    BOOST_THROW_EXCEPTION(boost::system::system_error(make_nss_error(),
      "Unable to modify SSL_ENABLE_TLS option"));

  /* TODO: Require latest TLS version */
  {
    SSLVersionRange sslverrange = {
      SSL_LIBRARY_VERSION_TLS_1_2, SSL_LIBRARY_VERSION_TLS_1_2
    };
    if (SSL_VersionRangeSet(sslfd, &sslverrange) != SECSuccess)
      BOOST_THROW_EXCEPTION(boost::system::system_error(make_nss_error(),
        "Unable to set SSL version"));
  }
  
  /* Disable session cache */
  if (SSL_OptionSet(sslfd, SSL_NO_CACHE, PR_TRUE) != SECSuccess)
    BOOST_THROW_EXCEPTION(boost::system::system_error(make_nss_error(),
      "Unable to modify SSL_NO_CACHE option"));
  
  /* Enable ALPN */
  if (SSL_OptionSet(sslfd, SSL_ENABLE_NPN, PR_TRUE) != SECSuccess)
    BOOST_THROW_EXCEPTION(boost::system::system_error(make_nss_error(),
      "Unable to modify SSL_ENABLE_NPN option"));
      
  /* Disable NPN */
  if (SSL_OptionSet(sslfd, SSL_ENABLE_ALPN, PR_TRUE) != SECSuccess)
    BOOST_THROW_EXCEPTION(boost::system::system_error(make_nss_error(),
      "Unable to modify SSL_ENABLE_ALPN option"));

  /* Set the only supported protocol to HTTP/2 */
  {
    std::vector<unsigned char> protocols(1 + NGHTTP2_PROTO_VERSION_ID_LEN);

    auto it = protocols.begin();
    *(it++) = (unsigned char)NGHTTP2_PROTO_VERSION_ID_LEN;
    it = std::copy((unsigned char *)NGHTTP2_PROTO_VERSION_ID,
      (unsigned char *)(NGHTTP2_PROTO_VERSION_ID
                      + NGHTTP2_PROTO_VERSION_ID_LEN), it);
    assert (it == protocols.end());

    if (SSL_SetNextProtoNego(sslfd, protocols.data(), protocols.size()) != SECSuccess)
      BOOST_THROW_EXCEPTION(boost::system::system_error(make_nss_error(),
        "Unable to set protocol negotiation"));
  }
  
  /* Client certificate and key callback */
  {
    auto rv = SSL_AuthCertificateHook(sslfd, 
    [](void *arg, PRFileDesc *fd, PRBool checkSig, PRBool isServer) -> SECStatus
    {
      Socket &socket = *static_cast<Socket *>(arg);
      return socket.context().authCertificate(socket, checkSig, isServer);
    }, &sock);
    
    if (rv != SECSuccess)
      BOOST_THROW_EXCEPTION(boost::system::system_error(make_nss_error(),
        "Unable to set AuthCertificateHook"));
  }

  /* Handshake as server */
  if (SSL_OptionSet(sslfd, SSL_HANDSHAKE_AS_SERVER, sock.server ? PR_TRUE : PR_FALSE) != SECSuccess)
    BOOST_THROW_EXCEPTION(boost::system::system_error(make_nss_error(),
      "Unable to modify SSL_HANDSHAKE_AS_SERVER option"));
      
  /* Handshake as client */
  if (SSL_OptionSet(sslfd, SSL_HANDSHAKE_AS_CLIENT, sock.server ? PR_FALSE : PR_TRUE) != SECSuccess)
    BOOST_THROW_EXCEPTION(boost::system::system_error(make_nss_error(),
      "Unable to modify SSL_HANDSHAKE_AS_CLIENT option"));

  if (!sock.server) {
    /* Set client certificate and key callback */
    auto rv = SSL_GetClientAuthDataHook(sslfd,
    [](void *arg, PRFileDesc *fd, CERTDistNames *caNames, CERTCertificate **pRetCert,
       SECKEYPrivateKey **pRetKey) -> SECStatus
    {
      Socket &socket = *static_cast<Socket *>(arg);
      return socket.context().getClientCert(socket, caNames, pRetCert, pRetKey);
    }, &sock);
    
    if (rv != SECSuccess)
      BOOST_THROW_EXCEPTION(boost::system::system_error(make_nss_error(),
        "Unable to set GetClientAuthDataHook"));
  }

  /* Reset handshake */
  /* TODO: Check if necessary */
  if(SSL_ResetHandshake(sslfd, sock.server ? PR_TRUE : PR_FALSE) != SECSuccess)
    BOOST_THROW_EXCEPTION(boost::system::system_error(make_nss_error(),
      "Unable to reset handshake"));
}

/*
 * Open a non-blocking socket.
 */
c_unique_ptr<PRFileDesc> SSLContext::openSocket()
{
  auto fd = to_unique(PR_OpenTCPSocket(PR_AF_INET));
  if (!fd)
    BOOST_THROW_EXCEPTION(boost::system::system_error(make_nss_error(),
      "Unable to open TCP socket"));

  PRSocketOptionData sockOpt;
  sockOpt.option = PR_SockOpt_Nonblocking;
  sockOpt.value.non_blocking = PR_TRUE;
  if (PR_SetSocketOption(fd.get(), &sockOpt) != PR_SUCCESS)
    BOOST_THROW_EXCEPTION(boost::system::system_error(make_nss_error(),
      "Unable to set PR_SockOpt_Nonblocking"));
  
  return std::move(fd);
}

/*
 * Opens, binds a non-blocking SSL rendez-vous socket listening to the
 * specified port.
 */
c_unique_ptr<PRFileDesc> SSLContext::openRdvSocket(uint16_t port, std::size_t backlog)
{
  auto fd = openSocket();
  
  initializeSecurity(fd);
  
  /* Note that we do not call initializeTLS here, even though we theoretically
     could, since there is an issue with inheriting protocol negotiation
     settings */

  /* Set server certificate and private key */
  auto authData = getAuthData((char *)nickname, SSL_RevealPinArg(fd.get()));
  if (!authData.first || !authData.second)
    BOOST_THROW_EXCEPTION(boost::system::system_error(make_mist_error(MIST_ERR_NO_KEY_OR_CERT),
      "Unable to find private key or certificate for rendez-vous socket"));

  if (SSL_ConfigSecureServer(fd.get(),
      authData.first.get(), authData.second.get(),
      NSS_FindCertKEAType(authData.first.get())) != SECSuccess)
    BOOST_THROW_EXCEPTION(boost::system::system_error(make_nss_error(),
      "Unable to set server certificate and key for rendez-vous socket"));

  /* Initialize addr to localhost:port */
  PRNetAddr addr;
  if (PR_InitializeNetAddr(PR_IpAddrLoopback, port, &addr) != PR_SUCCESS)
    BOOST_THROW_EXCEPTION(boost::system::system_error(make_nss_error(),
      "Unable to initialize address for rendez-vous socket"));

  if (PR_Bind(fd.get(), &addr) != PR_SUCCESS)
    BOOST_THROW_EXCEPTION(boost::system::system_error(make_nss_error(),
      "Unable to bind rendez-vous socket to port " + std::to_string(port)));

  if (PR_Listen(fd.get(), backlog) != PR_SUCCESS)
    BOOST_THROW_EXCEPTION(boost::system::system_error(make_nss_error(),
      "Unable to start listening to rendez-vous socket"));

  return std::move(fd);
}

/*
 * Accepts a connection from the rendez-vous socket.
 */
void SSLContext::accept(RdvSocket &rdvSock)
{
  sslSocks.emplace_back(rdvSock.accept(), true, *this);
  Socket &sock = *(--sslSocks.end());
  rdvSock.cb(sock);
}

/*
 * Forces the eventLoop to wake up.
 */
void SSLContext::signal()
{
  if (PR_SetPollableEvent(signalEvent.get()) != PR_SUCCESS)
    BOOST_THROW_EXCEPTION(boost::system::system_error(make_nss_error(),
      "Unable to signal write"));
}

/*
 * Main event loop.
 */
void SSLContext::eventLoop()
{
  while (1) {
    std::vector<PRPollDesc> pds;
    
    /* Add the write event */
    pds.push_back(PRPollDesc{signalEvent.get(), PR_POLL_READ});
    
    /* Add the rendez-vous sockets */
    for (auto i = rdvSocks.begin(); i != rdvSocks.end(); ++i) {
      pds.push_back(PRPollDesc{i->fd.get(), PR_POLL_READ|PR_POLL_EXCEPT, 0});
    }
    
    /* Add the SSL sockets */
    for (auto i = sslSocks.begin(); i != sslSocks.end(); ) {
      switch (i->state) {
      case Socket::State::Handshaking:
      {
        std::cerr << "Socket handshaking poll" << std::endl;
        PRInt16 in_flags = PR_POLL_READ;
        pds.push_back(PRPollDesc{i->fileDesc(), in_flags, 0});
        break;
      }
      case Socket::State::Connecting:
      {
        std::cerr << "Socket connect poll" << std::endl;
        PRInt16 in_flags = PR_POLL_WRITE|PR_POLL_EXCEPT;
        pds.push_back(PRPollDesc{i->fileDesc(), in_flags, 0});
        break;
      }
      case Socket::State::Connected:
      case Socket::State::Open:
      {
        PRInt16 in_flags
          = (i->isReading() ? PR_POLL_READ : 0)   // 1
          | (i->isWriting() ? PR_POLL_WRITE : 0); // 2
        std::cerr << "Socket polling with flags " << in_flags << std::endl;
        pds.push_back(PRPollDesc{i->fileDesc(), in_flags, 0});
        break;
      }
      case Socket::State::Closed:
        /* Remove the closed connection */
        std::cerr << "Erased one socket" << std::endl;
        i = sslSocks.erase(i);
        continue;
      }
      ++i;
    }
    
    PRInt32 n = PR_Poll(pds.data(), pds.size(),
      PR_MillisecondsToInterval(10000));
    if (n == -1)
      throw new std::runtime_error("Poll failed");
    if (!n) {
      std::cerr << "Timeout" << std::endl;
      /* Timeout */
      continue;
    }

    auto j = pds.begin();
    
    if (j->out_flags & PR_POLL_READ) {
      std::cerr << "signalEvent!" << std::endl;
      if (PR_WaitForPollableEvent(signalEvent.get()) != PR_SUCCESS)
        BOOST_THROW_EXCEPTION(boost::system::system_error(make_nss_error(),
          "Unable to wait for signalEvent"));
    }
    ++j;
    
    for (auto i = rdvSocks.begin(); i != rdvSocks.end(); ++i, ++j) {
      /* Handle the rendez-vous sockets */
      PRInt16 out_flags = j->out_flags;
      if (out_flags & PR_POLL_READ) {
        std::cerr << "Rdv socket PR_POLL_READ" << std::endl;
        accept(*i);
      }
      if (out_flags & PR_POLL_EXCEPT) {
        std::cerr << "Rdv socket PR_POLL_EXCEPT" << std::endl;
      }
    }
    
    /* Handle the SSL sockets */
    for (auto i = sslSocks.begin(); j != pds.end(); ++i, ++j) {
      PRInt16 out_flags = j->out_flags;
      if (out_flags & PR_POLL_ERR) {
        /* Get the error code by performing a bogus read, expected to fail */
        boost::system::error_code ec;
        if (PR_Read(i->fileDesc(), nullptr, 0) != PR_SUCCESS)
          ec = make_nss_error();
        else
          ec = make_nss_error(PR_UNKNOWN_ERROR);
        i->close(ec);
      } else if (out_flags & PR_POLL_NVAL) {
        /* Invalid file descriptor */
        i->close(make_nss_error(PR_BAD_DESCRIPTOR_ERROR));
      } else if (out_flags) {
        switch (i->state) {
        case Socket::State::Handshaking:
          assert (out_flags & PR_POLL_READ);
          std::cerr << "Socket handshaking PR_POLL_READ" << std::endl;
          i->_handshake();
          break;
        case Socket::State::Connecting:
          std::cerr << "Socket Connecting" << std::endl;
          i->_connectContinue(out_flags);
          break;
        case Socket::State::Connected:
        case Socket::State::Open:
          if (out_flags & PR_POLL_WRITE) {
            std::cerr << "Socket Open PR_POLL_WRITE" << std::endl;
            i->_write();
          }
          if (out_flags & PR_POLL_READ) {
            std::cerr << "Socket Open PR_POLL_READ" << std::endl;
            i->_read();
          }
          break;
        }
      }
    }
  }
}

SSLContext::SSLContext(const char *nickname)
  : nickname(nickname), signalEvent(to_unique<PRFileDesc>())
{
  initializeNSS("db");
  
  signalEvent = to_unique(PR_NewPollableEvent(), [](PRFileDesc *p) {
    PR_DestroyPollableEvent(p);
  });
}

void SSLContext::serve(uint16_t servPort, connection_callback cb)
{
  rdvSocks.emplace_back(openRdvSocket(servPort), std::move(cb));
}

void SSLContext::exec()
{
  eventLoop();
}

Socket &SSLContext::openClientSocket()
{
  sslSocks.emplace_back(openSocket(), false, *this);
  return *(--sslSocks.end());
}

}
