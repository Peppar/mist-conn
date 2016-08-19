#include <algorithm>
#include <cassert>
#include <cstddef>
#include <iostream>
#include <string>
#include <memory>
#include <vector>
#include <list>

#include <prtypes.h>
#include <prio.h>
#include <pk11priv.h>
#include <pk11pub.h>

#include <nss.h>
#include <ssl.h>
#include <sslproto.h>
#include <cert.h>

#include <boost/optional.hpp>
#include <boost/system/error_code.hpp>
#include <boost/system/system_error.hpp>
#include <boost/throw_exception.hpp>

#include "error/mist.hpp"
#include "error/nss.hpp"
#include "memory/nss.hpp"

#include "io/io_context.hpp"
#include "io/rdv_socket.hpp"
#include "io/ssl_socket.hpp"

namespace mist
{
namespace io
{
namespace
{

std::string
to_hex(std::uint8_t byte)
{
  static const char *digits = "0123456789abcdef";
  std::array<char, 2> text{digits[byte >> 4], digits[byte & 0xf]};
  return std::string(text.begin(), text.end());
}

template<typename It>
std::string
to_hex(It begin, It end)
{
  std::string text;
  while (begin != end)
    text += to_hex(static_cast<std::uint8_t>(*(begin++)));
  return text;
}

std::string
to_hex(SECItem *item)
{
  return to_hex(reinterpret_cast<std::uint8_t *>(item->data),
                reinterpret_cast<std::uint8_t *>(item->data + item->len));
}

std::string
to_hex(std::string str)
{
  return to_hex(reinterpret_cast<const std::uint8_t *>(str.data()),
              reinterpret_cast<const std::uint8_t *>(str.data() + str.size()));
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
  HASH_Update(ctx.get(),
    reinterpret_cast<const unsigned char *>(begin), end - begin);
  HASH_End(ctx.get(),
    reinterpret_cast<unsigned char *>(digest.data()), &len, digest.size());
  
  return std::string(reinterpret_cast<const char *>(digest.data()), len);
}

std::string
certPubKeyHash(CERTCertificate *cert)
{
  auto pubKey = to_unique(CERT_ExtractPublicKey(cert));
  auto derPubKey = to_unique(SECKEY_EncodeDERSubjectPublicKeyInfo(pubKey.get()));
  return hash(derPubKey->data, derPubKey->data + derPubKey->len);
}

} // namespace

/*
 * SSLContext
 */
SSLContext::SSLContext(IOContext &ioCtx,
                       const std::string &dbdir,
                       const std::string &nickname)
  : _ioCtx(ioCtx), _nickname(nickname)
{
  initializeNSS(dbdir);
}

IOContext &
SSLContext::ioCtx()
{
  return _ioCtx;
}

namespace
{

/* Try to get the certificate and private key with the given nickname */
std::pair<c_unique_ptr<CERTCertificate>,
          c_unique_ptr<SECKEYPrivateKey>>
getAuthData(const std::string &nickname, void *wincx)
{
  std::cerr << "get_auth_data" << std::endl;
  if (!nickname.empty()) {
    auto cert = to_unique(CERT_FindUserCertByUsage(
      CERT_GetDefaultCertDB(), const_cast<char *>(nickname.c_str()),
      certUsageSSLClient, PR_FALSE, wincx));
      
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

} // namespace

/* Opens, binds a non-blocking SSL rendez-vous socket listening to the
   specified port. */
void
SSLContext::serve(std::uint16_t servPort, connection_callback cb)
{
  const std::size_t backlog = 16;

  auto fd = openTCPSocket();
  {
    initializeSecurity(fd);
    
    /* Note that we do not call initializeTLS here, even though we theoretically
       could, since there is an issue with inheriting protocol negotiation
       settings */

    /* Set server certificate and private key */
    auto authData = getAuthData(_nickname, SSL_RevealPinArg(fd.get()));
    if (!authData.first || !authData.second)
      BOOST_THROW_EXCEPTION(boost::system::system_error(
        make_mist_error(MIST_ERR_NO_KEY_OR_CERT),
        "Unable to find private key or certificate for rendez-vous socket"));

    if (SSL_ConfigSecureServer(fd.get(),
        authData.first.get(), authData.second.get(),
        NSS_FindCertKEAType(authData.first.get())) != SECSuccess)
      BOOST_THROW_EXCEPTION(boost::system::system_error(make_nss_error(),
        "Unable to set server certificate and key for rendez-vous socket"));

    /* Initialize addr to localhost:servPort */
    PRNetAddr addr;
    if (PR_InitializeNetAddr(PR_IpAddrLoopback, servPort, &addr) != PR_SUCCESS)
      BOOST_THROW_EXCEPTION(boost::system::system_error(make_nss_error(),
        "Unable to initialize address for rendez-vous socket"));

    if (PR_Bind(fd.get(), &addr) != PR_SUCCESS)
      BOOST_THROW_EXCEPTION(boost::system::system_error(make_nss_error(),
        "Unable to bind rendez-vous socket to port " + std::to_string(servPort)));

    if (PR_Listen(fd.get(), backlog) != PR_SUCCESS)
      BOOST_THROW_EXCEPTION(boost::system::system_error(make_nss_error(),
        "Unable to start listening to rendez-vous socket"));
  }

  _ioCtx.addDescriptor(
             std::make_shared<RdvSocket>(*this, std::move(fd), std::move(cb)));
}

std::shared_ptr<SSLSocket>
SSLContext::openSocket()
{
  auto socket = std::make_shared<SSLSocket>(*this, openTCPSocket(), false);
  _ioCtx.addDescriptor(socket);
  return std::move(socket);
}

/* Initialize NSS with the given database directory */
void
SSLContext::initializeNSS(const std::string &dbdir)
{
  if (NSS_InitReadWrite(dbdir.c_str()) != SECSuccess)
    BOOST_THROW_EXCEPTION(boost::system::system_error(make_nss_error(),
      "Unable to initialize NSS"));
  
  /* Set the password function to delegate to SSLContext */
  PK11_SetPasswordFunc(
    [](PK11SlotInfo *info, PRBool retry, void *arg)
    -> char *
  {
    SSLContext &sslCtx = *static_cast<SSLContext *>(arg);
    boost::optional<std::string> password = sslCtx.getPassword(info, retry);
    if (password) {
      /* Use PL_strdup; NSS will try to free the pointer later. */
      return PL_strdup(password->c_str());
    } else {
      return nullptr;
    }
  });
}

/* Upgrades the NSPR socket file descriptor to TLS */
void
SSLContext::initializeSecurity(c_unique_ptr<PRFileDesc> &fd)
{
  auto sslSockFd = to_unique(SSL_ImportFD(nullptr, fd.get()));
  if (!sslSockFd)
    BOOST_THROW_EXCEPTION(boost::system::system_error(make_nss_error(),
      "Unable to wrap SSL socket"));

  /* We no longer own the old pointer */
  fd.release();
  
  fd = std::move(sslSockFd);

  /* All SSL sockets need SSL_SECURITY, enable it here. For sockets created
     by accepting a rendez-vous socket, this setting will be inherited */
  if (SSL_OptionSet(fd.get(), SSL_SECURITY, PR_TRUE) != SECSuccess)
    BOOST_THROW_EXCEPTION(boost::system::system_error(make_nss_error(),
      "Unable to modify SSL_SECURITY setting"));

  /* Set the PK11 user data to this ssl context */
  if (SSL_SetPKCS11PinArg(fd.get(), this) != SECSuccess)
    BOOST_THROW_EXCEPTION(boost::system::system_error(make_nss_error(),
      "Unable to set PKCS11 Pin Arg"));
}

/* Called when NSS wants to get the client certificate */
SECStatus
SSLContext::getClientCert(SSLSocket &socket, CERTDistNames *caNames,
                          CERTCertificate **pRetCert,
                          SECKEYPrivateKey **pRetKey)
{
  std::cerr << "nss_get_client_cert" << std::endl;
  auto authData = getAuthData(_nickname, SSL_RevealPinArg(socket.fileDesc()));
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
SSLContext::authCertificate(SSLSocket &socket, PRBool checkSig,
                            PRBool isServer)
{
  auto cert = to_unique(SSL_PeerCertificate(socket.fileDesc()));
  std::string pubKeyHash = certPubKeyHash(cert.get());
  std::cerr << "Public key hash = " << to_hex(pubKeyHash) << std::endl;

  /* Check certificate time validity */
  if (CERT_CheckCertValidTimes(cert.get(), PR_Now(), PR_TRUE)
      != secCertTimeValid)
    return SECFailure;
  
  /* TODO: Verify against revocation list */

  if (!socket.authenticate(cert.get()))
    return SECFailure;
  
  return SECSuccess;
}

/* Called when NSS wants us to supply a password */
boost::optional<std::string>
SSLContext::getPassword(PK11SlotInfo *info, PRBool retry)
{
  /* Use PL_strdup; NSS will try to free the pointer later. */
  std::cerr << "password func" << std::endl;
  if (!retry)
    return std::string("mist");
  else
    return boost::none;
}

namespace
{

/* Returns an nghttp2-compatible protocols string */
std::vector<unsigned char>
h2Protocol()
{
  std::vector<unsigned char> protocols;
  protocols.push_back(2);
  protocols.push_back('h');
  protocols.push_back('2');
  return std::move(protocols);
  
  // auto pData
    // = reinterpret_cast<const unsigned char *>(NGHTTP2_PROTO_VERSION_ID);
  // auto pLen = static_cast<unsigned char>(NGHTTP2_PROTO_VERSION_ID_LEN);

  // std::vector<unsigned char> protocols(1 + pLen);

  // auto it = protocols.begin();
  // *(it++) = pLen;
  // it = std::copy(pData, pData + pLen, it);
  // assert (it == protocols.end());
  
  // return std::move(protocols);
}

} // namespace

/* Initialize the SSL socket with mist TLS settings */
void
SSLContext::initializeTLS(SSLSocket &sock)
{
  PRFileDesc *sslfd = sock.fileDesc();

  /* Server requests certificate from client */
  if (SSL_OptionSet(sslfd, SSL_REQUEST_CERTIFICATE, PR_TRUE) != SECSuccess)
    BOOST_THROW_EXCEPTION(boost::system::system_error(make_nss_error(),
      "Unable to modify SSL_REQUEST_CERTIFICATE option"));
      
  /* Require certificate */
  if (SSL_OptionSet(sslfd, SSL_REQUIRE_CERTIFICATE , PR_TRUE) != SECSuccess)
    BOOST_THROW_EXCEPTION(boost::system::system_error(make_nss_error(),
      "Unable to modify SSL_REQUIRE_CERTIFICATE option"));
  
  /* Disable SSLv2 */
  /* This doesn't work in windows... why? */
  //if (SSL_OptionSet(sslfd, SSL_ENABLE_SSL2, PR_FALSE) != SECSuccess)
  //  BOOST_THROW_EXCEPTION(boost::system::system_error(make_nss_error(),
  //    "Unable to modify SSL_ENABLE_SSL2 option"));
      
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
    auto protocols = h2Protocol();
    if (SSL_SetNextProtoNego(sslfd, protocols.data(), protocols.size()) != SECSuccess)
      BOOST_THROW_EXCEPTION(boost::system::system_error(make_nss_error(),
        "Unable to set protocol negotiation"));
  }
  
  /* Client certificate and key callback */
  {
    auto rv = SSL_AuthCertificateHook(sslfd, 
    [](void *arg, PRFileDesc *fd, PRBool checkSig, PRBool isServer) -> SECStatus
    {
      SSLSocket &socket = *static_cast<SSLSocket *>(arg);
      return socket.sslCtx().authCertificate(socket, checkSig, isServer);
    }, &sock);
    
    if (rv != SECSuccess)
      BOOST_THROW_EXCEPTION(boost::system::system_error(make_nss_error(),
        "Unable to set AuthCertificateHook"));
  }

  /* Handshake as server */
  if (SSL_OptionSet(sslfd, SSL_HANDSHAKE_AS_SERVER, sock.isServer() ? PR_TRUE : PR_FALSE) != SECSuccess)
    BOOST_THROW_EXCEPTION(boost::system::system_error(make_nss_error(),
      "Unable to modify SSL_HANDSHAKE_AS_SERVER option"));
      
  /* Handshake as client */
  if (SSL_OptionSet(sslfd, SSL_HANDSHAKE_AS_CLIENT, sock.isServer() ? PR_FALSE : PR_TRUE) != SECSuccess)
    BOOST_THROW_EXCEPTION(boost::system::system_error(make_nss_error(),
      "Unable to modify SSL_HANDSHAKE_AS_CLIENT option"));

  if (!sock.isServer()) {
    /* Set client certificate and key callback */
    auto rv = SSL_GetClientAuthDataHook(sslfd,
    [](void *arg, PRFileDesc *fd, CERTDistNames *caNames, CERTCertificate **pRetCert,
       SECKEYPrivateKey **pRetKey) -> SECStatus
    {
      SSLSocket &socket = *static_cast<SSLSocket *>(arg);
      return socket.sslCtx().getClientCert(socket, caNames, pRetCert, pRetKey);
    }, &sock);
    
    if (rv != SECSuccess)
      BOOST_THROW_EXCEPTION(boost::system::system_error(make_nss_error(),
        "Unable to set GetClientAuthDataHook"));
  }

  /* Reset handshake */
  /* TODO: Check if necessary */
  if(SSL_ResetHandshake(sslfd, sock.isServer() ? PR_TRUE : PR_FALSE) != SECSuccess)
    BOOST_THROW_EXCEPTION(boost::system::system_error(make_nss_error(),
      "Unable to reset handshake"));
}

} // namespace io
} // namespace mist
