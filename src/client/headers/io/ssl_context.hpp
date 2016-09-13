#ifndef __MIST_HEADERS_IO_SSL_CONTEXT_HPP__
#define __MIST_HEADERS_IO_SSL_CONTEXT_HPP__

#include <cstddef>
#include <string>
#include <memory>
#include <list>

#include <prtypes.h>
#include <prio.h>
#include <pk11priv.h>
#include <pk11pub.h>

#include <nss.h>
#include <ssl.h>
#include <cert.h>

#include <boost/optional.hpp>

#include "memory/nss.hpp"

#include "io/io_context.hpp"
#include "io/ssl_socket.hpp"

namespace mist
{
namespace io
{

class SSLSocket;

class SSLContext
{
public:

  using connection_callback = std::function<void(std::shared_ptr<SSLSocket>)>;

private:

  friend class SSLSocket;

  IOContext& _ioCtx;

  std::string _slotPassword;

  std::string _nickname;

  c_unique_ptr<CERTCertificate> _certificate;

  c_unique_ptr<SECKEYPrivateKey> _privateKey;

  /* Initialize NSS with the given database directory */
  void initializeNSS(const std::string& dbdir);

  /* Makes sure that the internal slot is initialized and returns it */
  c_unique_ptr<PK11SlotInfo> internalSlot();

  /* Upgrades the NSPR socket file descriptor to TLS */
  void initializeSecurity(c_unique_ptr<PRFileDesc>& fd);
  
  /* Initialize the socket with mist TLS settings */
  void initializeTLS(SSLSocket& sock);

  /* Called when NSS wants to get the client certificate */
  SECStatus getClientCert(SSLSocket& socket, CERTDistNames* caNames,
                          CERTCertificate** pRetCert,
                          SECKEYPrivateKey** pRetKy);

  /* Called when NSS wants to authenticate the peer certificate */
  SECStatus authCertificate(SSLSocket& socket, PRBool checkSig,
                            PRBool isServer);

  ///* Called when NSS wants us to supply a password */
  //boost::optional<std::string> getPassword(PK11SlotInfo* info, PRBool retry);

public:

  SSLContext(IOContext& ioCtx, const std::string& dbdir);

  void loadPKCS12(const std::string& data, const std::string& password);

  void loadPKCS12File(const std::string& path, const std::string& password);

  IOContext& ioCtx();

  void serve(std::uint16_t servPort, connection_callback cb);

  std::shared_ptr<SSLSocket> openSocket();

};

} // namespace io
} // namespace mist

#endif
