#ifndef __MIST_HEADERS_IO_SSL_SOCKET_HPP__
#define __MIST_HEADERS_IO_SSL_SOCKET_HPP__

#include <functional>
#include <memory>

#include <cert.h>

#include <boost/optional.hpp>
#include <boost/system/error_code.hpp>

#include "io/socket.hpp"
#include "io/io_context.hpp"
#include "io/ssl_context.hpp"
#include "memory/nss.hpp"

namespace mist
{
namespace io
{

class SSLContext;

class SSLSocket : public Socket
{
public:

  /* Callback types */
  using handshake_callback = std::function<void(boost::system::error_code)>;
  using peer_auth_callback = std::function<bool(CERTCertificate*)>;

protected:

  friend class SSLContext;

  SSLContext &_sslCtx;

  bool _server; /* True iff socket was accepted by a rendez-vous socket */

  /*
   * Handshake state data
   */
  struct Handshake
  {
    handshake_callback cb;
    peer_auth_callback authCb;
  } _h;

  /* Called when the socket is handhaking and has signaled that it
     is ready to continue. */
  void handshakeContinue();

  /* Called by the context to authenticate the peer. */
  bool authenticate(CERTCertificate* cert);

public:

  SSLSocket(SSLContext &sslCtx, c_unique_ptr<PRFileDesc> fd, bool server);

  SSLContext &sslCtx();

  /* Perform a TLS handshake. */
  void handshake(handshake_callback cb = nullptr,
                 peer_auth_callback authCb = nullptr);

  /* Close the SSL socket. */
  void close(boost::system::error_code ec = boost::system::error_code());

  /* Returns true iff the socket was accepted by a rendez-vous socket */
  bool isServer() const;

public:

  /* FileDescriptor interface implementation */
  virtual boost::optional<PRInt16> inFlags() const override;
  
  virtual void process(PRInt16 inFlags, PRInt16 outFlags) override;

private:

  SSLSocket(SSLSocket&&) = delete;
  SSLSocket &operator=(SSLSocket&&) = delete;

};

} // namespace io
} // namespace mist

#endif
