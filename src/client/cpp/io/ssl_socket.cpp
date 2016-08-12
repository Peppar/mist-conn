#include <algorithm>
#include <cassert>
#include <iostream>
#include <string>
#include <memory>
#include <vector>
#include <list>

/* NSPR Headers */
//#include <nspr.h>
#include <prerror.h>
#include <prtypes.h>
#include <prio.h>

#include <boost/optional.hpp>
#include <boost/system/error_code.hpp>
#include <boost/system/system_error.hpp>

#include <nghttp2/nghttp2.h>

#include "memory/nss.hpp"
#include "error/mist.hpp"
#include "error/nss.hpp"

#include "io/io_context.hpp"
#include "io/socket.hpp"
#include "io/ssl_context.hpp"
#include "io/ssl_socket.hpp"

namespace mist
{
namespace io
{
namespace
{

/* Return the negotiated protocol from an NPN/ALPN enabled SSL socket. */
boost::optional<std::string>
get_negotiated_protocol(PRFileDesc *fd)
{
  std::array<std::uint8_t, 50> buf;
  unsigned int buflen;
  SSLNextProtoState state;

  if (SSL_GetNextProto(fd, &state,
                       reinterpret_cast<unsigned char*>(buf.data()),
                       &buflen, buf.size()) != SECSuccess)
    return boost::none;

  switch(state) {
  case SSL_NEXT_PROTO_SELECTED:
  case SSL_NEXT_PROTO_NEGOTIATED:
    return std::string(reinterpret_cast<const char*>(buf.data()), buflen);

  default:
    return boost::none;
  }
}

/* Returns true iff the negotiated protocol for the socket is HTTP/2. */
bool
is_negotiated_protocol_http2(PRFileDesc *fd)
{
  auto protocol = get_negotiated_protocol(fd);
  return protocol &&
    protocol == std::string(NGHTTP2_PROTO_VERSION_ID,
                            NGHTTP2_PROTO_VERSION_ID_LEN);
}

} // namespace

/*
 * SSLSocket
 */
SSLSocket::SSLSocket(SSLContext &sslCtx, c_unique_ptr<PRFileDesc> fd,
                     bool server)
  : Socket(sslCtx.ioCtx(), std::move(fd), server),
    _sslCtx(sslCtx),
    _server(server)
  {}

boost::optional<PRInt16>
SSLSocket::inFlags() const
{
  if (_state == State::Handshaking) {
    std::cerr << "Socket handshaking poll" << std::endl;
    return PR_POLL_READ;
  } else {
    return Socket::inFlags();
  }
}

void
SSLSocket::process(PRInt16 inFlags, PRInt16 outFlags)
{
  if (outFlags & (PR_POLL_ERR|PR_POLL_NVAL)) {
    
    Socket::process(inFlags, outFlags);    

  } else if (outFlags) {
    
    if (_state == State::Handshaking) {
      
      assert (outFlags & PR_POLL_READ);
      std::cerr << "Socket handshaking PR_POLL_READ" << std::endl;
      handshakeContinue();
      
    } else {
      
      Socket::process(inFlags, outFlags);
      
    }
  }
}

/* Perform TLS handshake. */ 
void
SSLSocket::handshake(handshake_callback cb, peer_auth_callback authCb)
{
  assert (_state == State::Open);
  assert (_r.state == Read::State::Off);
  assert (_w.state == Write::State::Off);

  _state = State::Handshaking;
  _h.cb = std::move(cb);
  _h.authCb = std::move(authCb);

  if (!isServer()) {
    /* If this socket was created by the client, the socket has
       not yet been wrapped as an SSL socket */
    sslCtx().initializeSecurity(_fd);
  }
  sslCtx().initializeTLS(*this);
  
  handshakeContinue();
}

/* Called when the socket is handhaking and has signaled that it
   is ready to continue. */
void
SSLSocket::handshakeContinue()
{
  assert (_state == State::Handshaking);
  if (SSL_ForceHandshake(_fd.get()) != SECSuccess) {
    PRErrorCode err = PR_GetError();
    if(PR_GetError() == PR_WOULD_BLOCK_ERROR) {
      /* Try again later */
    } else {
      /* Error while handshaking */
      close(make_nss_error(err));
    }
  } else {
    if (!is_negotiated_protocol_http2(_fd.get())) {
      close(make_mist_error(MIST_ERR_NOT_HTTP2));
    } else {
      _state = State::Open;
      if (_h.cb) {
        _h.cb(boost::system::error_code());
        _h.cb = nullptr;
      }
    }
  }
}

/* Called by the context to authenticate the peer. */
bool
SSLSocket::authenticate(CERTCertificate *cert)
{
  bool authenticated = true;
  if (_h.authCb) {
    authenticated = _h.authCb(cert);
    _h.authCb = nullptr;
  }
  return authenticated;
}

/* Returns the SSL context of the socket */
SSLContext &
SSLSocket::sslCtx()
{
  return _sslCtx;
}

bool 
SSLSocket::isServer() const
{
  return _server;
}

/* Close the SSL socket. */
void
SSLSocket::close(boost::system::error_code ec)
{
  if (!ec)
    ec = make_nss_error(PR_CONNECT_RESET_ERROR);
  if (_state == State::Handshaking && _h.cb) {
    _h.cb(ec);
    _h.cb = nullptr;
  }
  Socket::close(ec);
}

} // namespace io
} // namespace mist
