#include <algorithm>
#include <cassert>
#include <iostream>
#include <string>
#include <memory>
#include <vector>
#include <list>

/* NSPR Headers */
#include <nspr.h>
#include <prthread.h>
#include <plgetopt.h>
#include <prerror.h>
#include <prinit.h>
#include <prlog.h>
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
#include <secerr.h>
#include <secmod.h>
#include <secitem.h>
#include <secport.h>
#include <sslproto.h>
#include <certdb.h>
#include <cert.h>
#include <certt.h>

#include <secasn1.h>

#include <nghttp2/nghttp2.h>
#include <boost/optional.hpp>
#include <boost/system/error_code.hpp>
#include <boost/system/system_error.hpp>

#include "memory/nss.hpp"
#include "error/mist.hpp"
#include "error/nss.hpp"

#include "socket.hpp"
#include "context.hpp"

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

/*
 * Return the negotiated protocol from an NPN/ALPN enabled SSL socket.
 */
boost::optional<std::string> get_negotiated_protocol(PRFileDesc *fd) {
  std::array<uint8_t, 50> buf;
  unsigned int buflen;
  SSLNextProtoState state;

  if (SSL_GetNextProto(fd, &state, (unsigned char*)buf.data(),
                       &buflen, buf.size()) != SECSuccess)
    return boost::none;

  switch(state) {
  case SSL_NEXT_PROTO_SELECTED:
  case SSL_NEXT_PROTO_NEGOTIATED:
    return std::string((const char*)buf.data(), buflen);

  default:
    return boost::none;
  }
}

/*
 * Returns true iff the negotiated protocol for the socket is HTTP/2.
 */
bool is_negotiated_protocol_http2(PRFileDesc *fd) {
  auto protocol = get_negotiated_protocol(fd);
  return protocol &&
    protocol == std::string(NGHTTP2_PROTO_VERSION_ID,
                            NGHTTP2_PROTO_VERSION_ID_LEN);
}

}

Socket::Socket(c_unique_ptr<PRFileDesc> fd, bool server, SSLContext &ctx)
  : fd(std::move(fd)), server(server), ctx(ctx)
{
  using namespace std::placeholders;
  
  w.state = Write::State::Off;
  r.state = Read::State::Off;
  
  if (server)
    /* For sockets accepted by rendez-vous sockets */
    state = State::Connected;
  else
    /* For sockets opened by us */
    state = State::Unconnected;
}

/*
 * Connect to the specified address.
 */
void Socket::connect(PRNetAddr *addr, connect_callback cb)
{
  assert (state == State::Unconnected);
  
  c.cb = std::move(cb);
  if (PR_Connect(fd.get(), addr, PR_INTERVAL_NO_WAIT) != PR_SUCCESS) {
    /* Set state here to avoid race conditions */
    state = State::Connecting;
    PRErrorCode err = PR_GetError();
    if (err == PR_IN_PROGRESS_ERROR) {
      /* Try again later */
    } else {
      /* Error while connecting */
      close(make_nss_error(err));
    }
  } else {
    state = State::Connected;
    if (c.cb) {
      c.cb(boost::system::error_code());
      c.cb = nullptr;
    }
  }
  
  signal();
}

/*
 * Called when the socket is connecting and has signaled that it
 * is ready to continue.
 */
void Socket::_connectContinue(PRInt16 out_flags)
{
  assert (state == State::Connecting);
  if (PR_ConnectContinue(fd.get(), out_flags) != PR_SUCCESS) {
    PRErrorCode err = PR_GetError();
    if(err == PR_IN_PROGRESS_ERROR) {
      /* Try again later */
    } else {
      /* Error while connecting */
      close(make_nss_error(err));
    }
  } else {
    state = State::Connected;
    if (c.cb) {
      c.cb(boost::system::error_code());
      c.cb = nullptr;
    }
  }
}

/*
 * Begin TLS communication.
 */ 
void Socket::handshake(handshake_callback cb)
{
  assert (state == State::Connected);
  assert (r.state == Read::State::Off);
  assert (w.state == Write::State::Off);

  state = State::Handshaking;
  h.cb = std::move(cb);

  if (!server) {
    /* If this socket was created by the client, the socket has
       not yet been wrapped as an SSL socket */
    ctx.initializeSecurity(fd);
  }
  ctx.initializeTLS(*this);
  
  _handshake();
}

/*
 * Called when the socket is handhaking and has signaled that it
 * is ready to continue.
 */
void Socket::_handshake()
{
  assert (state == State::Handshaking);
  if (SSL_ForceHandshake(fd.get()) != SECSuccess) {
    PRErrorCode err = PR_GetError();
    if(PR_GetError() == PR_WOULD_BLOCK_ERROR) {
      /* Try again later */
    } else {
      /* Error while handshaking */
      close(make_nss_error(err));
    }
  } else {
    if (!is_negotiated_protocol_http2(fd.get())) {
      close(make_mist_error(MIST_ERR_NOT_HTTP2));
    } else {
      state = State::Open;
      if (h.cb) {
        h.cb(boost::system::error_code());
        h.cb = nullptr;
      }
    }
  }
}

/*
 * Read a short packet (fitting in the receive buffer) and
 * then call the callback.
 */
void
Socket::readOnce(std::size_t length, read_callback cb)
{
  assert (r.state == Read::State::Off);

  r.state = Read::State::Once;
  r.length = length;
  r.nread = 0;
  r.cb = std::move(cb);
  
  signal();
}

/*
 * Read data continuously.
 */
void
Socket::read(read_callback cb)
{
  assert (r.state == Read::State::Off);

  r.state = Read::State::Continuous;
  r.length = 0;
  r.nread = 0;
  r.cb = std::move(cb);

  signal();
}

/*
 * Called when the socket is ready for read.
 */
void
Socket::_read()
{
  assert (r.state != Read::State::Off);

  std::size_t length = r.buffer.size();
  
  if (r.state == Read::State::Once) {
    /* Limit the requested number of bytes */
    length = std::min(length, r.length - r.nread);
  }

  assert (length);

  auto nread = PR_Recv(fd.get(), r.buffer.data() + r.nread, length, 0,
                       PR_INTERVAL_NO_WAIT);

  if (!nread) {
    /* Read 0 bytes: the socket is closed */
    close();
  } else if (nread < 0) {
    PRErrorCode err = PR_GetError();
    if (err == PR_WOULD_BLOCK_ERROR) {
      /* Would block; try again later */
    } else {
      /* Error while reading */
      close(make_nss_error(err));
    }
  } else {
    std::cerr << "Received " << to_hex(r.buffer.data(), r.buffer.data() + nread) << std::endl;
    if (r.state == Read::State::Once) {
      r.nread += nread;
      assert (r.nread <= r.length);
      
      /* Read nread bytes */
      if (r.nread == r.length) {
        /* We have read all requested data */
        r.state = Read::State::Off;
        r.cb(r.buffer.data(), r.length, boost::system::error_code());
        r.cb = nullptr;
        return;
      }
    } else {
      assert (r.state == Read::State::Continuous);
      r.cb(r.buffer.data(), nread, boost::system::error_code());
    }
  }
}

/*
 * Write.
 */
void
Socket::write(const uint8_t *data, std::size_t length,
              write_callback cb)
{
  assert (length);
  assert (w.state == Write::State::Off);
  
  w.state = Write::State::On;
  w.data = data;
  w.length = length;
  w.nwritten = 0;
  
  w.cb = std::move(cb);
  
  _write();
}

/*
 * Called when the socket is ready for writing.
 */
void
Socket::_write()
{
  assert (w.state == Write::State::On);
  auto rc = PR_Send(fd.get(), w.data + w.nwritten,
                    w.length - w.nwritten, 0,
                    PR_INTERVAL_NO_WAIT);
  
  assert (rc);
  if (rc < 0) {
    /* Error */
    PRErrorCode err = PR_GetError();
    if (err == PR_WOULD_BLOCK_ERROR) {
      /* Can not write at this moment; try again later */
    } else {
      /* Unable to send  */
      close(make_nss_error(err));
    }
  } else {
    std::cerr << "Wrote " << to_hex(w.data + w.nwritten, w.data + w.nwritten + rc) << std::endl;
    /* Wrote rc bytes */
    w.nwritten += rc;
    assert (w.nwritten <= w.length);
    if (w.nwritten == w.length) {
      w.state = Write::State::Off;
      /* Nothing more to write; notify callback */
      if (w.cb) {
        w.cb(w.nwritten, boost::system::error_code());
        w.cb = nullptr;
      }
    }
  }
}

/*
 * Close the socket.
 */
void
Socket::close(boost::system::error_code ec)
{
  if (!ec)
    ec = make_nss_error(PR_CONNECT_RESET_ERROR);
  if (state == State::Handshaking && h.cb) {
    h.cb(ec);
    h.cb = nullptr;
  }
  if (state == State::Connecting && c.cb) {
    c.cb(ec);
    c.cb = nullptr;
  }
  if (r.state != Read::State::Off && r.cb) {
    r.cb(r.buffer.data(), r.length, ec);
    r.cb = nullptr;
  }
  if (w.state != Write::State::Off && w.cb) {
    w.cb(w.nwritten, ec);
    w.cb = nullptr;
  }
  r.state = Read::State::Off;
  w.state = Write::State::Off;
  state = State::Closed;
  
  signal();
}

/*
 * Returns true iff there is data to be written.
 */
bool
Socket::isWriting() const
{
  return w.state != Write::State::Off;
}

/*
 * Returns true iff we are ready to listen for reads.
 */
bool
Socket::isReading() const
{
  return r.state != Read::State::Off;
}

/*
 * Signal to the context event loop that we have things to do.
 */
void
Socket::signal()
{
  ctx.signal();
}

}
