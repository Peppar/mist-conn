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

#include "memory/nss.hpp"
#include "error/nss.hpp"

#include "socket.hpp"
#include "context.hpp"

namespace mist
{

namespace
{
  
std::string getPRError() {
  auto length = PR_GetErrorTextLength();
  if (!length)
    return "Error " + std::to_string(PR_GetError());
  char* c = new char[length + 1];
  PR_GetErrorText(c);
  auto error = std::string(c);
  delete[] c;
  return error;
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

Socket::Socket(nss_unique_ptr<PRFileDesc> fd, bool server, SSLContext &ctx)
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
  
  w.cons = std::bind(&Socket::_writeConsumer, this, _1, _2));
}

/*
 * Connect to the specified address.
 */
void Socket::connect(PRNetAddr addr, connect_callback cb)
{
  c.cb = std::move(cb);
  if (PR_Connect(fd.get(), &addr, PR_INTERVAL_NO_WAIT) != PR_SUCCESS) {
    PRErrorCode err = PR_GetError();
    if (err == PR_IN_PROGRESS_ERROR) {
      state = State::Connecting;
    } else {
      if (c.cb) {
        c.cb(make_nss_error(err));
        c.cb = nullptr;
      }
      // if (errCb)
        // errCb();
      std::cerr << "Unable to connect" << std::endl;
    }
  } else {
    state = State::Connected;
    if (c.cb) {
      c.cb(boost::error::error_code());
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

  h.cb = std::move(cb);

  if (!server) {
    /* If this socket was created by the client, the socket has
       not yet been wrapped as an SSL socket */
    ctx.initializeSecurity(fd);
  }
  ctx.initializeTLS(*this);
  state = State::Handshaking;
  _handshake();
}

/*
 * Read once, for small, one-shot packets (~less than 1kB)
 */
// void Socket::readOnce(const uint8_t *data, std::size_t length, read_callback cb)
// {
  // assert (length);
  // assert (length <= r.buffer.size());
  // assert (r.state == Read::State::Off);
  // assert (r.buffer.empty());
  
  // r.state = Read::State::Once;
  // r.data = data;
  // r.target = length;
  // r.cb = std::move(cb);
  // /* TODO: Signal that this socket is ready for read */
// }

/*
 * Set the consumer callback for ingoing data.
 */
void read(consumer_callback cons);
{
  assert (r.state == Read::State::Off);

  r.state = Read::State::Continuous;
  r.cons = std::move(cons);
  //r.buffer.setConsumer(std::move(cons));
  /* TODO: Signal that this socket is ready for read */
}

/*
 * Set the producer callback for outgoing data.
 */
void setSendProducer(producer_callback prod)
{
  assert (w.state == Write::State::Off);

  w.state = Write::State::Continuous;
  w.buffer.setProducer(std::move(prod));
  _write();
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
      if (c.cb) {
        c.cb(make_nss_error(err));
        c.cb = nullptr;
      }
      std::cerr << "Unable to handshake" << std::endl;
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
      if (h.cb) {
        h.cb(make_nss_error(err));
        h.cb = nullptr;
      }
      std::cerr << "Unable to handshake" << std::endl;
    }
  } else {
    if (!is_negotiated_protocol_http2(fd.get())) {
      if (h.cb) {
        h.cb(make_mist_error(MIST_ERR_NOT_HTTP2));
        h.cb = nullptr;
      }
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
 * Set the consumer callback for ingoing data.
 */
void readOnce(std::size_t length, consumer_callback cons);
{
  assert (r.state == Read::State::Off);

  r.state = Read::State::Once;
  r.length = length;
  r.buffer.setConsumer(std::move(cons));
  //r.buffer.setConsumer(std::move(cons));
  /* TODO: Signal that this socket is ready for read */
}

/*
 * Set the consumer callback for ingoing data.
 */
void read(consumer_callback cons);
{
  assert (r.state == Read::State::Off);

  r.state = Read::State::Continuous;
  r.buffer.setConsumer(std::move(cons));
  //r.buffer.setConsumer(std::move(cons));
  /* TODO: Signal that this socket is ready for read */
}

/*
 * Called when the socket is ready for read.
 */
void Socket::_read()
{
  assert (r.state != Read::State::Off);
  
  if (r.state == Read::State::Once) {
    r.buffer.cycle();
    
    if (r.state == Read::State::Error) {
      /* An error occurred while reading */
      std::cerr << "Error while reading" << std::endl;
      state = State::Closed;
    } else if (r.dataCount() == 0) {
      /* All data read; delete the callback */
      r.buffer.setConsumer(nullptr);
      r.state = Read::State::Off;
    }
    return;
  }

  assert (r.state == Write::State::Continuous);
  r.buffer.cycle();
  
  if (r.state == Read::State::Error) {
    /* An error occurred while reading */
    std::cerr << "Error while reading" << std::endl;
    state = State::Closed;
  }
}

/*
 * The receive data producer.
 */
std::size_t Socket::receiveProducer(const uint8_t *data, std::size_t length)
{
  /* Limit the requested number of bytes */
  if (r.state == Read::State::Once)
    length = std::min(length, r.length);
  
  assert (length);

  nread = PR_Recv(fd.get(), data, length, 0, PR_INTERVAL_NO_WAIT);

  /* First, check for would block/timeout */
  if (!nread) {
    state = State::Closed;
    return 0;
  } else if (nread < 0) {
    if (PR_GetError() == PR_WOULD_BLOCK_ERROR) {
      /* Try again later */
    } else {
      /* Error while reading */
      r.state = Read::State::Error;
    }
    return 0;
  } else {
    /* Read nread bytes */
    if (r.state == Read::State::Once)
      r.length -= nread;
    return nread;
  }
}
  
/*
 * Write.
 */
// void Socket::write(write_callback cb)
// {
  // assert (length);
  // assert (w.state == Write::State::Off);

  // w.state = Write::State::On;
  // w.prov = std::move(prov);
  // //w.buffer.setProducer(std::move(prod));
  
  // // std::size_t nwritten;
  // // while (true) {
    // // if (length) {
      // // std::size_t bufWritten = w.buffer.write(data, length);
      // // length -= bufWritten;
      // // nwritten += bufWritten;
      // // data += bufWritten;
    // // }
    // // if (!w.buffer.consume())
      // // break;
  // // }
  // // return nwritten;
  
  // _write();
// }

/*
 * Write.
 */
void Socket::writeOnce(const uint8_t *data, std::size_t length,
  write_callback cb)
{
  assert (length);
  assert (w.state == Write::State::Off);
  
  w.state = Write::State::On;
  w.data = data;
  w.length = length;
  w.written = 0;
  
  w.cb = std::move(cb);
  _write();
}

/*
 * Called when the socket is ready for writing.
 */
void Socket::_write()
{
  assert (w.state == Write::State::On);
  if (w.length == w.written) {
    w.state = Write::State::Off;
    /* Nothing more to write; notify callback */
    if (w.cb) {
      w.cb(w.written, boost::system::error_code());
      w.cb = nullptr;
    }
    return;
  }
  auto rc = PR_Send(fd.get(), w.data + w.written,
                    w.length - w.written, 0,
                    PR_INTERVAL_NO_WAIT);
  
  if (rc == 0) {
    /* Unexpected */
    if (w.cb) {
      w.cb(w.written, make_nss_error(PR_UNKNOWN_ERROR));
      w.cb = nullptr;
    }
    std::cerr << "PR_Send returned 0" << std::endl;
  } else if (rc < 0) {
    /* Error */
    PRInt32 err = PR_GetError();
    if (err == PR_WOULD_BLOCK_ERROR) {
      /* Can not write at this moment; try again later */
    } else {
      /* Unable to send; do not send any further data */
      w.state = Write::State::Off;
      /* Notify the callback */
      if (w.cb) {
        w.cb(w.written, make_nss_error(err));
        w.cb = nullptr;
      }
      std::cerr << "Error while writing: " << getPRError() << std::endl;
    }
  } else {
    /* Wrote rc bytes */
    w.written += rc;
    assert (w.written <= w.length);
  }
}
// std::size_t Socket::_writeConsumer(const uint8_t *data, std::size_t length)
// {
  // if (!length) {
    // /* End of this data source; delete callback */
    // w.state = Write::State::Off;
    // w.prov = nullptr;
    // return 0;
  // }
    
  // auto rc = PR_Send(fd.get(), data, length, 0, PR_INTERVAL_NO_WAIT);
  
  // if (rc == 0) {
    // /* Unexpected */
    // state = State::Error;
  // } else if (rc < 0) {
    // /* Error */
    // PRInt32 err = PR_GetError();
    // if (err == PR_WOULD_BLOCK_ERROR || err == PR_IO_TIMEOUT_ERROR) {
      // /* Can not write at this moment; try again later */
    // } else {
      // /* Unable to send; do not send any further data */
      // w.state = Write::State::Off;
      // state = State::Error;
    // }
    // return 0;
  // } else {
    // /* Wrote rc bytes */
    // w.written += rc;
    // assert (w.written <= w.length);
  // }
// }

// /*
 // * Called when the socket is ready for writing.
 // */
// void Socket::_write()
// {
  // assert (w.state != Write::State::Off);  
  // w.prov(w.cons);
// }
  
  // if (!w.length) {
    // w.state = Write::State::Off;
    // /* Nothing more to write; notify callback */
    // if (w.cb) {
      // w.cb(w.written);
      // w.cb = nullptr;
    // }
    // return;
  // }
  // auto rc = PR_Send(fd.get(), w.data + w.written,
                    // w.length - w.written, 0,
                    // PR_INTERVAL_NO_WAIT);
  
  // if (rc == 0) {
    // /* Unexpected */
    // if (w.cb) {
      // w.cb(w.written);
      // w.cb = nullptr;
    // }
    // std::cerr << "PR_Send returned 0" << std::endl;
  // } else if (rc < 0) {
    // /* Error */
    // PRInt32 err = PR_GetError();
    // if (err == PR_WOULD_BLOCK_ERROR || err == PR_IO_TIMEOUT_ERROR) {
      // /* Can not write at this moment; try again later */
    // } else {
      // /* Unable to send; do not send any further data */
      // w.state = Write::State::Off;
      // /* Notify the callback */
      // if (w.cb) {
        // w.cb(w.written);
        // w.cb = nullptr;
      // }
      // std::cerr << "Error while writing: " << getPRError() << std::endl;
    // }
  // } else {
    // /* Wrote rc bytes */
    // w.written += rc;
    // assert (w.written <= w.length);
  // }
/*
 * Called when the socket is ready for writing.
 */
// void Socket::_write()
// {
  // assert (w.state != Write::State::Off);

  // if (w.state == Write::State::Once) {
    // w.buffer.consume();
    // if (w.buffer.empty()) {
      // w.state = Write::State::Off;
      // /* Nothing more to write; notify callback */
      // if (w.cb) {
        // w.cb(w.written);
        // w.cb = nullptr;
      // }
    // }
    // return;
  // }
  
  // assert (w.state == Write::State::Continuous);
  // w.buffer.cycle();
  
  // if (w.state == Write::State::Error) {
    // /* An error occurred while writing */
    // std::cerr << "Error while writing" << std::endl;
    // state = State::Closed;
  // }
// }

// /*
 // * Called when the socket is ready for read.
 // */
// void Socket::_read()
// {
  // assert (r.state != Read::State::Off);
  // PRInt32 nread;
  // {
    // std::size_t maxRead;
    // //uint8_t *bufferInsertionPt = r.buffer.data() + r.nread;
    // if (r.state == Read::State::Once) {
      // maxRead = r.target - r.buffer.dataCount();
    // } else {
      // maxRead = std::numeric_limits<std::size_t>::max();
    // }
    
    // /* Make sure we didn't screw up the calculation */
    // //assert (bufferInsertionPt + maxRead - r.buffer.data() <= r.buffer.size());

    // /* std::tuple<File descriptor, Max read size, Errno> */
    // using userdata_type = std::tuple<PRFileDesc*, std::size_t, int>;
    // userdata_type data{fd.get(), maxRead, 0};
    // r.buffer.write(&data,
      // [](uint8_t *data, std::size_t length, void *user)
    // {
      // /* Unpack our user state */
      // userdata_type &data = *(userdata_type *)user;
      // std::size_t &maxRead = std::get<1>(data);
      // int &err = std::get<2>(data);
      
      // std::size_t avail = std::min(length, maxRead);
      // ssize_t nread = PR_Recv(std::get<0>(data), data, maxRead, 0,
                              // PR_INTERVAL_NO_WAIT);

      // if (nread < 0) {
        // auto prErr = PR_GetError();
        // if (prErr == PR_WOULD_BLOCK_ERROR)
          // return 0;
        // err = prErr;
        // return 0;
      // }
      
      // maxRead -= nread;
      // return nread;
    // });

    // /* Read successful */
    // r.nread += nread;
    // assert (r.nread <= r.buffer.length());
    
    // if (r.state == Read::State::Once && r.nread < r.length) {
      // /* More data to be read before triggering the callback */
    // } else {
      // /* Notify the read callback */
      // r.cb(r.buffer.data(), r.nread);
      // if (r.state == Read::State::Once) {
        // /* One-off read; clear the callback */
        // r.state = Read::State::Off;
        // r.cb = nullptr;
      // } else {
        // /* Continuous read */
        // assert (r.state == Read::State::Continuous);
      // }
    // }
  // } else {
    // /* Read failed */
    // if (nread == 0) {
      // /* Connection closed */
      // std::cerr << "Connection closed while reading" << std::endl;
      // state = State::Closed;
    // } else {
      // /* Read error */
      // std::cerr << "Error while reading: " << getPRError() << std::endl;
    // }
    
    // /* Notify the callback of the data already read, and
       // set read state to off */
    // assert (r.cb);
    // r.state = Read::State::Off;
    // r.cb(r.buffer.data(), r.state == Read::State::Once ? r.nread : 0);
    // r.cb = nullptr;
  // }
    // });
    // nread = PR_Recv(fd.get(), bufferInsertionPt, maxRead, 0,
                    // PR_INTERVAL_NO_WAIT);
  // }
  
  // /* First, check for would block/timeout */
  // if (nread < 0) {
    // PRInt32 err = PR_GetError();
    // if (err == PR_WOULD_BLOCK_ERROR || err == PR_IO_TIMEOUT_ERROR) {
      // /* Can not read at this moment; try again later */
      // return;
    // }
  // }
  
  // if (nread > 0) {
    // /* Read successful */
    // r.nread += nread;
    // assert (r.nread <= r.buffer.length());
    
    // if (r.state == Read::State::Once && r.nread < r.length) {
      // /* More data to be read before triggering the callback */
    // } else {
      // /* Notify the read callback */
      // r.cb(r.buffer.data(), r.nread);
      // if (r.state == Read::State::Once) {
        // /* One-off read; clear the callback */
        // r.state = Read::State::Off;
        // r.cb = nullptr;
      // } else {
        // /* Continuous read */
        // assert (r.state == Read::State::Continuous);
      // }
    // }
  // } else {
    // /* Read failed */
    // if (nread == 0) {
      // /* Connection closed */
      // std::cerr << "Connection closed while reading" << std::endl;
      // state = State::Closed;
    // } else {
      // /* Read error */
      // std::cerr << "Error while reading: " << getPRError() << std::endl;
    // }
    
    // /* Notify the callback of the data already read, and
       // set read state to off */
    // assert (r.cb);
    // r.state = Read::State::Off;
    // r.cb(r.buffer.data(), r.state == Read::State::Once ? r.nread : 0);
    // r.cb = nullptr;
  // }
// }



/*
 * Called when the socket is closed.
 */
void Socket::_close()
{
  state = State::Closed;
}

/*
 * Returns true iff there is data to be written.
 */
bool Socket::isWriting() const
{
  return w.state != Write::State::Off;
}

/*
 * Returns true iff we are ready to listen for reads.
 */
bool Socket::isReading() const
{
  return r.state != Read::State::Off;
}

// std::size_t Socket::sendConsumer(const uint8_t *data, std::size_t length);
// {
  // assert (length);
  
  // auto nsent = PR_Send(fd.get(), data, length, 0, PR_INTERVAL_NO_WAIT);
  
  // assert (nsent != 0);
  
  // if (nsent < 0) {
    // /* Error */
    // if (PR_GetError() == PR_WOULD_BLOCK_ERROR) {
      // /* Can not write at this moment; try again later */
    // } else {
      // /* Error while sending */
      // w.state = Write::State::Error;
    // }
    // return 0;
  // } else {
    // /* Wrote nsent bytes */
    // return nsent;
  // }
// }

/*
 * Creates a self-contained writer provider to write a fixed-size
 * packet. This is intended for use in handshaking, and with
 * relatively small packets.
 */
// provider_callback Socket::createProvider(const uint8_t *data,
  // std::size_t length)
// {
  // std::vector<uint8_t> v(data, data + length);
  // std::size_t nwritten = 0;
  // return
    // [v(std::move(v)), nwritten, length]
    // (consumer_callback &cons) mutable
  // {
    // nwritten += cons(v.data() + nwritten, length - nwritten);
  // };
// }

}
