#include <algorithm>
#include <cassert>
#include <iostream>
#include <string>
#include <memory>
#include <vector>
#include <list>

//#include <nspr.h>
#include <prerror.h>
#include <prtypes.h>
#include <prio.h>

#include <boost/optional.hpp>
#include <boost/system/error_code.hpp>
#include <boost/system/system_error.hpp>

#include "memory/nss.hpp"
#include "error/mist.hpp"
#include "error/nss.hpp"

#include "io/socket.hpp"
#include "io/io_context.hpp"

namespace mist
{
namespace io
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
    text += to_hex(static_cast<uint8_t>(*(begin++)));
  return text;
}

} // namespace

/*
 * Socket
 */
Socket::Socket(IOContext &ioCtx, c_unique_ptr<PRFileDesc> fd, bool isOpen)
  : _ioCtx(ioCtx), _fd(std::move(fd))
{
  _w.state = Write::State::Off;
  _r.state = Read::State::Off;
  if (isOpen)
    _state = State::Open;
  else
    _state = State::Unconnected;
}

PRFileDesc *
Socket::fileDesc()
{
  return _fd.get();
}

boost::optional<PRInt16>
Socket::inFlags() const
{
  if (_state == State::Closed) {
    return boost::none;
  } else if (_state == State::Connecting) {
    std::cerr << "Socket connect poll" << std::endl;
    return PR_POLL_WRITE|PR_POLL_EXCEPT;
  } else {
    PRInt16 flags
      = (isReading() ? PR_POLL_READ : 0)   // 1
      | (isWriting() ? PR_POLL_WRITE : 0); // 2
    std::cerr << "Socket polling with flags " << flags << std::endl;
    return flags;
  }
}

void
Socket::process(PRInt16 inFlags, PRInt16 outFlags)
{
  if (outFlags & PR_POLL_ERR) {
    
    /* Get the error code by performing a bogus read, expected to fail */
    boost::system::error_code ec;
    if (PR_Read(fileDesc(), nullptr, 0) != PR_SUCCESS)
      ec = make_nss_error();
    else
      ec = make_nss_error(PR_UNKNOWN_ERROR);
    close(ec);
    
  } else if (outFlags & PR_POLL_NVAL) {
    
    /* Invalid file descriptor */
    close(make_nss_error(PR_BAD_DESCRIPTOR_ERROR));
    
  } else if (outFlags) {
    
    if (_state == State::Connecting) {
      std::cerr << "Socket Connecting" << std::endl;
      connectContinue(outFlags);
    } else {
      if (outFlags & PR_POLL_WRITE) {
        std::cerr << "Socket Open PR_POLL_WRITE" << std::endl;
        writeReady();
      }
      if (outFlags & PR_POLL_READ) {
        std::cerr << "Socket Open PR_POLL_READ" << std::endl;
        readReady();
      }
    }
  }
}

/* Connect to the specified address. */
void
Socket::connect(PRNetAddr *addr, connect_callback cb)
{
  assert (_state == State::Unconnected);
  
  _c.cb = std::move(cb);
  if (PR_Connect(_fd.get(), addr, PR_INTERVAL_NO_WAIT) != PR_SUCCESS) {
    /* Set state here to avoid race conditions */
    _state = State::Connecting;
    PRErrorCode err = PR_GetError();
    if (err == PR_IN_PROGRESS_ERROR) {
      /* Try again later */
    } else {
      /* Error while connecting */
      close(make_nss_error(err));
    }
  } else {
    _state = State::Open;
    if (_c.cb) {
      /* Move the callback as a new one can be set by the time it returns */
      auto cb = std::move(_c.cb);
      cb(boost::system::error_code());
    }
  }
  
  signal();
}

/* Called when the socket is connecting and has signaled that it
 * is ready to continue. */
void
Socket::connectContinue(PRInt16 out_flags)
{
  assert (_state == State::Connecting);
  if (PR_ConnectContinue(_fd.get(), out_flags) != PR_SUCCESS) {
    PRErrorCode err = PR_GetError();
    if (err == PR_IN_PROGRESS_ERROR) {
      /* Try again later */
    } else {
      /* Error while connecting */
      close(make_nss_error(err));
    }
  } else {
    _state = State::Open;
    if (_c.cb) {
      /* Move the callback as a new one can be set by the time it returns */
      auto cb = std::move(_c.cb);
      cb(boost::system::error_code());
    }
  }
}

/* Read a short packet (fitting in the receive buffer) and
 * then call the callback. */
void
Socket::readOnce(std::size_t length, read_callback cb)
{
  assert (_r.state == Read::State::Off);

  _r.state = Read::State::Once;
  _r.length = length;
  _r.nread = 0;
  _r.cb = std::move(cb);
  
  signal();
}

/* Read data continuously. */
void
Socket::read(read_callback cb)
{
  assert (_r.state == Read::State::Off);

  _r.state = Read::State::Continuous;
  _r.length = 0;
  _r.nread = 0;
  _r.cb = std::move(cb);

  signal();
}

/* Called when the socket is ready for read. */
void
Socket::readReady()
{
  assert (_r.state != Read::State::Off);

  std::size_t length = _r.buffer.size();
  
  if (_r.state == Read::State::Once) {
    /* Limit the requested number of bytes */
    length = std::min(length, _r.length - _r.nread);
  }

  assert (length);

  auto nread = PR_Recv(_fd.get(), _r.buffer.data() + _r.nread, length, 0,
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
    std::cerr << "Received " << to_hex(_r.buffer.data(), _r.buffer.data() + nread) << std::endl;
    if (_r.state == Read::State::Once) {
      _r.nread += nread;
      assert (_r.nread <= _r.length);
      
      /* Read nread bytes */
      if (_r.nread == _r.length) {
        /* We have read all requested data */
        _r.state = Read::State::Off;

        /* Move the callback as a new one can be set by the time it returns */
        std::move(_r.cb)(_r.buffer.data(),
          _r.length, boost::system::error_code());
      }
    } else {
      assert (_r.state == Read::State::Continuous);
      _r.cb(_r.buffer.data(), nread, boost::system::error_code());
    }
  }
}

/* Write. */
void
Socket::write(const uint8_t *data, std::size_t length,
              write_callback cb)
{
  assert (length);
  assert (_w.state == Write::State::Off);
  
  _w.state = Write::State::On;
  _w.data = data;
  _w.length = length;
  _w.nwritten = 0;
  
  _w.cb = std::move(cb);
  
  writeReady();
}

/* Called when the socket is ready for writing. */
void
Socket::writeReady()
{
  assert (_w.state == Write::State::On);
  auto rc = PR_Send(_fd.get(), _w.data + _w.nwritten,
                    _w.length - _w.nwritten, 0,
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
    std::cerr << "Wrote " << to_hex(_w.data + _w.nwritten, _w.data + _w.nwritten + rc) << std::endl;
    /* Wrote rc bytes */
    _w.nwritten += rc;
    assert (_w.nwritten <= _w.length);
    if (_w.nwritten == _w.length) {
      _w.state = Write::State::Off;
      /* Nothing more to write; notify callback */
      if (_w.cb) {
        /* Move the callback as a new one can be set by the time it returns */
        auto cb = std::move(_w.cb);
        cb(_w.nwritten, boost::system::error_code());
      }
    }
  }
}

/* Close the socket. */
void
Socket::close(boost::system::error_code ec)
{
  if (!ec)
    ec = make_nss_error(PR_CONNECT_RESET_ERROR);
  if (_state == State::Connecting && _c.cb) {
    std::move(_c.cb)(ec);
    //_c.cb = nullptr;
  }
  if (_r.state != Read::State::Off && _r.cb) {
    _r.cb(_r.buffer.data(), _r.length, ec);
    _r.cb = nullptr;
  }
  if (_w.state != Write::State::Off && _w.cb) {
    _w.cb(_w.nwritten, ec);
    _w.cb = nullptr;
  }
  _r.state = Read::State::Off;
  _w.state = Write::State::Off;
  _state = State::Closed;
  
  signal();
}

/* Returns true iff there is data to be written. */
bool
Socket::isWriting() const
{
  return _w.state != Write::State::Off;
}

/* Returns true iff we are ready to listen for reads. */
bool
Socket::isReading() const
{
  return _r.state != Read::State::Off;
}

/* Signal to the context event loop that we have things to do. */
void
Socket::signal()
{
  _ioCtx.signal();
}

/* Returns the I/O context of the socket */
IOContext &
Socket::ioCtx()
{
  return _ioCtx;
}

} // namespace io
} // namespace mist
