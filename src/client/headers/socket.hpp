#ifndef __MIST_SOCKET_HPP__
#define __MIST_SOCKET_HPP__

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

#include "memory/nss.hpp"
#include "cbuffer.hpp"

namespace mist
{

class SSLContext;

class Socket
{
public:

  /*
   * The current overarching state of the socket
   */
  enum class State {
    Unconnected, /* Not yet connected to an endpoint */
    Connecting,  /* Connecting to an endpoint */
    Connected,   /* Connected to an endpoint, non-TLS */
    Handshaking, /* Performing TLS handshake */
    Open,        /* Connected to an endpoint, TLS */
    Closed,      /* Closed */
  } state;

  /*
   * Callback types
   */
  using write_callback = std::function<void(std::size_t, boost::system::error_code)>;
  using read_callback = std::function<void(const uint8_t *, std::size_t, boost::system::error_code)>;
  using connect_callback = std::function<void(boost::system::error_code)>;
  using handshake_callback = std::function<void(boost::system::error_code)>;

private:

  friend class SSLContext;

  /*
   * Write state data. Note that we can write when the overarching
   * state is Connected, Handshaking or Open.
   */
  struct Write
  {
    enum class State {
      Off,
      On,
    } state;
    
    const uint8_t *data;
    std::size_t length;
    std::size_t nwritten;
    
    write_callback cb;
  } w;

  /*
   * Read state data. Note that we can read when the overarching
   * state is Connected, Handshaking or Open.
   */
  struct Read
  {
    enum class State {
      Off,
      Once,
      Continuous,
    } state;
    
    std::array<uint8_t, 8192> buffer;
    std::size_t length;
    std::size_t nread;
    
    read_callback cb;
  } r;

  /*
   * Connect state data
   */
  struct Connect
  {
    connect_callback cb;
  } c;
  
  /*
   * Handshake state data
   */
  struct Handshake
  {
    handshake_callback cb;
  } h;
  
  bool server; /* True iff socket accepted by a listen socket */
  
  SSLContext &ctx;

  c_unique_ptr<PRFileDesc> fd;

  /*
   * Called when the socket is connecting and has signaled that it
   * is ready to continue.
   */
  void _connectContinue(PRInt16 out_flags);
  
  /*
   * Called when the socket is handhaking and has signaled that it
   * is ready to continue.
   */
  void _handshake();
  
  /*
   * Called when the socket is ready for read.
   */
  void _read();
  
  /*
   * Called when the socket is ready for writing.
   */
  void _write();
  
  /*
   * Signal to the context event loop that we have things to do.
   */
  void signal();

public:

  inline PRFileDesc *fileDesc() { return fd.get(); };

  Socket(c_unique_ptr<PRFileDesc> fd, bool server, SSLContext &ctx);

  /*
   * Connect to the specified address.
   */
  void connect(PRNetAddr *addr, connect_callback cb = nullptr);

  /*
   * Perform a TLS handshake.
   */
  void handshake(handshake_callback cb = nullptr);

  /*
   * Read a fixed-length packet.
   */
  void readOnce(std::size_t length, read_callback cb);

  /*
   * Read indefinitely.
   */
  void read(read_callback cb);

  /*
   * Write.
   */
  void write(const uint8_t *data, std::size_t length,
    write_callback cb = nullptr);

  /*
   * Close the socket.
   */
  void close(boost::system::error_code ec = boost::system::error_code());

  /*
   * Returns true iff there is data to be written.
   */
  bool isWriting() const;
  
  /*
   * Returns true iff we are ready to listen for reads.
   */
  bool isReading() const;
  
  SSLContext &context();
  
};

}

#endif
