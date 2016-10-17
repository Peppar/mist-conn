#ifndef __MIST_HEADERS_IO_TCP_SOCKET_HPP__
#define __MIST_HEADERS_IO_TCP_SOCKET_HPP__

#include <algorithm>
#include <array>
#include <cassert>
#include <iostream>
#include <string>
#include <memory>
#include <mutex>
#include <vector>
#include <list>

#include <nspr.h>
#include <prerror.h>
#include <prtypes.h>
#include <prio.h>

#include <boost/optional.hpp>
#include <boost/system/error_code.hpp>

#include "memory/nss.hpp"
#include "io/file_descriptor.hpp"
#include "io/socket.hpp"

namespace mist
{
namespace io
{

class IOContext;

class TCPSocket : public Socket, public FileDescriptor
{
public:

  /* Callback types */
  using connect_callback = std::function<void(boost::system::error_code)>;
  using write_callback = std::function<void(std::size_t,
    boost::system::error_code)>;
  using read_callback = std::function<void(const uint8_t*, std::size_t,
    boost::system::error_code)>;

protected:

  IOContext &_ioCtx;

  c_unique_ptr<PRFileDesc> _fd;

  mutable std::recursive_mutex _mutex;

  /* The current overarching state of the socket */
  enum State {
    Unconnected, /* Not yet connected to an endpoint */
    Connecting,  /* Connecting to an endpoint */
    Open,        /* Connected to an endpoint (non-TLS) */
    Closed,      /* Closed */
    
    /* These are for SSL socket only */
    Handshaking, /* Performing TLS handshake */
    OpenTLS,     /* Connected to an endpoint, TLS */
  } _state;

  /* Write state data. */
  struct Write
  {
    enum class State {
      Off,
      On,
    } state;
    
    const uint8_t* data;
    std::size_t length;
    std::size_t nwritten;
    
    write_callback cb;
  } _w;

  /* Read state data. */
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
  } _r;

  /* Connect state data */
  struct Connect
  {
    connect_callback cb;
  } _c;

  /* Called when the socket is connecting and has signaled that it
     is ready to continue. */
  void connectContinue(PRInt16 out_flags);
  
  /* Called when the socket is ready for read. */
  void readReady();
  
  /* Called when the socket is ready for writing. */
  void writeReady();

  /* Signal to the context event loop that we have things to do. */
  void signal();
  
  /* Returns true iff there is data to be written. */
  bool isWriting() const;
  
  /* Returns true iff we are ready to listen for reads. */
  bool isReading() const;
  
public:

  TCPSocket(IOContext& ioCtx, c_unique_ptr<PRFileDesc> fd, bool isOpen);

  IOContext& ioCtx();
  
  /* Connect to the specified address. */
  void connect(PRNetAddr* addr, connect_callback cb = nullptr);

  /* Read a fixed-length packet. */
  virtual void readOnce(std::size_t length, read_callback cb) override;

  /* Read indefinitely. */
  virtual void read(read_callback cb) override;

  /* Write. */
  virtual void write(const uint8_t* data, std::size_t length,
                     write_callback cb = nullptr) override;

  /* Close the socket. */
  virtual void close(boost::system::error_code ec
    = boost::system::error_code()) override;

public:

  /* FileDescriptor interface implementation */
  virtual PRFileDesc* fileDesc() override;
  
  virtual boost::optional<PRInt16> inFlags() const override;
  
  virtual void process(PRInt16 inFlags, PRInt16 outFlags) override;

private:

  TCPSocket(TCPSocket&&) = delete;
  TCPSocket& operator=(TCPSocket&&) = delete;

};

} // namespace io
} // namespace mist

#endif
