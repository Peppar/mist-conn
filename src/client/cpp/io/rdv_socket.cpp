#include <cstddef>

#include <boost/optional.hpp>
#include <boost/system/error_code.hpp>
#include <boost/system/system_error.hpp>
#include <boost/throw_exception.hpp>

#include "io/io_context.hpp"
#include "io/rdv_socket.hpp"
#include "io/socket.hpp"
#include "io/ssl_socket.hpp"

#include "error/nss.hpp"

namespace mist
{
namespace io
{

/*
 * Rendez-vous socket
 */
RdvSocket::RdvSocket(SSLContext &sslCtx, c_unique_ptr<PRFileDesc> fd,
                     connection_callback cb)
  : _sslCtx(sslCtx), _fd(std::move(fd)), _cb(std::move(cb)), _open(true)
  {}

IOContext &
RdvSocket::ioCtx()
{
  return sslCtx().ioCtx();
}

SSLContext &
RdvSocket::sslCtx()
{
  return _sslCtx;
}

PRFileDesc *
RdvSocket::fileDesc()
{
  return _fd.get();
}

boost::optional<PRInt16>
RdvSocket::inFlags() const
{
  if (_open)
    return PR_POLL_READ|PR_POLL_EXCEPT;
  else
    return boost::none;
}

void
RdvSocket::process(PRInt16 inFlags, PRInt16 outFlags)
{
  if (outFlags & PR_POLL_EXCEPT) {
    //std::cerr << "Rdv socket PR_POLL_EXCEPT" << std::endl;
    _open = false;
  } else if (outFlags & PR_POLL_READ) {
    //std::cerr << "Rdv socket PR_POLL_READ" << std::endl;
    
    /* Accept the incoming connection */
    c_unique_ptr<PRFileDesc> acceptedFd =
      to_unique(PR_Accept(fileDesc(), nullptr, PR_INTERVAL_NO_TIMEOUT));
    if (!acceptedFd)
      BOOST_THROW_EXCEPTION(boost::system::system_error(make_nss_error(),
        "Unable to accept incoming connection"));
    
    auto socket = std::make_shared<SSLSocket>(sslCtx(), std::move(acceptedFd),
                                              true);

    ioCtx().addDescriptor(socket);

    _cb(std::move(socket));
  }
}

} // namespace io
} // namespace mist
