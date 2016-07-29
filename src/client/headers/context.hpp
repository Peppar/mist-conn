#ifndef __MIST_CONTEXT_HPP__
#define __MIST_CONTEXT_HPP__

#include <cstddef>

//#include <algorithm>
//#include <cassert>
//#include <iostream>
#include <string>
#include <memory>
//#include <vector>
#include <list>

/* NSPR Headers */
//#include <nspr.h>
//#include <prthread.h>
//#include <plgetopt.h>
//#include <prerror.h>
//#include <prinit.h>
//#include <prlog.h>
#include <prtypes.h>
//#include <plstr.h>
//#include <prio.h>
//#include <prnetdb.h>
//#include <prinrval.h>

/* NSS headers */
#include <keyhi.h>
#include <pk11priv.h>
#include <pk11pub.h>
#include <pkcs11t.h>

//#include <base64.h>

#include <nss.h>
#include <ssl.h>
//#include <sslerr.h>
//#include <secerr.h>
#include <secmod.h>
#include <secitem.h>
#include <secport.h>
#include <sslproto.h>
#include <certdb.h>
#include <cert.h>
#include <certt.h>

//#include <secasn1.h>

#include <boost/optional.hpp>

#include "memory/nss.hpp"

namespace mist
{

class Socket;

class RdvSocket
{
public:

  using connection_callback = std::function<void(Socket&)>;

private:

  friend class SSLContext;

  c_unique_ptr<PRFileDesc> fd;
  
  connection_callback cb;

public:

  RdvSocket(c_unique_ptr<PRFileDesc> fd, connection_callback cb);

  /* Accepts a connection from the rendez-vous socket */
  c_unique_ptr<PRFileDesc> accept();
};

class SSLContext
{
public:

  using connection_callback = std::function<void(Socket&)>;

private:

  friend class Socket;

  const char *nickname;
  
  c_unique_ptr<PRFileDesc> signalEvent;

  std::list<RdvSocket> rdvSocks;
  std::list<Socket> sslSocks;

  /* Initialize NSS with the given database directory */
  void initializeNSS(std::string dbdir);
  
  /* Upgrades the NSPR socket to an SSL socket */
  void initializeSecurity(c_unique_ptr<PRFileDesc> &fd);
  
  /* Initialize the socket with mist TLS settings */
  void initializeTLS(Socket &sock);
  
  /* Opens a non-blocking socket */
  c_unique_ptr<PRFileDesc> openSocket();

  /* Opens, binds a non-blocking SSL rendez-vous socket listening to the
     specified port */
  c_unique_ptr<PRFileDesc> openRdvSocket(std::uint16_t port,
                                         std::size_t backlog = 16);

  /* Accepts a socket from the specified rendez-vous socket */
  void accept(RdvSocket &rdvSock);

  /* Main event loop */
  void eventLoop();

  /* Called when NSS wants to get the client certificate */
  SECStatus getClientCert(Socket &socket, CERTDistNames *caNames,
                          CERTCertificate **pRetCert,
                          SECKEYPrivateKey **pRetKy);
  
  /* Called when NSS wants to authenticate the peer certificate */
  SECStatus authCertificate(Socket &socket, PRBool checkSig, PRBool isServer);

  /* Called when NSS wants us to supply a password */
  boost::optional<std::string> getPassword(Socket &socket, PK11SlotInfo *info,
                                           PRBool retry);

public:

  SSLContext(const char *nickname);

  void serve(std::uint16_t servPort, connection_callback cb);

  void exec();

  Socket &openClientSocket();

  void signal();
};

}

#endif
