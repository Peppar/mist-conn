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
#include <prrng.h>

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
#include <boost/exception/diagnostic_information.hpp> 
#include <boost/generator_iterator.hpp>
#include <boost/optional.hpp>
#include <boost/random.hpp>
#include <boost/random/random_device.hpp>

#include "error/mist.hpp"
#include "error/nss.hpp"
#include "memory/nss.hpp"
#include "context.hpp"
#include "socket.hpp"

#include "h2/session.hpp"
#include "h2/stream.hpp"
#include "h2/client_request.hpp"
#include "h2/client_response.hpp"
#include "h2/server_request.hpp"
#include "h2/server_response.hpp"

namespace
{

std::string generateRandomId(std::size_t numDwords)
{
  std::vector<uint32_t> out(numDwords);
  boost::random::random_device rng;
  rng.generate(out.begin(), out.end());
  return std::string((const char *)out.data(), 4 * out.size());
}

std::string to_hex(uint8_t byte)
{
  std::array<char, 2> text{"0123456789abcdef"[byte >> 4],
                           "0123456789abcdef"[byte & 0xf]};
  return std::string(text.begin(), text.end());
}

std::string to_hex(SECItem *item)
{
  std::string text;
  for (std::size_t n = 0; n < item->len; ++n)
  {
    text += to_hex(item->data[n]);
  }
  return text;
}

}

/*
 * Try to perform a SOCKS5 handshake to connect to the given
 * domain name and port.
 */
void handshakeSOCKS5(mist::Socket &sock,
  std::string hostname, uint16_t port,
  std::function<void(std::string, boost::system::error_code)> cb)
{
  std::array<uint8_t, 4> socksReq;
  socksReq[0] = 5; /* Version */
  socksReq[1] = 1;
  socksReq[2] = 0;
  socksReq[3] = 2;

  sock.write(socksReq.data(), socksReq.size());

  sock.readOnce(2,
    [=, &sock, cb(std::move(cb))]
    (const uint8_t *data, std::size_t length, boost::system::error_code ec) mutable
  {
    if (ec) {
      cb("", ec);
      return;
    }
    if (length != 2 || data[0] != 5 || data[1] != 0) {
      cb("", mist::make_mist_error(mist::MIST_ERR_SOCKS_HANDSHAKE));
      return;
    }
    
    /* Construct the SOCKS5 connect request */
    std::vector<uint8_t> connReq(5 + hostname.length() + 2);
    {
      auto outIt = connReq.begin();
      *(outIt++) = 5; /* Version */
      *(outIt++) = 1; /* Connect */
      *(outIt++) = 0; /* Must be zero */
      *(outIt++) = 3; /* Resolve domain name */
      *(outIt++) = uint8_t(hostname.length()); /* Domain name length */
      outIt = std::copy(hostname.begin(), hostname.end(), outIt); /* Domain name */
      *(outIt++) = uint8_t((port >> 8) & 0xff); /* Port MSB */
      *(outIt++) = uint8_t(port & 0xff); /* Port LSB */
      /* Make sure that we can count */
      assert (outIt == connReq.end());
    }
    
    sock.write(connReq.data(), connReq.size());
    
    /* Read 5 bytes; these are all the bytes we need to determine the
       final packet size */
    sock.readOnce(5,
      [=, &sock, cb(std::move(cb))]
      (const uint8_t *data, std::size_t length, boost::system::error_code ec) mutable
    {
      if (ec) {
        cb("", ec);
        return;
      }
      if (length != 5 || data[0] != 5 || data[1] != 0) {
        cb("", mist::make_mist_error(mist::MIST_ERR_SOCKS_HANDSHAKE));
        return;
      }
      
      uint8_t type = data[3];
      uint8_t firstByte = data[4];
      
      std::size_t complLength;
      if (type == 1)
        complLength = 10 - 5;
      else if (type == 3)
        complLength = 7 + firstByte - 5;
      else if (type == 4)
        complLength = 22 - 5;
      else {
        cb("", mist::make_mist_error(mist::MIST_ERR_SOCKS_HANDSHAKE));
        return;
      }
      
      sock.readOnce(complLength,
        [=, &sock, cb(std::move(cb))]
        (const uint8_t *data, std::size_t length, boost::system::error_code ec) mutable
      {
        if (ec) {
          cb("", ec);
          return;
        }
        if (complLength != length) {
          cb("", mist::make_mist_error(mist::MIST_ERR_SOCKS_HANDSHAKE));
          return;
        }
        
        std::string address;
        if (type == 1)
          address = std::to_string(firstByte) + '.'
            + std::to_string(data[0]) + '.'
            + std::to_string(data[1]) + '.'
            + std::to_string(data[2]) + ':'
            + std::to_string((data[3] << 8) | data[4]);
        else if (type == 3)
          address = std::string((const char*)data, firstByte) + ':'
            + std::to_string((data[firstByte] << 8) | data[firstByte + 1]);
        else if (type == 4)
          address = to_hex(firstByte) + to_hex(data[0]) + ':'
            + to_hex(data[1]) + to_hex(data[2]) + ':'
            + to_hex(data[3]) + to_hex(data[4]) + ':'
            + to_hex(data[5]) + to_hex(data[6]) + ':'
            + to_hex(data[7]) + to_hex(data[8]) + ':'
            + to_hex(data[9]) + to_hex(data[10]) + ':'
            + to_hex(data[11]) + to_hex(data[12]) + ':'
            + to_hex(data[13]) + to_hex(data[14]) + ':'
            + std::to_string((data[15] << 8) | data[16]);
        assert (address.length());
        cb(address, boost::system::error_code());
      });
    });
  });
}

/*
 * Connect the socket through a local Tor SOCKS5 proxy.
 */
void connectTor(mist::Socket &sock, uint16_t torPort,
  std::string hostname, uint16_t port,
  std::function<void(std::string, boost::system::error_code)> cb)
{
  /* Initialize addr to localhost:torPort */
  PRNetAddr addr;
  if (PR_InitializeNetAddr(PR_IpAddrLoopback, torPort, &addr) != PR_SUCCESS) {
    cb("", mist::make_nss_error());
    return;
  }

  sock.connect(&addr,
    [=, &sock, cb(std::move(cb))]
    (boost::system::error_code ec) mutable
  {
    if (ec) {
      cb("", ec);
      return;
    }
    handshakeSOCKS5(sock, std::move(hostname), port, std::move(cb));
  });
}

