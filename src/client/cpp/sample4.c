/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

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
#include <boost/optional.hpp>
#include <boost/random.hpp>
#include <boost/random/random_device.hpp>
#include <boost/generator_iterator.hpp>

#include "nss_memory.h"
#include "context.hpp"
#include "socket.hpp"

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
  std::function<void(std::string)> cb)
{
  std::array<uint8_t, 4> socksReq;
  socksReq[0] = 5; /* Version */
  socksReq[1] = 1;
  socksReq[2] = 0;
  socksReq[3] = 2;

  sock.write(mist::Socket::createProvider(socksReq.data(), socksReq.size()));

  sock.readOnce(2,
    [=, &sock, cb(std::move(cb))]
    (const uint8_t *data, std::size_t length) mutable
  {
    if (length != 2) {
      std::cerr << "Invalid packet length returned" << std::endl;
      cb("");
      return; /* Invalid packet length read */
    }
    if (data[0] != 5) {
      std::cerr << "Wrong SOCKS version" << std::endl;
      cb("");
      return; /* Wrong version */
    }
    if (data[1] != 0) {
      std::cerr << "Authentication needed" << std::endl;
      cb("");
      return; /* Authentication needed */
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
    
    sock.write(mist::Socket::createProvider(connReq.data(), connReq.size()));
    
    /* Read 5 bytes; these are all the bytes we need to determine the
       final packet size */
    sock.readOnce(5,
      [=, &sock, cb(std::move(cb))]
      (const uint8_t *data, std::size_t length)
    {
      if (length != 5) {
        std::cerr << "Invalid packet length returned" << std::endl;
        cb("");
        return;
      }
      if (data[0] != 5) {
        std::cerr << "Wrong SOCKS version" << std::endl;
        cb("");
        return;
      }
      if (data[1] != 0) {
        std::cerr << "Connection error" << std::endl;
        cb("");
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
        std::cerr << "SOCKS type unknown" << std::endl;
        cb("");
        return;
      }
      
      sock.readOnce(complLength,
        [=, &sock, cb(std::move(cb))]
        (const uint8_t *data, std::size_t length) mutable
      {
        if (complLength != length) {
          std::cerr << "Invalid packet length returned" << std::endl;
          cb("");
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
        cb(address);
      });
    });
  });
}

/*
 * Connect the socket through a local Tor SOCKS5 proxy.
 */
void connectTor(mist::Socket &sock, uint16_t torPort,
  std::string hostname, uint16_t port,
  std::function<void(std::string)> cb)
{
  /* Initialize addr to localhost:torPort */
  PRNetAddr addr;
  if (PR_InitializeNetAddr(PR_IpAddrLoopback, torPort, &addr) != PR_SUCCESS)
    throw new std::runtime_error("PR_InitializeNetAddr failed");

  sock.connect(addr,
    [=, &sock, cb(std::move(cb))]
    (bool success) mutable
  {
    if (!success) {
      cb("");
      std::cerr << "Failed to connect" << std::endl;
      return;
    }
    handshakeSOCKS5(sock, std::move(hostname), port, std::move(cb));
      // [=, &sock, cb(std::move(cb))]
      // (std::string address) mutable
    // {
      // if (address.empty()) {
        // cb("");
        // std::cerr << "Failed to SOCKS5 connect" << std::endl;
        // return;
      // }
      // std::cerr << "SOCKS5 connected to " << address << std::endl;
      // cb(std::move(address));
    // });
  });
}

int
main(int argc, char **argv)
{
  //nss_init("db");
  try {
    assert(argc == 3);
    bool isServer = atoi(argv[1]);
    char *nickname = argv[2];
    int port = isServer ? 9150 : 9151;
    
    mist::SSLContext sslCtx(nickname);
    
    sslCtx.serve(port,
      [](mist::Socket &sock)
    {
      std::cerr << "New connection !!! " << std::endl;
      sock.handshake(
        [&sock](bool success)
      {
        std::cerr << "Handshaked! " << success << std::endl;
        auto sessionId = to_unique(SSL_GetSessionID(sock.fileDesc()));
        std::cerr << "Session ID = " << to_hex(sessionId.get()) << std::endl;
        const uint8_t *data = (const uint8_t *)"Hus";
        sock.write(data, 3);
        sock.readContinuous(
          [&sock](const uint8_t *data, std::size_t length)
        {
          std::cerr << "Server received " << std::string((const char*)data, length) << std::endl;
        });
      });
    });
    
    if (!isServer) {
      // Try connect
      PRNetAddr addr;
      if (PR_InitializeNetAddr(PR_IpAddrLoopback, 9150, &addr) != PR_SUCCESS)
        throw new std::runtime_error("PR_InitializeNetAddr failed");
      mist::Socket &sock = sslCtx.openClientSocket();
      std::cerr << "Trying to connect..." << std::endl;
      sock.connect(addr,
        [&sock](bool success)
      {
        if (success) {
          std::cerr << "Connected! Initializing TLS..:" << std::endl;
          sock.handshake(
            [&sock](bool success)
          {
            std::cerr << "Handshaked! " << success << std::endl;
            auto sessionId = to_unique(SSL_GetSessionID(sock.fileDesc()));
            std::cerr << "Session ID = " << to_hex(sessionId.get()) << std::endl;

            const uint8_t *data = (const uint8_t *)"Hoj";
            sock.write(data, 3);
            sock.readContinuous(
              [&sock](const uint8_t *data, std::size_t length)
            {
              std::cerr << "Client received " << std::string((const char*)data, length) << std::endl;
            });
          });
        } else {
          std::cerr << "Client could not connect!" << std::endl;
        }
      });
    }

    sslCtx.exec();
    //ventLoop(port, nickname, isServer ? 0 : 9150);
    //auto cert = createRootCert(privk, pubk, hashAlgTag, );
    // if (isServer) {
      // std::cerr << "Server" << std::endl;
      // server(nickname);
    // } else {
      // std::cerr << "Client" << std::endl;
      // client(nickname);
    // }
  } catch(const std::exception *e) {
     std::cerr << e->what() << std::endl;
     throw;
  }
}
