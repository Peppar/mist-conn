#include <cstddef>
#include <functional>
#include <string>
#include <sstream>
#include <vector>

#include <iostream>

#include <boost/filesystem.hpp>
#include <boost/optional.hpp>
#include <boost/random/random_device.hpp>
#include <boost/system/error_code.hpp>
#include <boost/system/system_error.hpp>
#include <boost/throw_exception.hpp>

#include <prproces.h>

#include "error/mist.hpp"
#include "error/nss.hpp"
#include "io/file_descriptor.hpp"
#include "io/io_context.hpp"
#include "memory/nss.hpp"
#include "tor/tor.hpp"

namespace mist
{
namespace tor
{

/*
 * TorHiddenService
 */
TorHiddenService::TorHiddenService(io::IOContext &ioCtx, TorController &ctrl,
                                   std::uint16_t port, std::string path)
  : _ioCtx(ioCtx), _ctrl(ctrl), _port(port), _path(path)
  {}

std::uint16_t
TorHiddenService::port() const
{
  return _port;
}

const std::string &
TorHiddenService::path() const
{
  return _path;
}

boost::optional<const std::string &>
TorHiddenService::tryGetOnionAddress()
{
  if (_onionAddress)
    return *_onionAddress;

  /* Try to read the hostname file */
  std::string hostnameFilename = path() + "/hostname";
  auto inFile = to_unique(PR_Open(hostnameFilename.c_str(), PR_RDONLY, 0));
  if (inFile) {
    std::array<std::uint8_t, 128> buf;
    std::size_t nread = 0;
    
    while (1) {
      auto n
        = PR_Read(inFile.get(), reinterpret_cast<void*>(buf.data() + nread),
                  buf.size() - nread);
      if (n < 0) {
        return boost::none;
      } else if (n == 0) {
        std::string hostname;
        std::copy_if(buf.data(), buf.data() + nread,
                     std::back_inserter(hostname),
                     [](const char c){ return c != '\n' && c != '\r'; });
        _onionAddress = std::move(hostname);
        return *_onionAddress;
      } else {
        nread += n;
      }
    }
  }
  return boost::none;
}

void
TorHiddenService::onionAddress(onion_address_callback cb)
{
  auto addr = tryGetOnionAddress();
  if (addr) {
    cb(*addr);
  } else {
    _ioCtx.setTimeout(1000, std::bind(&TorHiddenService::onionAddress, this,
                                     std::move(cb)));
  }
}

/*
 * TorController
 */
TorController::TorController(io::IOContext &ioCtx, std::string execName,
                             std::string workingDir)
  : _ioCtx(ioCtx), _execName(execName), _workingDir(workingDir)
  {}

namespace
{

std::string
to_hex(uint8_t byte)
{
  static const char *digits = "0123456789abcdef";
  std::array<char, 2> text{ digits[byte >> 4], digits[byte & 0xf] };
  return std::string(text.begin(), text.end());
}

template<typename It>
std::string
to_hex(It begin, It end)
{
  std::string text;
  while (begin != end)
    text += to_hex(uint8_t(*(begin++)));
  return text;
}

std::string
to_hex(std::string str)
{
  return to_hex((uint8_t *)str.data(), (uint8_t *)(str.data() + str.size()));
}

std::string
generateRandomId(std::size_t numDwords)
{
  std::vector<std::uint32_t> out(numDwords);
  boost::random::random_device rng;
  rng.generate(out.begin(), out.end());
  return std::string(reinterpret_cast<const char *>(out.data()),
    4 * out.size());
}

std::string
generateRandomHexString(std::size_t numBytes)
{
  return to_hex(generateRandomId((numBytes + 3) / 4)).substr(0, 2 * numBytes);
}

std::string
readAll(PRFileDesc *fd)
{
  std::array<char, 80> buf;
  std::string out;
  while (1) {
    auto n = PR_Read(fd, buf.data(), buf.size());
    if (n <= 0)
      break;
    out += std::string(buf.data(), buf.data() + n);
  }
  return out;
}

void
writeAll(PRFileDesc *fd, std::string contents)
{
  std::size_t nwritten = 0;
  while (1) {
    auto n = PR_Write(fd, contents.data() + nwritten,
      contents.length() - nwritten);
    if (n < 0) {
      BOOST_THROW_EXCEPTION(boost::system::system_error(make_nss_error(),
        "Unable to write to torrc file"));
    }
    else {
      nwritten += n;
      if (nwritten == contents.length())
        break;
    }
  }
}

bool
isCrlf(char c)
{
  return c == '\n' || c == '\r';
};

} // namespace

void
TorController::runTorProcess(std::vector<std::string> processArgs,
  std::function<void(std::int32_t)> cb)
{
  boost::filesystem::path workingDir(_workingDir);

  _ioCtx.queueJob([=]() mutable
  {
    /* Due to difficulties with redirecting Tor's STDOUT/STDERR,
    we need to use a launchpad script to recover its output */
    std::string executable;
    {
#if defined(_WIN32)||defined(_WIN64)
      std::string launchpadName = "launchpad.cmd";
#else
      std::string launchpadName = "launchpad.sh";
#endif
      auto launchpadPath
        = boost::filesystem::path(workingDir) / launchpadName;

      executable = launchpadPath.string();

      processArgs.insert(processArgs.begin(), _execName);
      processArgs.insert(processArgs.begin(), executable);
    }

    /* Convert arguments to argv format */
    std::vector<char *> argv;
    {
      for (auto &arg : processArgs) {
        argv.push_back(const_cast<char *>(arg.c_str()));
      }
      argv.push_back(nullptr);
    }

    /* Process attributes */
    auto attr = to_unique(PR_NewProcessAttr());
    {
      PR_ProcessAttrSetCurrentDirectory(attr.get(), _workingDir.c_str());
    }

    /* Create the process */
    {
      _torProcess = to_unique(PR_CreateProcess(executable.c_str(),
        argv.data(), nullptr, attr.get()));

      if (!_torProcess)
        BOOST_THROW_EXCEPTION(boost::system::system_error(make_nss_error(),
          "Unable to launch tor process"));
    }

    /* Wait for the process to finish */
    {
      PRInt32 exitCode = 0xCCCCCCCC;
      /* Release the process pointer here, PR_WaitProcess takes care of it */
      PR_WaitProcess(_torProcess.release(), &exitCode);
      cb(exitCode);
    }
  });
}

void
TorController::start(std::uint16_t socksPort, std::uint16_t ctrlPort)
{
  _socksPort = socksPort;
  _ctrlPort = ctrlPort;

  _password = generateRandomHexString(32);

  boost::filesystem::path workingDir(_workingDir);

  /* Launch tor to create the password hash */
  runTorProcess({"--hash-password", _password, "--quiet"},
    [=, anchor(shared_from_this())](std::int32_t exitCode)
  {
    if (exitCode) {
      std::cerr << "Tor process exited unexpectedly with exitCode " << exitCode
        << " when hashing password" << std::endl;
      return;
      //BOOST_THROW_EXCEPTION(boost::system::system_error(make_nss_error(),
      //  "Unable to launch Tor to hash the password"));
    }

    /* Read the password hash */
    auto logPath = workingDir / "out.log";
    std::string passwordHash;
    {
      auto logFile = to_unique(PR_Open(logPath.string().c_str(),
        PR_RDONLY, 0));
      if (!logFile)
        BOOST_THROW_EXCEPTION(boost::system::system_error(make_nss_error(),
          "Unable to open log file for reading hashed password"));
      passwordHash = readAll(logFile.get());

      /* Remove CR/LF */
      passwordHash.erase(std::remove_if(passwordHash.begin(),
        passwordHash.end(), isCrlf), passwordHash.end());
        
      /* Make sure that the password hash was created */
      if (passwordHash.empty()) {
      BOOST_THROW_EXCEPTION(boost::system::system_error(
        make_mist_error(MIST_ERR_ASSERTION),
        "Log file contains nothing"));
      }
    }

    /* Construct the contents of the torrc file */
    std::string torrcContents;
    {
      auto torDataDir = workingDir / "tordata";
      std::ostringstream buf;
      buf << "SocksPort " << socksPort << std::endl;
      buf << "ControlPort " << ctrlPort << std::endl;
      buf << "DataDirectory " << torDataDir.string() << std::endl;
      buf << "HashedControlPassword " << passwordHash << std::endl;

      /* Bridge configuration */
      if (_bridges.size()) {
        buf << "UseBridges 1" << std::endl;
        for (auto &bridge : _bridges) {
          buf << "Bridge " << bridge << std::endl;
        }
      }

      for (auto &hiddenService : _hiddenServices) {
        buf << "HiddenServiceDir " << hiddenService.path() << std::endl;
        buf << "HiddenServicePort 443"
          << " 127.0.0.1:" << hiddenService.port() << std::endl;
      }

      torrcContents = buf.str();
    }

    /* Write contents to the torrc file */
    boost::filesystem::path torrcPath(workingDir / "torrc");
    {
      auto rcFile = to_unique(PR_Open(torrcPath.string().c_str(),
        PR_WRONLY|PR_CREATE_FILE|PR_TRUNCATE, PR_IRUSR|PR_IWUSR));
      
      if (!rcFile)
        BOOST_THROW_EXCEPTION(boost::system::system_error(make_nss_error(),
          "Unable to open torrc file for reading"));

      writeAll(rcFile.get(), torrcContents);
      
      if (PR_Sync(rcFile.get()) != PR_SUCCESS)
        BOOST_THROW_EXCEPTION(boost::system::system_error(make_nss_error(),
          "Unable to sync file"));
    }

    /* Launch Tor for real this time */
    {
      using namespace std::placeholders;
      runTorProcess({"-f", torrcPath.string()},
        std::bind(&TorController::torProcessExit, this, _1));
    }

    connectControlPort();

  });
}

void
TorController::torProcessExit(std::int32_t exitCode)
{
  /* Close the control socket */
  if (_ctrlSocket)
    _ctrlSocket->close();

  /* TODO: Inform about the exit */
  std::cerr << "Tor process exited with exit code " << exitCode << std::endl;
}

void
TorController::sendCommand(std::string cmd)
{
  assert(_ctrlSocket);

  cmd += "\r\n";
  _ctrlSocket->write(reinterpret_cast<const std::uint8_t*>(cmd.c_str()),
    cmd.length(),
    [=, anchor(shared_from_this())]
  (std::size_t nwritten, boost::system::error_code ec)
  {
    if (ec) {
      std::cerr << "Error while writing to control socket" << std::endl;
      return;
    }
    std::cerr << "Wrote authenticate " << nwritten << std::endl;
  });
}

void
TorController::readResponse(const std::uint8_t *data, std::size_t length,
  boost::system::error_code ec)
{
  auto begin = data;
  auto end = data + length;
  
  while (1) {
    auto crlfPos = std::find_if(begin, end, isCrlf);
    _pendingResponse += std::string(begin, crlfPos);
  
    /* No CR/LF found; store the text for the next read */
    if (crlfPos == end)
      break;
  
    /* Non-empty line found*/
    if (!_pendingResponse.empty())
      std::cerr << "Tor said: " << _pendingResponse << std::endl;
  
    /* Start a new line */
    _pendingResponse.clear();
    begin = std::next(crlfPos);
  }
}

void
TorController::connectControlPort()
{
  _ctrlSocket = _ioCtx.openSocket();

  /* Bind the address */
  PRNetAddr addr;
  {
    PR_InitializeNetAddr(PR_IpAddrLoopback, _ctrlPort, &addr);
  }

  /* Connect */
  _ctrlSocket->connect(&addr,
    [=, anchor(shared_from_this())]
    (boost::system::error_code ec)
  {
    std::cerr << "Trying to connect to the Tor control port" << std::endl;

    /* Unable to connect; retry */
    if (ec) {
      _ioCtx.setTimeout(1000,
        std::bind(&TorController::connectControlPort, this));
      return;
    }

    /* Set the socket read callback */
    {
      using namespace std::placeholders;
      _ctrlSocket->read(std::bind(&TorController::readResponse, this,
        _1, _2, _3));
    }
    
    /* Authenticate with our password */
    sendCommand("AUTHENTICATE \"" + _password + "\"");
  });
}

void
TorController::stop()
{
  _torProcess = nullptr;
}

bool
TorController::isRunning() const
{
  return static_cast<bool>(_torProcess);
}

TorHiddenService &
TorController::addHiddenService(std::uint16_t port, std::string name)
{
  boost::filesystem::path workingDir(_workingDir);
  _hiddenServices.emplace_back(_ioCtx, *this, port,
    (workingDir / name).string());
  return *(--_hiddenServices.end());
}

namespace
{

using socks_callback
  = std::function<void(std::string, boost::system::error_code)>;

/* Try to perform a SOCKS5 handshake to connect to the given
domain name and port. */
void
handshakeSOCKS5(mist::io::TCPSocket &sock,
  std::string hostname, std::uint16_t port,
  socks_callback cb)
{
  std::array<std::uint8_t, 3> socksReq;
  socksReq[0] = 5; /* Version */
  socksReq[1] = 1;
  socksReq[2] = 0;

  sock.write(socksReq.data(), socksReq.size());

  sock.readOnce(2,
    [=, &sock, cb(std::move(cb))]
  (const std::uint8_t *data, std::size_t length,
    boost::system::error_code ec) mutable
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
    std::vector<std::uint8_t> connReq(5 + hostname.length() + 2);
    {
      auto outIt = connReq.begin();
      *(outIt++) = 5; /* Version */
      *(outIt++) = 1; /* Connect */
      *(outIt++) = 0; /* Must be zero */
      *(outIt++) = 3; /* Resolve domain name */
      *(outIt++) = static_cast<std::uint8_t>(hostname.length()); /* Domain name length */
      outIt = std::copy(hostname.begin(), hostname.end(), outIt); /* Domain name */
      *(outIt++) = static_cast<std::uint8_t>((port >> 8) & 0xff); /* Port MSB */
      *(outIt++) = static_cast<std::uint8_t>(port & 0xff); /* Port LSB */
                                                            /* Make sure that we can count */
      assert(outIt == connReq.end());
    }

    sock.write(connReq.data(), connReq.size());

    /* Read 5 bytes; these are all the bytes we need to determine the
    final packet size */
    sock.readOnce(5,
      [=, &sock, cb(std::move(cb))]
    (const std::uint8_t *data, std::size_t length,
      boost::system::error_code ec) mutable
    {
      if (ec) {
        cb("", ec);
        return;
      }
      if (length != 5 || data[0] != 5) {
        cb("", mist::make_mist_error(mist::MIST_ERR_SOCKS_HANDSHAKE));
        return;
      }

      bool success = data[1] == 0;
      std::uint8_t type = data[3];
      std::uint8_t firstByte = data[4];

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
      (const std::uint8_t *data, std::size_t length,
        boost::system::error_code ec) mutable
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
          address = std::string(reinterpret_cast<const char*>(data),
            firstByte) + ':'
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
        else {
          cb("", mist::make_mist_error(mist::MIST_ERR_SOCKS_HANDSHAKE));
          return;
        }
        assert(address.length());
        if (!success) {
          cb(address, mist::make_mist_error(mist::MIST_ERR_SOCKS_HANDSHAKE));
        } else {
          cb(address, boost::system::error_code());
        }
      });
    });
  });
}

} // namespace

void
TorController::connect(io::TCPSocket & socket, std::string hostname,
  std::uint16_t port, connect_callback cb)
{
  /* Initialize addr to localhost:torPort */
  PRNetAddr addr;
  if (PR_InitializeNetAddr(PR_IpAddrLoopback, _socksPort, &addr) != PR_SUCCESS) {
    cb(mist::make_nss_error());
    return;
  }

  socket.connect(&addr,
    [=, &socket, cb(std::move(cb)), anchor(shared_from_this())]
    (boost::system::error_code ec) mutable
  {
    if (ec) {
      cb(ec);
      return;
    }
    handshakeSOCKS5(socket, std::move(hostname), port,
      [=, cb(std::move(cb)), anchor(shared_from_this())]
      (std::string address, boost::system::error_code ec)
    {
      cb(ec);
    });
  });
}

} // namespace tor
} // namespace mist
