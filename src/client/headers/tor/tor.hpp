#ifndef __MIST_HEADERS_TOR_TOR_HPP__
#define __MIST_HEADERS_TOR_TOR_HPP__

#include <cstddef>
#include <functional>
#include <list>
#include <memory>
#include <string>
#include <vector>

#include <boost/optional.hpp>
#include <boost/system/error_code.hpp>

#include "memory/nss.hpp"

#include "io/io_context.hpp"

namespace mist
{

class SSLContext;

namespace tor
{

class TorController;

class TorHiddenService
{
private:

  io::IOContext &_ioCtx;
  TorController &_ctrl;
  
  std::uint16_t _port;
  std::string _path;
  boost::optional<std::string> _onionAddress;

  boost::optional<const std::string &> tryGetOnionAddress();
  
public:

  using onion_address_callback = std::function<void(const std::string&)>;

  TorHiddenService(io::IOContext &ioCtx, TorController &ctrl,
                   std::uint16_t port, std::string path);

  std::uint16_t port() const;
  const std::string &path() const;
  void onionAddress(onion_address_callback cb);

};

class TorController : public std::enable_shared_from_this<TorController>
{
private:

  io::SSLContext &_sslCtx;
  std::string _execName;
  std::string _workingDir;
  std::uint16_t _socksPort;
  std::uint16_t _ctrlPort;
  std::string _password;

  std::list<TorHiddenService> _hiddenServices;

  c_unique_ptr<PRProcess> _torProcess;
#if !(defined(_WIN32)||defined(_WIN64))
  c_unique_ptr<PRFileDesc> _torLogFile;
#endif

  std::vector<std::string> _bridges;

  std::string _pendingResponse;
  std::shared_ptr<io::Socket> _ctrlSocket;

  void connectControlPort();

  void torProcessExit(std::int32_t exitCode);

  void sendCommand(std::string cmd);

  void readResponse(const std::uint8_t *data, std::size_t length,
    boost::system::error_code ec);

public:

  TorController(io::SSLContext &sslCtx, std::string execName,
                std::string workingDir);

  using process_exit_callback = std::function<void(std::int32_t exitCode)>;

  void start(std::uint16_t socksPort, std::uint16_t ctrlPort);

  void stop();

  bool isRunning() const;

  TorHiddenService &addHiddenService(std::uint16_t port, std::string name);
  
};

} // namespace tor
} // namespace mist

#endif
