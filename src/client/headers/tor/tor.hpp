#ifndef __MIST_HEADERS_TOR_TOR_HPP__
#define __MIST_HEADERS_TOR_TOR_HPP__

#include <cstddef>
#include <functional>
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

class TorController
{
private:

  io::IOContext &_ioCtx;
  std::string _execName;
  std::string _workingDir;

  std::list<TorHiddenService> _hiddenServices;

  c_unique_ptr<PRProcess> _torProcess;

  c_unique_ptr<PRFileDesc> _outLogFile;

public:

  TorController(io::IOContext &ioCtx, std::string execName,
                std::string workingDir);

  void start(boost::system::error_code &ec, std::uint16_t socksPort,
             std::uint16_t ctrlPort);

  void stop();

  bool isRunning() const;

  TorHiddenService &addHiddenService(std::uint16_t port, std::string name);
  
};

} // namespace tor
} // namespace mist

#endif
