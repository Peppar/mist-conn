#ifndef __MIST_HEADERS_TOR_TOR_HPP__
#define __MIST_HEADERS_TOR_TOR_HPP__

#include <cstddef>
#include <functional>
#include <list>
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

class ProcessArguments
{
private:

  std::list<std::string> _data;
  std::vector<char *> _argv;
  std::vector<char *> _envp;

public:

  void addArgument(std::string arg)
  {
    _data.push_back(std::move(arg));
    _argv.push_back(const_cast<char*>((--_data.end())->c_str()));
  }

  void addEnvironment(std::string env)
  {
    _data.push_back(std::move(env));
    _envp.push_back(const_cast<char*>((--_data.end())->c_str()));
  }

  char *const *argv()
  {
    _argv.push_back(nullptr);
    return _argv.data();
  }

  char *const *envp()
  {
    _envp.push_back(nullptr);
    return _envp.data();
  }
};

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

  using process_exit_callback = std::function<void(std::int32_t exitCode)>;

  void start(boost::system::error_code &ec, std::uint16_t socksPort,
             std::uint16_t ctrlPort, process_exit_callback cb);

  void stop();

  bool isRunning() const;

  TorHiddenService &addHiddenService(std::uint16_t port, std::string name);
  
};

} // namespace tor
} // namespace mist

#endif
