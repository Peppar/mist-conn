#include <cstddef>
#include <functional>
#include <string>
#include <sstream>
#include <vector>

#include <iostream>

#include <boost/filesystem.hpp>
#include <boost/optional.hpp>
#include <boost/system/error_code.hpp>
#include <boost/system/system_error.hpp>
#include <boost/throw_exception.hpp>

#include <prproces.h>

#include "error/nss.hpp"
#include "io/file_descriptor.hpp"
#include "io/ssl_context.hpp"
#include "memory/nss.hpp"
#include "tor/tor.hpp"

namespace mist
{
namespace tor
{
  
class TorPrinter : public io::FileDescriptor
{
private:

  c_unique_ptr<PRFileDesc> _fd;

  std::array<std::uint8_t, 128> _buffer;
  
  std::size_t _nread;

public:
  
  TorPrinter(c_unique_ptr<PRFileDesc> fd)
    : _fd(std::move(fd)), _nread(0) {}

  /* FileDescriptor interface implementation */
  virtual PRFileDesc *fileDesc() override
  {
    return _fd.get();
  }
  
  virtual boost::optional<PRInt16> inFlags() const override
  {
    return PR_POLL_READ;
  }
  
  virtual void process(PRInt16 inFlags, PRInt16 outFlags) override
  {
    if (outFlags & PR_POLL_READ) {
      auto n = PR_Read(fileDesc(), _buffer.data() + _nread,
                       _buffer.size() - _nread);
      if (n < 0)
        BOOST_THROW_EXCEPTION(boost::system::system_error(make_nss_error(),
          "Unable to read from tor log file"));
      if (n == 0)
        BOOST_THROW_EXCEPTION(boost::system::system_error(make_nss_error(),
          "Tor log file EOF encountered"));
      _nread += n;
      //if (nread 
    }
  }

};

// void
// redirectProcessOutput()
// {
  // PRSocketOptionData sockOpt;
  // sockOpt.option = PR_SockOpt_Nonblocking;
  // sockOpt.value.non_blocking = PR_TRUE;
  // if (PR_SetSocketOption(fd.get(), &sockOpt) != PR_SUCCESS)
    // BOOST_THROW_EXCEPTION(boost::system::system_error(make_nss_error(),
      // "Unable to set PR_SockOpt_Nonblocking"));

 
// }

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
      std::size_t n
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
  : _ioCtx(ioCtx), _execName(execName), _workingDir(workingDir),
    _torProcess(to_unique<PRProcess>()),
    _outLogFile(to_unique<PRFileDesc>())
  {}

void
TorController::start(boost::system::error_code &ec, std::uint16_t socksPort,
                     std::uint16_t ctrlPort)
{
  ec.clear();
  
  /* TODO: Clean this up */
  boost::filesystem::path workingDir(_workingDir);

  /* Construct the contents of the torrc file */
  std::string torrcContents;
  {
    boost::filesystem::path torDataDir(workingDir / "tordata");
    std::ostringstream buf;
    buf << "SocksPort " << socksPort << std::endl;
    //buf << "ControlPort " << ctrlPort << std::endl;
    buf << "DataDirectory " << torDataDir.string() << std::endl;
    // of << "HashedControlPassword " << hashedCtrlPassword << std::endl;
    
    // /* Bridge configuration */
    // if (bridges.size()) {
      // of << "UseBridges 1" << std::endl;
      // for (auto &bridge : bridges) {
        // os << bridge << std::endl;
      // }
    // }
    
    for (auto &hiddenService : _hiddenServices) {
      buf << "HiddenServiceDir " << hiddenService.path() << std::endl;
      buf << "HiddenServicePort 443"
        << " localhost:" << hiddenService.port() << std::endl;
    }
    
    torrcContents = buf.str();
  }
  
  /* Write contents to the torrc file */
  boost::filesystem::path torrcPath(workingDir / "torrc");
  {
    auto rcFile = to_unique(PR_Open(torrcPath.string().c_str(),
                                    PR_WRONLY|PR_CREATE_FILE|PR_TRUNCATE,
                                    PR_IRWXU));
    if (!rcFile)
      BOOST_THROW_EXCEPTION(boost::system::system_error(make_nss_error(),
        "Unable to open torrc file for reading"));

    std::size_t nwritten = 0;
    while (1) {
      auto n = PR_Write(rcFile.get(), torrcContents.data() + nwritten,
                        torrcContents.length() - nwritten);
      if (n < 0) {
        BOOST_THROW_EXCEPTION(boost::system::system_error(make_nss_error(),
          "Unable to write to torrc file"));
      } else {
        nwritten += n;
        if (nwritten == torrcContents.length())
          break;
      }
    }
    
    if (PR_Sync(rcFile.get()) != PR_SUCCESS)      
      BOOST_THROW_EXCEPTION(boost::system::system_error(make_nss_error(),
        "Unable to sync file"));
  }
  
  /* Open a file containing the process output */
  boost::filesystem::path logPath(workingDir / "out.log");
  {
    _outLogFile = to_unique(PR_Open(logPath.string().c_str(),
      PR_WRONLY|PR_CREATE_FILE|PR_TRUNCATE|PR_SYNC, PR_IRWXU));
    if (!_outLogFile)
      BOOST_THROW_EXCEPTION(boost::system::system_error(make_nss_error(),
        "Unable to open output log file"));

    std::string header(std::string("*** Tor log file ***\r\n"));
    PR_Write(_outLogFile.get(), header.data(), header.length());
  }

  /* Process attributes */
  auto attr = to_unique(PR_NewProcessAttr());
  {
    PR_ProcessAttrSetStdioRedirect(attr.get(), PR_StandardOutput,
      PR_GetSpecialFD(PR_StandardOutput));
                               //    _outLogFile.get());
    PR_ProcessAttrSetStdioRedirect(attr.get(), PR_StandardError,
      PR_GetSpecialFD(PR_StandardError));
                              //     _outLogFile.get());
    PR_ProcessAttrSetCurrentDirectory(attr.get(), _workingDir.c_str());
  }

  /* Create the process */
  {
    /* Process arguments */
    _processArgs.addArgument(_execName);
    _processArgs.addArgument("-f");
    _processArgs.addArgument(torrcPath.string().c_str());

    _torProcess = to_unique(PR_CreateProcess(_execName.c_str(),
      _processArgs.argv(), _processArgs.envp(), attr.get()));
    if (!_torProcess)
      BOOST_THROW_EXCEPTION(boost::system::system_error(make_nss_error(),
        "Unable to write to create Tor process"));
  }
  
  /* Create the log file reader thread */
  {
    //ioCtx.queueJob(std::bind(&TorController::logReader, this, logPath));
  }
}
/*
void
TorController::logReader(std::string logPath)
{
  auto logFile = to_unique(PR_Open(logPath.c_str(), PR_RDONLY, 0));
  while (1) {
    
    std::cerr << "I am job number two!" << std::endl;
    PR_Sleep(PR_MillisecondsToInterval(800));
  }
}*/

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

} // namespace tor
} // namespace mist
