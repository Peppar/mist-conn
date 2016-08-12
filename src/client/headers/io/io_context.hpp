#ifndef __MIST_HEADERS_IO_IO_CONTEXT_HPP__
#define __MIST_HEADERS_IO_IO_CONTEXT_HPP__

#include <cstddef>
#include <memory>
#include <list>

#include <prio.h>

#include <boost/optional.hpp>

#include "memory/nss.hpp"

#include "io/file_descriptor.hpp"

namespace mist
{
namespace io
{

struct Timeout
{
  PRIntervalTime established;
  PRIntervalTime interval;
  std::function<void()> callback;
  
  Timeout(PRIntervalTime interval, std::function<void()> callback);
};

class IOContext
{
private:

  std::list<Timeout> _timeouts;

  std::list<std::shared_ptr<FileDescriptor>> _descriptors;

  c_unique_ptr<PRFileDesc> _signalEvent;

  c_unique_ptr<PRThreadPool> _threadPool;

  const std::size_t initialThreadCount = 16;
  const std::size_t maxThreadCount = 192;

public:

  using job_callback = std::function<void()>;

  IOContext();

  /* Wait for one round of I/O events and process them
     Timeout in milliseconds */
  void ioStep(unsigned int maxTimeout);

  void exec();

  PRJob *queueJob(job_callback callback);

  void setTimeout(unsigned int interval, job_callback callback);

  void addDescriptor(std::shared_ptr<FileDescriptor> descriptor);

  void signal();

};

} // namespace io
} // namespace mist

#endif
