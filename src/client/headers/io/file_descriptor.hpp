#ifndef __MIST_HEADERS_FILE_DESCRIPTOR_HPP__
#define __MIST_HEADERS_FILE_DESCRIPTOR_HPP__

#include <boost/optional.hpp>

#include <prtypes.h>
#include <prio.h>

namespace mist
{
namespace io
{

class FileDescriptor
{
public:

  virtual ~FileDescriptor();

  virtual PRFileDesc *fileDesc() = 0;
  
  virtual boost::optional<PRInt16> inFlags() const = 0;
  
  virtual void process(PRInt16 inFlags, PRInt16 outFlags) = 0;

};

} // namespace io
} // namespace mist

#endif
