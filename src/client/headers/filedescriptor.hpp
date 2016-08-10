#ifndef __MIST_HEADERS_FILE_DESCRIPTOR_HPP__
#define __MIST_HEADERS_FILE_DESCRIPTOR_HPP__

#include <prtypes.h>
#include <prio.h>

namespace mist
{

class FileDescriptor
{
public:

  virtual PRFileDesc *fileDesc() = 0;
  
  virtual PRInt16 inFlags() const = 0;
  
  virtual void process(PRInt16 inFlags, PRInt16 outFlags) = 0;

};

} // namespace mist

#endif
