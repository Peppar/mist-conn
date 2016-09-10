#ifndef __MIST_HEADERS_CRYPTO_PKCS12_HPP__
#define __MIST_HEADERS_CRYPTO_PKCS12_HPP__

#include <cstddef>
#include <string>

#include <secmodt.h>

namespace mist
{
namespace crypto
{

void
importPKCS12(PK11SlotInfo* slot, const std::string& slotPassword,
  const std::string& data, const std::string& dataPassword,
  const std::string& nickname);

} // namespace crypto
} // namespace mist

#endif
