#include <array>
#include <cstddef>
#include <string>

#include <sechash.h>

#include "crypto/hash.hpp"
#include "crypto/sha3.h"

#include "memory/nss.hpp"

namespace mist
{
namespace crypto
{
namespace
{

std::string
hash_nss(const std::uint8_t *begin, const std::uint8_t *end,
  SECOidTag hashOIDTag)
{
  std::array<std::uint8_t, 64> digest;
  unsigned int len;

  HASH_HashType hashType = HASH_GetHashTypeByOidTag(hashOIDTag);

  auto ctx = to_unique(HASH_Create(hashType));
  HASH_Begin(ctx.get());
  HASH_Update(ctx.get(),
    reinterpret_cast<const unsigned char *>(begin), end - begin);
  HASH_End(ctx.get(),
    reinterpret_cast<unsigned char *>(digest.data()), &len, digest.size());

  return std::string(reinterpret_cast<const char *>(digest.data()), len);
}

std::string
hash_sha3(const std::uint8_t *begin, const std::uint8_t *end,
  sha3_context *c, std::size_t digestBitCount)
{
  sha3_Update(c, begin, end - begin);
  const char* digest
    = static_cast<const char*>(sha3_Finalize(c));
  return std::string(digest, digestBitCount / 8);
}

} // namespace

//std::string
//hash_sha2_256(const std::uint8_t *begin, const std::uint8_t *end)
//{
//  return hash_nss(begin, end, SEC_OID_SHA256);
//}

std::string
hash_sha3_256(const std::uint8_t *begin, const std::uint8_t *end)
{
  sha3_context c;
  sha3_Init256(&c);
  return hash_sha3(begin, end, &c, 256);
}

std::string
hash_sha3_384(const std::uint8_t *begin, const std::uint8_t *end)
{
  sha3_context c;
  sha3_Init384(&c);
  return hash_sha3(begin, end, &c, 384);
}

std::string
hash_sha3_512(const std::uint8_t *begin, const std::uint8_t *end)
{
  sha3_context c;
  sha3_Init512(&c);
  return hash_sha3(begin, end, &c, 512);
}

} // namespace crypto
} // namespace mist
