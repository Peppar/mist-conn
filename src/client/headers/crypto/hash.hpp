#ifndef __MIST_HEADERS_CRYPTO_HASH_HPP__
#define __MIST_HEADERS_CRYPTO_HASH_HPP__

#include <cstddef>
#include <string>

namespace mist
{
namespace crypto
{

std::string hash_sha3_256(const std::uint8_t* begin, const std::uint8_t* end);

std::string hash_sha3_384(const std::uint8_t* begin, const std::uint8_t* end);

std::string hash_sha3_512(const std::uint8_t* begin, const std::uint8_t* end);

} // namespace crypto
} // namespace mist

#endif
