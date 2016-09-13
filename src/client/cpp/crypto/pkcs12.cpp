#include <string>
#include <iostream>
#include <vector>

#include <boost/optional.hpp>
#include <boost/system/error_code.hpp>
#include <boost/system/system_error.hpp>
#include <boost/throw_exception.hpp>

#include "nspr.h"
#include "pk11func.h"
#include "pkcs12.h"
#include "p12.h"
#include "p12plcy.h"
#include "nss.h"
#include "secport.h"
#include "secpkcs5.h"
#include "secerr.h"
#include "certdb.h"

#include "error/mist.hpp"
#include "error/nss.hpp"

#include "memory/nss.hpp"

namespace mist
{
namespace crypto
{
namespace
{

//c_unique_ptr<SECItem>
//convertPassword(const std::string& password, bool toUnicode, bool swapBytes)
//{
//  SECItem *pwitem = nullptr;
//  {
//    const std::size_t stringBufferSize = password.length() + 1;
//    const char* stringBuffer = password.c_str();
//
//    pwitem = SECITEM_AllocItem(nullptr, nullptr, stringBufferSize);
//    assert(pwitem->len == stringBufferSize);
//    pwitem->type = siAsciiString;
//    std::copy(stringBuffer, stringBuffer + stringBufferSize,
//      pwitem->data);
//  }
//  return pwitem;
//}
c_unique_ptr<SECItem>
convertPassword(const std::string& in, bool toUnicode, bool swapBytes)
{
  const std::size_t strBufLen = in.size() + 1;
  unsigned char* strBufData
    = reinterpret_cast<unsigned char*>(const_cast<char*>(in.c_str()));

  const std::size_t encBufLen = toUnicode ? 4 * strBufLen : strBufLen;
  std::vector<unsigned char> encBuf(encBufLen);
  unsigned int outLength;

  if (PORT_UCS2_UTF8Conversion(toUnicode, strBufData, strBufLen,
    encBuf.data(), encBufLen, &outLength) == PR_FALSE)
    BOOST_THROW_EXCEPTION(boost::system::system_error(make_nss_error(),
      "Unable to convert password"));

  if (swapBytes) {
    std::uint16_t* ucs2Data = reinterpret_cast<std::uint16_t*>(encBuf.data());
    std::size_t ucs2Len = outLength >> 1;
    for (std::size_t n = 0; n < ucs2Len; ++n) {
      ucs2Data[n] = ((ucs2Data[n] & 0xFF) << 8) | (ucs2Data[n] >> 8);
    }
  }

  c_unique_ptr<SECItem> pwitem;
  {
    pwitem = c_unique_ptr<SECItem>(
      reinterpret_cast<SECItem*>(PORT_ZAlloc(sizeof SECItem)));
    pwitem->type = siBuffer;
    pwitem->len = outLength;
    pwitem->data = static_cast<unsigned char*>(PORT_Alloc(outLength));
    std::copy(encBuf.data(), encBuf.data() + outLength, pwitem->data);
  }

  return std::move(pwitem);
}

c_unique_ptr<SEC_PKCS12DecoderContext>
tryInitDecode(const std::string& data, SECItem* pwitem, PK11SlotInfo* slot,
  void* wincx)
{
  auto p12dcx = to_unique(SEC_PKCS12DecoderStart(pwitem, slot, wincx,
    nullptr, nullptr, nullptr, nullptr, nullptr));

  if (!p12dcx)
    return nullptr;

  if (SEC_PKCS12DecoderUpdate(p12dcx.get(),
    reinterpret_cast<unsigned char*>(const_cast<char*>(data.data())),
    data.size()) != SECSuccess)
    return nullptr;

  if (SEC_PKCS12DecoderVerify(p12dcx.get()) != SECSuccess)
    return nullptr;

  return std::move(p12dcx);
}

c_unique_ptr<SEC_PKCS12DecoderContext>
initDecode(const std::string& data, const std::string& password,
  PK11SlotInfo* slot, c_unique_ptr<SECItem>& pwitem, void* wincx)
{
  bool toUnicode = true;
  bool swapBytes = false;

#ifdef IS_LITTLE_ENDIAN
  //swapBytes = true;
#endif

  // Convert the password to Unicode...
  // TODO: Looking at the implementation,
  // it seems that there is already a bit of Unicode conversion going on:
  // https://dxr.mozilla.org/mozilla-central/source/security/nss/lib/pkcs12/p12d.c?q=SEC_PKCS12DecoderStart&redirect_type=direct#1201
  {
    pwitem = convertPassword(password, toUnicode, swapBytes);
    if (!pwitem)
      BOOST_THROW_EXCEPTION(boost::system::system_error(
        make_mist_error(MIST_ERR_ASSERTION),
        "Could not convert password to Unicode"));
  }

  c_unique_ptr<SEC_PKCS12DecoderContext> p12dcx;
  {
    p12dcx = tryInitDecode(data, pwitem.get(), slot, wincx);
    if (!p12dcx && pwitem->len == 2) {
      pwitem->len = 0;
      p12dcx = tryInitDecode(data, pwitem.get(), slot, wincx);
    }
    if (!p12dcx)
      BOOST_THROW_EXCEPTION(boost::system::system_error(
        make_mist_error(MIST_ERR_ASSERTION),
        "Unable to decode"));
  }

  return std::move(p12dcx);
}

} // namespace

void
importPKCS12(PK11SlotInfo* slot, const std::string& data,
  const std::string& dataPassword, const std::string& nickname,
  void* wincx)
{
  // This is mandatory, otherwise NSS will crash by trying to access
  // freed memory.
  SEC_PKCS12EnableCipher(PKCS12_RC4_40, 1);
  SEC_PKCS12EnableCipher(PKCS12_RC4_128, 1);
  SEC_PKCS12EnableCipher(PKCS12_RC2_CBC_40, 1);
  SEC_PKCS12EnableCipher(PKCS12_RC2_CBC_128, 1);
  SEC_PKCS12EnableCipher(PKCS12_DES_56, 1);
  SEC_PKCS12EnableCipher(PKCS12_DES_EDE3_168, 1);
  SEC_PKCS12SetPreferredCipher(PKCS12_DES_EDE3_168, 1);

  // Initialize the decoder. Note that the pwitem must live at least as long
  // as p12dcx is being used.
  c_unique_ptr<SECItem> pwitem;
  c_unique_ptr<SEC_PKCS12DecoderContext> p12dcx;
  {
    p12dcx = initDecode(data, dataPassword, slot, pwitem, wincx);
    if (!p12dcx)
      BOOST_THROW_EXCEPTION(boost::system::system_error(
        make_mist_error(MIST_ERR_ASSERTION),
        "Unable to initialize PKCS12 decoder"));
  }

  // Rename keys and certificates
  {
    std::string arg = nickname;
    using argType = decltype(arg);

    auto rv = SEC_PKCS12DecoderRenameCertNicknames(p12dcx.get(),
      [](const CERTCertificate *cert, const SECItem *default_nickname,
        SECItem **new_nickname, void *argPtr)
    {
      auto& arg = *reinterpret_cast<argType*>(argPtr);
      SECItem *nick = nullptr;
      {
        const std::size_t stringBufferSize = arg.size() + 1;
        const char* stringBuffer = arg.c_str();

        nick = SECITEM_AllocItem(nullptr, nullptr,
          stringBufferSize);
        assert(nick->len == stringBufferSize);
        nick->type = siAsciiString;
        std::copy(stringBuffer, stringBuffer + stringBufferSize,
          nick->data);
      }
      *new_nickname = nick;
      return SECSuccess;
    }, &arg);

    if (rv != SECSuccess)
      BOOST_THROW_EXCEPTION(boost::system::system_error(
        make_mist_error(MIST_ERR_ASSERTION),
        "Unable to rename key and certificate"));
  }

  // Validate
  {
    auto rv = SEC_PKCS12DecoderValidateBags(p12dcx.get(),
      [](SECItem *old_nickname, PRBool *cancel, void *arg)
    {
      *cancel = PR_TRUE;
      return static_cast<SECItem*>(nullptr);
    });

    if (rv != SECSuccess)
      BOOST_THROW_EXCEPTION(boost::system::system_error(
        make_mist_error(MIST_ERR_ASSERTION),
        "PKCS12 decode validate bags failed"));
  }

  // Import
  {
    if (SEC_PKCS12DecoderImportBags(p12dcx.get()) != SECSuccess)
      BOOST_THROW_EXCEPTION(boost::system::system_error(
        make_mist_error(MIST_ERR_ASSERTION),
        "PKCS12 decode import bags failed"));
  }
}

} // namespace crypto
} // namespace mist
