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

#include "memory/nss.hpp"

namespace mist
{
namespace crypto
{
namespace
{

c_unique_ptr<SECItem>
convertPassword(const std::string& in, bool toUnicode, bool swapBytes)
{
  const std::size_t bufLength = toUnicode ? 4 * in.size() : in.size();
  std::vector<unsigned char> out(bufLength);
  unsigned int outLength;

  if (PORT_UCS2_ASCIIConversion(toUnicode,
    reinterpret_cast<unsigned char*>(const_cast<char*>(in.data())), in.size(),
    out.data(), bufLength, &outLength, swapBytes) == PR_FALSE)
    return nullptr;

  c_unique_ptr<SECItem> pwitem;
  {
    pwitem = c_unique_ptr<SECItem>(
      reinterpret_cast<SECItem*>(PORT_ZAlloc(sizeof SECItem)));
    pwitem->len = outLength;
    pwitem->data = static_cast<unsigned char*>(PORT_Alloc(outLength));
    std::copy(out.data(), out.data() + outLength, pwitem->data);
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
  bool swapUnicode = false;
  bool swapBytes = false;

#ifdef IS_LITTLE_ENDIAN
  swapUnicode = true;
#endif

  // Convert the password to Unicode...
  // TODO: Looking at the implementation,
  // it seems that there is already a bit of Unicode conversion going on:
  // https://dxr.mozilla.org/mozilla-central/source/security/nss/lib/pkcs12/p12d.c?q=SEC_PKCS12DecoderStart&redirect_type=direct#1201
  {
    pwitem = convertPassword(password, true, swapBytes);
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

void
initSlot(PK11SlotInfo* slot, const std::string& slotPassword)
{
  if (PK11_NeedUserInit(slot)) {
    PK11_InitPin(slot, static_cast<char*>(nullptr), slotPassword.c_str());
  } else {
    void* arg
      = const_cast<void*>(reinterpret_cast<const void*>(&slotPassword));
    if (PK11_Authenticate(slot, PR_TRUE, arg) != SECSuccess)
      BOOST_THROW_EXCEPTION(boost::system::system_error(
        make_mist_error(MIST_ERR_ASSERTION),
        "Unable to authenticate to slot"));
  }
}

} // namespace

void
importPKCS12(PK11SlotInfo* slot, const std::string& slotPassword,
  const std::string& data, const std::string& dataPassword,
  const std::string& nickname)
{
  // Initialize the slot
  initSlot(slot, slotPassword);

  // Initialize the decoder. Note that the pwitem must live at least as long
  // as p12dcx is being used.
  c_unique_ptr<SECItem> pwitem;
  c_unique_ptr<SEC_PKCS12DecoderContext> p12dcx;
  {
    p12dcx = initDecode(data, dataPassword, slot, pwitem, nullptr);
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
