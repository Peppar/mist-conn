#ifndef __MEMORY_NSS_HPP__
#define __MEMORY_NSS_HPP__

#include "memory/base.hpp"

#include <keyhi.h>

#include <certdb.h>
#include <cert.h>

#include <nspr.h>

#include <prproces.h>

#include <nss.h>

#include <pk11priv.h>
#include <pk11pub.h>
#include <pkcs11t.h>

#include <sechash.h>

struct SEC_PKCS12DecoderContextStr;
typedef struct SEC_PKCS12DecoderContextStr SEC_PKCS12DecoderContext;
extern "C" void SEC_PKCS12DecoderFinish(SEC_PKCS12DecoderContext*);


template<>
struct c_deleter<SEC_PKCS12DecoderContext>
{
  using type = void(*)(SEC_PKCS12DecoderContext*);
  static void del(SEC_PKCS12DecoderContext *ptr)
  {
    SEC_PKCS12DecoderFinish(ptr);
  }
};

template<>
struct c_deleter<CERTCertificate>
{
  using type = void(*)(CERTCertificate*);
  static void del(CERTCertificate *ptr)
  {
    CERT_DestroyCertificate(ptr);
  }
};

template<>
struct c_deleter<CERTCertificateRequest>
{
  using type = void(*)(CERTCertificateRequest*);
  static void del(CERTCertificateRequest *ptr)
  {
    CERT_DestroyCertificateRequest(ptr);
  }
};

template<>
struct c_deleter<CERTCertNicknames>
{
  using type = void(*)(CERTCertNicknames*);
  static void del(CERTCertNicknames *ptr)
  {
    CERT_FreeNicknames(ptr);
  }
};

template<>
struct c_deleter<CERTSubjectPublicKeyInfo>
{
  using type = void(*)(CERTSubjectPublicKeyInfo*);
  static void del(CERTSubjectPublicKeyInfo *ptr)
  {
    SECKEY_DestroySubjectPublicKeyInfo(ptr);
  }
};

template<>
struct c_deleter<CERTValidity>
{
  using type = void(*)(CERTValidity*);
  static void del(CERTValidity *ptr)
  {
    CERT_DestroyValidity(ptr);
  }
};

template<>
struct c_deleter<HASHContext>
{
  using type = void(*)(HASHContext*);
  static void del(HASHContext *ptr)
  {
    HASH_Destroy(ptr);
  }
};

template<>
struct c_deleter<PRArenaPool>
{
  using type = void(*)(PRArenaPool*);
  static void del(PRArenaPool *ptr)
  {
    PORT_FreeArena(ptr, PR_FALSE);
  }
};

template<>
struct c_deleter<PRDir>
{
  using type = void(*)(PRDir*);
  static void del(PRDir *ptr)
  {
    PR_CloseDir(ptr);
  }
};

template<>
struct c_deleter<PRFileDesc>
{
  using type = void(*)(PRFileDesc*);
  static void del(PRFileDesc *ptr)
  {
    PR_Close(ptr);
  }
};

template<>
struct c_deleter<PRProcess>
{
  using type = void(*)(PRProcess*);
  static void del(PRProcess *ptr)
  {
    PR_KillProcess(ptr);
  }
};

template<>
struct c_deleter<PRProcessAttr>
{
  using type = void(*)(PRProcessAttr*);
  static void del(PRProcessAttr *ptr)
  {
    PR_DestroyProcessAttr(ptr);
  }
};

template<>
struct c_deleter<PRThreadPool>
{
  using type = void(*)(PRThreadPool*);
  static void del(PRThreadPool *ptr)
  {
    PR_ShutdownThreadPool(ptr);
  }
};

template<>
struct c_deleter<PK11Context>
{
  using type = void(*)(PK11Context*);
  static void del(PK11Context *ptr)
  {
    PK11_DestroyContext(ptr, PR_TRUE);
  }
};

template<>
struct c_deleter<PK11SlotInfo>
{
  using type = void(*)(PK11SlotInfo*);
  static void del(PK11SlotInfo *ptr)
  {
    PK11_FreeSlot(ptr);
  }
};

template<>
struct c_deleter<PK11SymKey>
{
  using type = void(*)(PK11SymKey*);
  static void del(PK11SymKey *ptr)
  {
    PK11_FreeSymKey(ptr);
  }
};

template<>
struct c_deleter<SECItem>
{
  using type = void(*)(SECItem*);
  static void del(SECItem *ptr)
  {
    SECITEM_FreeItem(ptr, PR_TRUE);
  }
};

template<>
struct c_deleter<SECKEYPrivateKeyList>
{
  using type = void(*)(SECKEYPrivateKeyList*);
  static void del(SECKEYPrivateKeyList *ptr)
  {
    SECKEY_DestroyPrivateKeyList(ptr);
  }
};

template<>
struct c_deleter<SECKEYPrivateKey>
{
  using type = void(*)(SECKEYPrivateKey*);
  static void del(SECKEYPrivateKey *ptr)
  {
    SECKEY_DestroyPrivateKey(ptr);
  }
};

template<>
struct c_deleter<SECKEYPublicKey>
{
  using type = void(*)(SECKEYPublicKey*);
  static void del(SECKEYPublicKey *ptr)
  {
    SECKEY_DestroyPublicKey(ptr);
  }
};

#endif
