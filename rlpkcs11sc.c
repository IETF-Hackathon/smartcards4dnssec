#define TEST
#define VERSION "RL0.51"
// Still at PROOF OF CONCEPT stage
#define VERSION_MAJOR   0
#define VERSION_MINOR   51
#define PROGNAME "rlpkcs11sc"
#define LOGFILE "rlpkcs11sc.log"
/******************************************************************
 *
 * Copyright (C) 2016 Internet Corporation for Assigned Names
 *                         and Numbers ("ICANN")
 *
 * Smartcard PKCS11 Glue Provider for ISC BIND
 * Author: RHLamb 17 July 2016
 *   add native pkcs11 support
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ICANN DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS.  IN NO EVENT SHALL ICANN BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
 * OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 *
 * Author: RHLamb
 * Created: 17 July 2016 based on Rick's pkcs11 mypkcs11 of May 2012
 * Last Mod: 17 July 2016
 *
 * Still at proof of concept stage. DO NOT USE FOR PRODUCTION.
 * Lots of debugging in place.
 *
 * export PKCS11_LIBRARY_PATH=/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so
 * pkcs11-tool -l --keypairgen --key-type EC:prime256v1 --label ecc256key
 * pkcs11-tool -O
 * cc -Icryptoki -fPIC -c rlpkcs11sc.c
 * cc -shared -Wl,-soname,librlpkcs11sc.so -o librlpkcs11sc.so rlpkcs11sc.o -lssl -lcrypto
 * echo -n "123456" > mypin
 * dnssec-keyfromlabel-pkcs11 -E ./librlpkcs11sc.so -l "pkcs11:object=ecc256key;pin-source=mypin" -a ECDSAP256SHA256 -f KSK hx.cds.zx.com
 * cat hx.cds.zx.com.0 Khx.cds.zx.com.+013+60565.key > hx.cds.zx.com
 * dnssec-signzone-pkcs11 -E ./librlpkcs11sc.so -n 1 -x -z -o hx.cds.zx.com -k Khx.cds.zx.com.+013+60565 hx.cds.zx.com
 *
 *********************************************************************/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/param.h>
#include <dirent.h>
#include <dlfcn.h>
#include "cryptoki.h"

#define min(x,y) ((x)<(y)?(x):(y))
#define max(x,y) ((x)>(y)?(x):(y))

static CK_FUNCTION_LIST FuncList;  // My pkcs11
static CK_FUNCTION_LIST *flst; // Underlying pkcs11
static CK_SESSION_HANDLE cursession=0; // only one session at a time

// logging utilities
#include <stdarg.h>
static void mylog(const char *format, ...)
{
  static FILE *mylogfd=NULL;
  va_list args;
  
  if(mylogfd == NULL) {
    if((mylogfd=fopen(LOGFILE,"a")) == NULL) return;
    fprintf(mylogfd,"\n"); // separator
  }
  va_start(args,format);
  vfprintf(mylogfd,format,args);
  va_end(args);

  va_start(args,format);
  vfprintf(stderr,format,args);
  va_end(args);
}

#ifdef TEST
#define DEBUG_LOG(args...) mylog("%s+%d:",__func__,__LINE__); mylog(args)
#else
#define DEBUG_LOG
#endif // TEST

// my mem mgmt - just fail on no-heap
static char *mymalloc(int n)
{
  char *p;

  if((p=malloc(n)) == NULL) {
    printf("Can not malloc(%d) memory in %s\n",n,__func__);
    exit(-1);
  }
  return p;
}
static void myfree(void *p)
{
  free(p);
}
// my old useful dump utility
static int rdump(uint8_t *ptr,int n)
{
  int i,j1,j2; char buf[80]; static char htoas[]="0123456789ABCDEF";
  j1 = j2 = 0; /* gcc -W */
  for(i=0;i<n;i++,j1+=3,j2++) {
    if((i&0xf) == 0) {
      if(i) { buf[j2]='\0'; DEBUG_LOG("%s|\n",buf); }
      j1=0; j2=51; memset(buf,' ',80); buf[50]='|';
    }
    buf[j1] = htoas[(ptr[i]&0xf0) >> 4]; buf[j1+1] = htoas[ptr[i]&0x0f];
    if(ptr[i] >= 0x20 && ptr[i] < 0x80) buf[j2]=ptr[i]; else buf[j2]='.';
  }
  buf[j2]='\0'; DEBUG_LOG("%s|\n",buf);
  return 0;
}

static int lparse(char *line,char *argv[],int maxargs,char delc)
{
  char *cp;
  int argc,qflag;

  if((cp = strchr(line,'\r')) != (char *)0) *cp = '\0';
  if((cp = strchr(line,'\n')) != (char *)0) *cp = '\0';

  for(argc=0;argc<maxargs;argc++) argv[argc] = (char *)0;

  for(argc=0;argc<maxargs;) {
    qflag = 0;
    while(*line == ' ' || *line == '\t') line++; /* whitespace */
    if(*line == '\0') break; /* done */
    if(*line == '"') { line++; qflag = 1; } /* quote */
    argv[argc++] = line;
    if(qflag) {                         /* quote */
      if((line = strchr(line,'"')) == (char *)0) return -1; /*error*/
      *line++ = '\0';
      if(*line == delc) line++;
    } else {
      for(cp=line;*cp;cp++) {
        if(*cp == delc) break;
      }
      if(*cp) *cp++ = '\0'; /* non-zero */
      line = cp;
    }
  }
  return argc;
}
static int ahexbytetoi(char *p)
{
  int k;
  if(p == NULL || strlen(p) != 2) return -1;
  if(p[0] >= 'A' && p[0] <= 'F') k = 10 + p[0] - 'A';
  else if(p[0] >= '0' && p[0] <= '9') k = p[0] - '0';
  else return -1;
  k *= 16;
  if(p[1] >= 'A' && p[1] <= 'F') k += 10 + p[1] - 'A';
  else if(p[1] >= '0' && p[1] <= '9') k += p[1] - '0';
  else return -1;
  return k;
}

static const char *pkcs11_ret_str(CK_RV rv)
{
  switch(rv) {
  case CKR_OK:
    return "CKR_OK";
  case CKR_CANCEL:
    return "CKR_CANCEL";
  case CKR_HOST_MEMORY:
    return "CKR_HOST_MEMORY";
  case CKR_SLOT_ID_INVALID:
    return "CKR_SLOT_ID_INVALID";
  case CKR_GENERAL_ERROR:
    return "CKR_GENERAL_ERROR";
  case CKR_FUNCTION_FAILED:
    return "CKR_FUNCTION_FAILED";
  case CKR_ARGUMENTS_BAD:
    return "CKR_ARGUMENTS_BAD";
  case CKR_NO_EVENT:
    return "CKR_NO_EVENT";
  case CKR_NEED_TO_CREATE_THREADS:
    return "CKR_NEED_TO_CREATE_THREADS";
  case CKR_CANT_LOCK:
    return "CKR_CANT_LOCK";
  case CKR_ATTRIBUTE_READ_ONLY:
    return "CKR_ATTRIBUTE_READ_ONLY";
  case CKR_ATTRIBUTE_SENSITIVE:
    return "CKR_ATTRIBUTE_SENSITIVE";
  case CKR_ATTRIBUTE_TYPE_INVALID:
    return "CKR_ATTRIBUTE_TYPE_INVALID";
  case CKR_ATTRIBUTE_VALUE_INVALID:
    return "CKR_ATTRIBUTE_VALUE_INVALID";
  case CKR_DATA_INVALID:
    return "CKR_DATA_INVALID";
  case CKR_DATA_LEN_RANGE:
    return "CKR_DATA_LEN_RANGE";
  case CKR_DEVICE_ERROR:
    return "CKR_DEVICE_ERROR";
  case CKR_DEVICE_MEMORY:
    return "CKR_DEVICE_MEMORY";
  case CKR_DEVICE_REMOVED:
    return "CKR_DEVICE_REMOVED";
  case CKR_ENCRYPTED_DATA_INVALID:
    return "CKR_ENCRYPTED_DATA_INVALID";
  case CKR_ENCRYPTED_DATA_LEN_RANGE:
    return "CKR_ENCRYPTED_DATA_LEN_RANGE";
  case CKR_FUNCTION_CANCELED:
    return "CKR_FUNCTION_CANCELED";
  case CKR_FUNCTION_NOT_PARALLEL:
    return "CKR_FUNCTION_NOT_PARALLEL";
  case CKR_FUNCTION_NOT_SUPPORTED:
    return "CKR_FUNCTION_NOT_SUPPORTED";
  case CKR_KEY_HANDLE_INVALID:
    return "CKR_KEY_HANDLE_INVALID";
  case CKR_KEY_SIZE_RANGE:
    return "CKR_KEY_SIZE_RANGE";
  case CKR_KEY_TYPE_INCONSISTENT:
    return "CKR_KEY_TYPE_INCONSISTENT";
  case CKR_KEY_NOT_NEEDED:
    return "CKR_KEY_NOT_NEEDED";
  case CKR_KEY_CHANGED:
    return "CKR_KEY_CHANGED";
  case CKR_KEY_NEEDED:
    return "CKR_KEY_NEEDED";
  case CKR_KEY_INDIGESTIBLE:
    return "CKR_KEY_INDIGESTIBLE";
  case CKR_KEY_FUNCTION_NOT_PERMITTED:
    return "CKR_KEY_FUNCTION_NOT_PERMITTED";
  case CKR_KEY_NOT_WRAPPABLE:
    return "CKR_KEY_NOT_WRAPPABLE";
  case CKR_KEY_UNEXTRACTABLE:
    return "CKR_KEY_UNEXTRACTABLE";
  case CKR_MECHANISM_INVALID:
    return "CKR_MECHANISM_INVALID";
  case CKR_MECHANISM_PARAM_INVALID:
    return "CKR_MECHANISM_PARAM_INVALID";
  case CKR_OBJECT_HANDLE_INVALID:
    return "CKR_OBJECT_HANDLE_INVALID";
  case CKR_OPERATION_ACTIVE:
    return "CKR_OPERATION_ACTIVE";
  case CKR_OPERATION_NOT_INITIALIZED:
    return "CKR_OPERATION_NOT_INITIALIZED";
  case CKR_PIN_INCORRECT:
    return "CKR_PIN_INCORRECT";
  case CKR_PIN_INVALID:
    return "CKR_PIN_INVALID";
  case CKR_PIN_LEN_RANGE:
    return "CKR_PIN_LEN_RANGE";
  case CKR_PIN_EXPIRED:
    return "CKR_PIN_EXPIRED";
  case CKR_PIN_LOCKED:
    return "CKR_PIN_LOCKED";
  case CKR_SESSION_CLOSED:
    return "CKR_SESSION_CLOSED";
  case CKR_SESSION_COUNT:
    return "CKR_SESSION_COUNT";
  case CKR_SESSION_HANDLE_INVALID:
    return "CKR_SESSION_HANDLE_INVALID";
  case CKR_SESSION_PARALLEL_NOT_SUPPORTED:
    return "CKR_SESSION_PARALLEL_NOT_SUPPORTED";
  case CKR_SESSION_READ_ONLY:
    return "CKR_SESSION_READ_ONLY";
  case CKR_SESSION_EXISTS:
    return "CKR_SESSION_EXISTS";
  case CKR_SESSION_READ_ONLY_EXISTS:
    return "CKR_SESSION_READ_ONLY_EXISTS";
  case CKR_SESSION_READ_WRITE_SO_EXISTS:
    return "CKR_SESSION_READ_WRITE_SO_EXISTS";
  case CKR_SIGNATURE_INVALID:
    return "CKR_SIGNATURE_INVALID";
  case CKR_SIGNATURE_LEN_RANGE:
    return "CKR_SIGNATURE_LEN_RANGE";
  case CKR_TEMPLATE_INCOMPLETE:
    return "CKR_TEMPLATE_INCOMPLETE";
  case CKR_TEMPLATE_INCONSISTENT:
    return "CKR_TEMPLATE_INCONSISTENT";
  case CKR_TOKEN_NOT_PRESENT:
    return "CKR_TOKEN_NOT_PRESENT";
  case CKR_TOKEN_NOT_RECOGNIZED:
    return "CKR_TOKEN_NOT_RECOGNIZED";
  case CKR_TOKEN_WRITE_PROTECTED:
    return "CKR_TOKEN_WRITE_PROTECTED";
  case CKR_UNWRAPPING_KEY_HANDLE_INVALID:
    return "CKR_UNWRAPPING_KEY_HANDLE_INVALID";
  case CKR_UNWRAPPING_KEY_SIZE_RANGE:
    return "CKR_UNWRAPPING_KEY_SIZE_RANGE";
  case CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT:
    return "CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT";
  case CKR_USER_ALREADY_LOGGED_IN:
    return "CKR_USER_ALREADY_LOGGED_IN";
  case CKR_USER_NOT_LOGGED_IN:
    return "CKR_USER_NOT_LOGGED_IN";
  case CKR_USER_PIN_NOT_INITIALIZED:
    return "CKR_USER_PIN_NOT_INITIALIZED";
  case CKR_USER_TYPE_INVALID:
    return "CKR_USER_TYPE_INVALID";
  case CKR_USER_ANOTHER_ALREADY_LOGGED_IN:
    return "CKR_USER_ANOTHER_ALREADY_LOGGED_IN";
  case CKR_USER_TOO_MANY_TYPES:
    return "CKR_USER_TOO_MANY_TYPES";
  case CKR_WRAPPED_KEY_INVALID:
    return "CKR_WRAPPED_KEY_INVALID";
  case CKR_WRAPPED_KEY_LEN_RANGE:
    return "CKR_WRAPPED_KEY_LEN_RANGE";
  case CKR_WRAPPING_KEY_HANDLE_INVALID:
    return "CKR_WRAPPING_KEY_HANDLE_INVALID";
  case CKR_WRAPPING_KEY_SIZE_RANGE:
    return "CKR_WRAPPING_KEY_SIZE_RANGE";
  case CKR_WRAPPING_KEY_TYPE_INCONSISTENT:
    return "CKR_WRAPPING_KEY_TYPE_INCONSISTENT";
  case CKR_RANDOM_SEED_NOT_SUPPORTED:
    return "CKR_RANDOM_SEED_NOT_SUPPORTED";
  case CKR_RANDOM_NO_RNG:
    return "CKR_RANDOM_NO_RNG";
  case CKR_DOMAIN_PARAMS_INVALID:
    return "CKR_DOMAIN_PARAMS_INVALID";
  case CKR_BUFFER_TOO_SMALL:
    return "CKR_BUFFER_TOO_SMALL";
  case CKR_SAVED_STATE_INVALID:
    return "CKR_SAVED_STATE_INVALID";
  case CKR_INFORMATION_SENSITIVE:
    return "CKR_INFORMATION_SENSITIVE";
  case CKR_STATE_UNSAVEABLE:
    return "CKR_STATE_UNSAVEABLE";
  case CKR_CRYPTOKI_NOT_INITIALIZED:
    return "CKR_CRYPTOKI_NOT_INITIALIZED";
  case CKR_CRYPTOKI_ALREADY_INITIALIZED:
    return "CKR_CRYPTOKI_ALREADY_INITIALIZED";
  case CKR_MUTEX_BAD:
    return "CKR_MUTEX_BAD";
  case CKR_MUTEX_NOT_LOCKED:
    return "CKR_MUTEX_NOT_LOCKED";
  case CKR_FUNCTION_REJECTED:
    return "CKR_FUNCTION_REJECTED";
  case CKR_VENDOR_DEFINED:
    return "CKR_VENDOR_DEFINED";
  default:
    return "Undefined Return Code";
  }
}
static char *cka_str(int attr)
{
  switch(attr) {
  case CKA_AC_ISSUER: return "CKA_AC_ISSUER";
  case CKA_ALLOWED_MECHANISMS: return "CKA_ALLOWED_MECHANISMS";
  case CKA_ALWAYS_AUTHENTICATE: return "CKA_ALWAYS_AUTHENTICATE";
  case CKA_ALWAYS_SENSITIVE: return "CKA_ALWAYS_SENSITIVE";
  case CKA_APPLICATION: return "CKA_APPLICATION";
  case CKA_ATTR_TYPES: return "CKA_ATTR_TYPES";
  case CKA_AUTH_PIN_FLAGS: return "CKA_AUTH_PIN_FLAGS";
  case CKA_BASE: return "CKA_BASE";
  case CKA_BITS_PER_PIXEL: return "CKA_BITS_PER_PIXEL";
  case CKA_CERTIFICATE_CATEGORY: return "CKA_CERTIFICATE_CATEGORY";
  case CKA_CERTIFICATE_TYPE: return "CKA_CERTIFICATE_TYPE";
  case CKA_CHAR_COLUMNS: return "CKA_CHAR_COLUMNS";
  case CKA_CHAR_ROWS: return "CKA_CHAR_ROWS";
  case CKA_CHAR_SETS: return "CKA_CHAR_SETS";
  case CKA_CHECK_VALUE: return "CKA_CHECK_VALUE";
  case CKA_CLASS: return "CKA_CLASS";
  case CKA_COEFFICIENT: return "CKA_COEFFICIENT";
  case CKA_COLOR: return "CKA_COLOR";
  case CKA_DECRYPT: return "CKA_DECRYPT";
  case CKA_DEFAULT_CMS_ATTRIBUTES: return "CKA_DEFAULT_CMS_ATTRIBUTES";
  case CKA_DERIVE: return "CKA_DERIVE";
  case CKA_ECDSA_PARAMS: return "CKA_ECDSA_PARAMS";
    //case CKA_EC_PARAMS: return "CKA_EC_PARAMS";
  case CKA_EC_POINT: return "CKA_EC_POINT";
  case CKA_ENCODING_METHODS: return "CKA_ENCODING_METHODS";
  case CKA_ENCRYPT: return "CKA_ENCRYPT";
  case CKA_END_DATE: return "CKA_END_DATE";
  case CKA_EXPONENT_1: return "CKA_EXPONENT_1";
  case CKA_EXPONENT_2: return "CKA_EXPONENT_2";
  case CKA_EXTRACTABLE: return "CKA_EXTRACTABLE";
  case CKA_HASH_OF_ISSUER_PUBLIC_KEY: return "CKA_HASH_OF_ISSUER_PUBLIC_KEY";
  case CKA_HASH_OF_SUBJECT_PUBLIC_KEY: return "CKA_HASH_OF_SUBJECT_PUBLIC_KEY";
  case CKA_HAS_RESET: return "CKA_HAS_RESET";
  case CKA_HW_FEATURE_TYPE: return "CKA_HW_FEATURE_TYPE";
  case CKA_ID: return "CKA_ID";
  case CKA_ISSUER: return "CKA_ISSUER";
  case CKA_JAVA_MIDP_SECURITY_DOMAIN: return "CKA_JAVA_MIDP_SECURITY_DOMAIN";
  case CKA_KEY_GEN_MECHANISM: return "CKA_KEY_GEN_MECHANISM";
  case CKA_KEY_TYPE: return "CKA_KEY_TYPE";
  case CKA_LABEL: return "CKA_LABEL";
  case CKA_LOCAL: return "CKA_LOCAL";
  case CKA_MECHANISM_TYPE: return "CKA_MECHANISM_TYPE";
  case CKA_MIME_TYPES: return "CKA_MIME_TYPES";
  case CKA_MODIFIABLE: return "CKA_MODIFIABLE";
  case CKA_MODULUS: return "CKA_MODULUS";
  case CKA_MODULUS_BITS: return "CKA_MODULUS_BITS";
  case CKA_NEVER_EXTRACTABLE: return "CKA_NEVER_EXTRACTABLE";
  case CKA_OBJECT_ID: return "CKA_OBJECT_ID";
  case CKA_OWNER: return "CKA_OWNER";
  case CKA_PIXEL_X: return "CKA_PIXEL_X";
  case CKA_PIXEL_Y: return "CKA_PIXEL_Y";
  case CKA_PRIME: return "CKA_PRIME";
  case CKA_PRIME_1: return "CKA_PRIME_1";
  case CKA_PRIME_2: return "CKA_PRIME_2";
  case CKA_PRIME_BITS: return "CKA_PRIME_BITS";
  case CKA_PRIVATE: return "CKA_PRIVATE";
  case CKA_PRIVATE_EXPONENT: return "CKA_PRIVATE_EXPONENT";
  case CKA_PUBLIC_EXPONENT: return "CKA_PUBLIC_EXPONENT";
  case CKA_REQUIRED_CMS_ATTRIBUTES: return "CKA_REQUIRED_CMS_ATTRIBUTES";
  case CKA_RESET_ON_INIT: return "CKA_RESET_ON_INIT";
  case CKA_RESOLUTION: return "CKA_RESOLUTION";
  case CKA_SECONDARY_AUTH: return "CKA_SECONDARY_AUTH";
  case CKA_SENSITIVE: return "CKA_SENSITIVE";
  case CKA_SERIAL_NUMBER: return "CKA_SERIAL_NUMBER";
  case CKA_SIGN: return "CKA_SIGN";
  case CKA_SIGN_RECOVER: return "CKA_SIGN_RECOVER";
  case CKA_START_DATE: return "CKA_START_DATE";
  case CKA_SUBJECT: return "CKA_SUBJECT";
  case CKA_SUBPRIME: return "CKA_SUBPRIME";
    //case CKA_SUB_PRIME_BITS: return "CKA_SUB_PRIME_BITS";
  case CKA_SUBPRIME_BITS: return "CKA_SUBPRIME_BITS";
  case CKA_SUPPORTED_CMS_ATTRIBUTES: return "CKA_SUPPORTED_CMS_ATTRIBUTES";
  case CKA_TOKEN: return "CKA_TOKEN";
  case CKA_TRUSTED: return "CKA_TRUSTED";
  case CKA_UNWRAP: return "CKA_UNWRAP";
  case CKA_UNWRAP_TEMPLATE: return "CKA_UNWRAP_TEMPLATE";
  case CKA_URL: return "CKA_URL";
  case CKA_VALUE: return "CKA_VALUE";
  case CKA_VALUE_BITS: return "CKA_VALUE_BITS";
  case CKA_VALUE_LEN: return "CKA_VALUE_LEN";
  case CKA_VENDOR_DEFINED: return "CKA_VENDOR_DEFINED";
  case CKA_VERIFY: return "CKA_VERIFY";
  case CKA_VERIFY_RECOVER: return "CKA_VERIFY_RECOVER";
  case CKA_WRAP: return "CKA_WRAP";
  case CKA_WRAP_TEMPLATE: return "CKA_WRAP_TEMPLATE";
  case CKA_WRAP_WITH_TRUSTED: return "CKA_WRAP_WITH_TRUSTED";
  default: return "CKA_Unknown";
  }
}


CK_RV C_GenerateKeyPair(CK_SESSION_HANDLE    hSession,
			CK_MECHANISM_PTR     pMechanism,
			CK_ATTRIBUTE_PTR     pPublicKeyTemplate,
			CK_ULONG             ulPublicKeyAttributeCount,
			CK_ATTRIBUTE_PTR     pPrivateKeyTemplate,
			CK_ULONG             ulPrivateKeyAttributeCount,
			CK_OBJECT_HANDLE_PTR phPublicKey,
			CK_OBJECT_HANDLE_PTR phPrivateKey)
{
  DEBUG_LOG("sh:0x%08X\n",hSession);
  if(flst == NULL) return CKR_CRYPTOKI_NOT_INITIALIZED;
  return flst->C_GenerateKeyPair(hSession,pMechanism,pPublicKeyTemplate,ulPublicKeyAttributeCount,pPrivateKeyTemplate,ulPrivateKeyAttributeCount,phPublicKey,phPrivateKey);
}

CK_RV C_SignInit(CK_SESSION_HANDLE hSession,
                 CK_MECHANISM_PTR  pMechanism,
                 CK_OBJECT_HANDLE  hKey)
{
  DEBUG_LOG("sh:0x%08X\n",hSession);
  if(flst == NULL) return CKR_CRYPTOKI_NOT_INITIALIZED;
  return flst->C_SignInit(hSession,pMechanism,hKey);
}
CK_RV C_Sign(CK_SESSION_HANDLE hSession,
             CK_BYTE_PTR       pData,
             CK_ULONG          ulDataLen,
             CK_BYTE_PTR       pSignature,
             CK_ULONG_PTR      pulSignatureLen)
{
  DEBUG_LOG("sh:0x%08X\n",hSession);
  if(flst == NULL) return CKR_CRYPTOKI_NOT_INITIALIZED;
  return flst->C_Sign(hSession,pData,ulDataLen,pSignature,pulSignatureLen);
}
CK_RV C_SignUpdate(CK_SESSION_HANDLE hSession,
		   CK_BYTE_PTR       pPart,
		   CK_ULONG          ulPartLen)
{
  DEBUG_LOG("sh:0x%08X\n",hSession);
  if(flst == NULL) return CKR_CRYPTOKI_NOT_INITIALIZED;
  return flst->C_SignUpdate(hSession,pPart,ulPartLen);
}
CK_RV C_SignFinal(CK_SESSION_HANDLE hSession,
		  CK_BYTE_PTR       pSignature,   
		  CK_ULONG_PTR      pulSignatureLen)
{
  DEBUG_LOG("sh:0x%08X\n",hSession);
  if(flst == NULL) return CKR_CRYPTOKI_NOT_INITIALIZED;
  return flst->C_SignFinal(hSession,pSignature,pulSignatureLen);
}


CK_RV C_FindObjectsInit(CK_SESSION_HANDLE hSession,
			CK_ATTRIBUTE_PTR  pTemplate,
			CK_ULONG          ulCount)
{
  DEBUG_LOG("sh:0x%08X\n",hSession);
  if(flst == NULL) return CKR_CRYPTOKI_NOT_INITIALIZED;
  return flst->C_FindObjectsInit(hSession,pTemplate,ulCount);
}
CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE hSession)
{
  DEBUG_LOG("sh:0x%08X\n",hSession);
  if(flst == NULL) return CKR_CRYPTOKI_NOT_INITIALIZED;
  return flst->C_FindObjectsFinal(hSession);
}
CK_RV C_FindObjects(CK_SESSION_HANDLE    hSession,
		    CK_OBJECT_HANDLE_PTR phObject,
		    CK_ULONG             ulMaxObjectCount,
		    CK_ULONG_PTR         pulObjectCount)
{
  DEBUG_LOG("sh:0x%08X\n",hSession);
  if(flst == NULL) return CKR_CRYPTOKI_NOT_INITIALIZED;
  return flst->C_FindObjects(hSession,phObject,ulMaxObjectCount,pulObjectCount);
}

static void decode_attr(CK_ATTRIBUTE_PTR pt,CK_ULONG n)
{
  int i;
  CK_ATTRIBUTE_PTR x;
  x = pt;
  for(i=0;i<n;i++) {
    DEBUG_LOG("%s\n",cka_str(x->type));
    x++;
  }
}

CK_RV C_CreateObject(CK_SESSION_HANDLE    hSession,
                     CK_ATTRIBUTE_PTR     pTemplate,
                     CK_ULONG             ulCount,
                     CK_OBJECT_HANDLE_PTR phObject)
{
  CK_RV   rv;
  CK_ULONG n;
  CK_ATTRIBUTE_PTR pf;
  uint8_t *pp;
  
  DEBUG_LOG("sh:0x%08X\n",hSession);
  if(flst == NULL) return CKR_CRYPTOKI_NOT_INITIALIZED;

#ifdef FOOP
  // This does not often supported on smartcards.
  // Therefore we just create a local object to be referrenced later.
  rv = flst->C_CreateObject(hSession,pTemplate,ulCount,phObject);
  DEBUG_LOG("rv:%s\n",pkcs11_ret_str(rv));
  decode_attr(pTemplate,ulCount);
  
  if(rv == CKR_OK) return rv;
  DEBUG_LOG("rv:%d Trying another approach\n",rv);
#endif // FOOP
  
  if(hSession == 0) return CKR_SESSION_HANDLE_INVALID;
  
  pp = (uint8_t *)mymalloc(2048);
  memset(pp,0,2048);
  DEBUG_LOG("object:%p\n",pp);
  *phObject = (CK_OBJECT_HANDLE_PTR)pp;
  for(pf=pTemplate,n=ulCount;n>0;pf++,n--) {
    DEBUG_LOG("  %s len:%u\n",cka_str(pf->type),pf->ulValueLen);
    rdump(pf->pValue,pf->ulValueLen);
    *(CK_ULONG *)pp = pf->type; pp += sizeof(CK_ULONG);
    *(CK_ULONG *)pp = pf->ulValueLen; pp += sizeof(CK_ULONG);
    memcpy(pp,pf->pValue,pf->ulValueLen); pp += pf->ulValueLen;
  }

  *(CK_ULONG *)pp = 0x12345678; // my end of object attribute
  
  return CKR_OK;
}
CK_RV C_DestroyObject(CK_SESSION_HANDLE hSession,
                      CK_OBJECT_HANDLE  hObject)
{
  DEBUG_LOG("sh:0x%08X\n",hSession);
  if(flst == NULL) return CKR_CRYPTOKI_NOT_INITIALIZED;
  return flst->C_DestroyObject(hSession,hObject);
}

CK_RV C_GetAttributeValue(CK_SESSION_HANDLE hSession,
                          CK_OBJECT_HANDLE  hObject,
                          CK_ATTRIBUTE_PTR  pTemplate,
                          CK_ULONG          ulCount)
{
  DEBUG_LOG("sh:0x%08X\n",hSession);
  if(flst == NULL) return CKR_CRYPTOKI_NOT_INITIALIZED;
  return flst->C_GetAttributeValue(hSession,hObject,pTemplate,ulCount);
}
CK_RV C_SetAttributeValue(CK_SESSION_HANDLE hSession,
                          CK_OBJECT_HANDLE  hObject,
                          CK_ATTRIBUTE_PTR  pTemplate,
                          CK_ULONG          ulCount)
{
  DEBUG_LOG("sh:0x%08X\n",hSession);
  if(flst == NULL) return CKR_CRYPTOKI_NOT_INITIALIZED;
  return flst->C_SetAttributeValue(hSession,hObject,pTemplate,ulCount);
}

CK_RV C_DigestInit(CK_SESSION_HANDLE hSession,
	     CK_MECHANISM_PTR  pMechanism)
{
  CK_RV rv;
  DEBUG_LOG("sh:0x%08X\n",hSession);
  if(flst == NULL) return CKR_CRYPTOKI_NOT_INITIALIZED;
  rv = flst->C_DigestInit(hSession,pMechanism);
  
  if(rv != CKR_OK) DEBUG_LOG("XXX B rv:0x%08X\n",rv); // probmlen here
  
  return rv;
}
CK_RV C_Digest(   CK_SESSION_HANDLE hSession,     /* the session's handle */
	    CK_BYTE_PTR       pData,        /* data to be digested */
	    CK_ULONG          ulDataLen,    /* bytes of data to digest */
	    CK_BYTE_PTR       pDigest,      /* gets the message digest */
	    CK_ULONG_PTR      pulDigestLen  /* gets digest length */
	    
	 )
{
  DEBUG_LOG("sh:0x%08X\n",hSession);
  if(flst == NULL) return CKR_CRYPTOKI_NOT_INITIALIZED;
  return flst->C_Digest(hSession,pData,ulDataLen,pDigest,pulDigestLen);
}
CK_RV C_DigestUpdate(CK_SESSION_HANDLE hSession,  /* the session's handle */
	       CK_BYTE_PTR       pPart,     /* data to be digested */
	       CK_ULONG          ulPartLen  /* bytes of data to be digested */
	       
	       )
{
  CK_RV rv;
  DEBUG_LOG("sh:0x%08X\n",hSession);
  if(flst == NULL) return CKR_CRYPTOKI_NOT_INITIALIZED;
  rv= flst->C_DigestUpdate(hSession,pPart,ulPartLen);
  if(rv != CKR_OK) DEBUG_LOG("XXX B rv:0x%08X\n",rv); // probmlen here
  return rv;
}
CK_RV C_DigestKey(   CK_SESSION_HANDLE hSession,  /* the session's handle */
	       CK_OBJECT_HANDLE  hKey       /* secret key to digest */
	       
	    )
{
  DEBUG_LOG("sh:0x%08X\n",hSession);
  if(flst == NULL) return CKR_CRYPTOKI_NOT_INITIALIZED;
  return flst->C_DigestKey(hSession,hKey);
}
CK_RV C_DigestFinal(CK_SESSION_HANDLE hSession,     /* the session's handle */
		 CK_BYTE_PTR  pDigest,      /* gets the message digest */
		 CK_ULONG_PTR  pulDigestLen  /* gets byte count of digest */)
{
  CK_RV rv;
  DEBUG_LOG("sh:0x%08X\n",hSession);
  if(flst == NULL) return CKR_CRYPTOKI_NOT_INITIALIZED;
  rv= flst->C_DigestFinal(hSession,pDigest,pulDigestLen);
  if(rv != CKR_OK) DEBUG_LOG("XXX B rv:0x%08X 0x%08X\n",rv,CKR_OK); // probmlen here
  DEBUG_LOG("bytes:%d\n",*pulDigestLen);
  if(*pulDigestLen > 0) rdump(pDigest,*pulDigestLen);
  return rv;
}

CK_RV C_GetMechanismInfo( CK_SLOT_ID slotID,  /* ID of the token's slot */
			  CK_MECHANISM_TYPE  type,    /* type of mechanism */
			  CK_MECHANISM_INFO_PTR pInfo /* receives mechanism info */ )
{
  //DEBUG_LOG("\n");
  pInfo->flags = CKF_GENERATE_KEY_PAIR|CKF_SIGN|CKF_VERIFY|CKF_DIGEST;
  // 0xFFFFFFFF;
  return CKR_OK;
}

CK_RV C_GenerateRandom(CK_SESSION_HANDLE hSession,
                       CK_BYTE_PTR       RandomData,
                       CK_ULONG          ulRandomLen)
{
  DEBUG_LOG("sh:0x%08X\n",hSession);
  if(flst == NULL) return CKR_CRYPTOKI_NOT_INITIALIZED;
  return flst->C_GenerateRandom(hSession,RandomData,ulRandomLen);
}

CK_RV C_Login(CK_SESSION_HANDLE hSession,
              CK_USER_TYPE      userType,
              CK_CHAR_PTR       pPin,
              CK_ULONG          ulPinLen)
{
  char buf[32];
  //strncpy(buf,pPin,ulPinLen);
  //buf[ulPinLen] = '\0';
  buf[0] = '\0';
  DEBUG_LOG("sh:0x%08X |%s|\n",hSession,buf);
  if(flst == NULL) return CKR_CRYPTOKI_NOT_INITIALIZED;

  return flst->C_Login(hSession,userType,pPin,ulPinLen);
}
CK_RV C_Logout(CK_SESSION_HANDLE hSession)
{
  DEBUG_LOG("sh:0x%08X\n",hSession);
  if(flst == NULL) return CKR_CRYPTOKI_NOT_INITIALIZED;
  return flst->C_Logout(hSession);
}

// always return only one slot.  Slot 0
CK_RV C_GetSlotList(CK_BBOOL       tokenPresent,
		    CK_SLOT_ID_PTR pSlotList,
		    CK_ULONG_PTR   pulCount)
{
  DEBUG_LOG("\n");
  if(flst == NULL) return CKR_CRYPTOKI_NOT_INITIALIZED;
  DEBUG_LOG("tokenPresent:%d pSlotList:%p pulCount:%p *pulCount:%d\n",tokenPresent,pSlotList,pulCount,*pulCount);
  return flst->C_GetSlotList(tokenPresent,pSlotList,pulCount);
}
// only have one session
CK_RV C_OpenSession(CK_SLOT_ID            slotID,
		    CK_FLAGS              flags,
		    CK_VOID_PTR           pApplication,
		    CK_NOTIFY             Notify,
		    CK_SESSION_HANDLE_PTR phSession)
{
  CK_RV rv;
  DEBUG_LOG("\n");
  if(flst == NULL) return CKR_CRYPTOKI_NOT_INITIALIZED;
  DEBUG_LOG("id:%d flags:%x ptr:%p ntfy:%p phSession:%p\n",slotID,flags,pApplication,Notify,phSession);

  if(cursession) return CKR_SESSION_PARALLEL_NOT_SUPPORTED;
  
  rv = flst->C_OpenSession(slotID,flags,pApplication,Notify,phSession);
  DEBUG_LOG("sh:0x%08X\n",*phSession);
  cursession = *phSession;
  return rv;
}
CK_RV C_CloseSession(CK_SESSION_HANDLE hSession)
{
  CK_RV rv;
  int i;
  uint8_t buf[1024],obuf[1024];
  int n,olen;

  DEBUG_LOG("sh:0x%08X\n",hSession);
  if(flst == NULL) return CKR_CRYPTOKI_NOT_INITIALIZED;
  rv = flst->C_CloseSession(hSession);
  cursession = 0;
  return rv;
}
CK_RV C_Finalize(CK_VOID_PTR pReserved)
{
  DEBUG_LOG("\n");
  return flst->C_Finalize(pReserved);
}

#include <signal.h>
static void atexithandler(void)
{
  C_Finalize(0);
}

static void sighuphandler(int sig)
{
  C_Finalize(0);
}

CK_RV C_Initialize(CK_VOID_PTR pVoid)
{
  void *pkcs11_hLib=NULL;
  CK_C_GetFunctionList pGFL=0;
  char *pkcs11_library=NULL;
  int rv;

  DEBUG_LOG("\n");
  
  if(flst) return CKR_CRYPTOKI_ALREADY_INITIALIZED;  /* already open and associated */
  //pkcs11_library = "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so";
  if(pkcs11_library == NULL || strlen(pkcs11_library) <= 0) {
    if((pkcs11_library=getenv("PKCS11_LIBRARY_PATH")) == NULL || strlen(pkcs11_library) <= 0) {
      DEBUG_LOG("You must set PKCS11_LIBRARY_PATH, e.g.,\n \"export PKCS11_LIBRARY_PATH=/usr/lib/opensc-pkcs11.so\"\n");
      return CKR_FUNCTION_FAILED;
    }
  }
  pkcs11_hLib = dlopen(pkcs11_library,RTLD_LAZY);
  if(!pkcs11_hLib) {
    DEBUG_LOG("error: Failed to open PKCS11 library %s\n",pkcs11_library);
    return CKR_FUNCTION_FAILED;
  }
  if((pGFL=(CK_C_GetFunctionList)dlsym(pkcs11_hLib,"C_GetFunctionList")) == NULL) {
    DEBUG_LOG("error: Cannot find GetFunctionList()\n");
    dlclose(pkcs11_hLib);
    return CKR_FUNCTION_FAILED;
  }
  if((rv=pGFL(&flst)) != CKR_OK) {
    DEBUG_LOG("C_GetFunctionList %s\n",pkcs11_ret_str(rv));
    dlclose(pkcs11_hLib);
    flst = NULL;
    return CKR_FUNCTION_FAILED;
  }
  /*
   * Note: Since we dont know what a HSM vendor is going to do, this might
   * clobber signal handling and other process oriented stuff. 
   */
  if((rv=flst->C_Initialize(NULL)) != CKR_OK) {
    DEBUG_LOG("error: C_Initialize %s\n",pkcs11_ret_str(rv));
    dlclose(pkcs11_hLib);
    flst = NULL;
    return CKR_FUNCTION_FAILED;
  }

#ifdef FOOP
  // catch signals and exit - BUT none of these seems to catch a BIND failure
  if(atexit(atexithandler)) { // make sure to free HSM resources at exit
    DEBUG_LOG("Cannot set atexit function\n");
    return CKR_FUNCTION_FAILED;
  }
  // might do odd things with BIND and other programs calling this dynamic lib
  signal(SIGHUP,sighuphandler);
  signal(SIGINT,sighuphandler);
  signal(SIGQUIT,sighuphandler);
  signal(SIGTERM,sighuphandler);
#endif // FOOP
  
  return CKR_OK;
}

#define MY_TOKEN_LABEL PROGNAME
#define MY_TOKEN_MFR "RICKL "
#define MY_TOKEN_MODEL "PX "
#define MY_TOKEN_SER "0.51"

CK_RV C_GetTokenInfo(CK_SLOT_ID        slotID,
		     CK_TOKEN_INFO_PTR pInfo)
{
  int rv;
  char buf[64];
  int i;
  
  DEBUG_LOG("slotID:%d \n",slotID);
  if(flst == NULL) return CKR_CRYPTOKI_NOT_INITIALIZED;
  rv = flst->C_GetTokenInfo(slotID,pInfo);
  DEBUG_LOG("rv:%d \n",rv);
  if(rv != CKR_OK) return rv;
    
  if(pInfo == NULL) {
    DEBUG_LOG("NULL pInfo\n");
    return rv;
  }
  // Modify the label
  if(pInfo->label) { // CK_UTF8CHAR label[32]; /* blank padded */
    pInfo->label[31] = '\0';
    i = sprintf(buf,"%s %s",MY_TOKEN_LABEL,pInfo->label);
    memset(&buf[i],' ',sizeof(buf)-i);
    memcpy(pInfo->label,buf,32);
  }
#ifdef FOOP
  if(pInfo->manufacturerID) { // CK_UTF8CHAR manufacturerID[32];
    pInfo->manufacturerID[31] = '\0';
    i = sprintf(buf,"%s%s",MY_TOKEN_MFR,pInfo->manufacturerID);
    memset(&buf[i],' ',sizeof(buf)-i);
    memcpy(pInfo->manufacturerID,buf,32);
  }
  if(pInfo->model) { // CK_UTF8CHAR model[16]; /* blank padded */
    pInfo->model[15] = '\0';
    i = sprintf(buf,"%s%s",MY_TOKEN_MODEL,pInfo->model);
    memset(&buf[i],' ',sizeof(buf)-i);
    memcpy(pInfo->model,buf,16);
  }
  if(pInfo->serialNumber) { // CK_CHAR serialNumber[16]; /* blank padded *
    pInfo->serialNumber[15] = '\0';
    i = sprintf(buf,"%s%s",MY_TOKEN_SER,pInfo->serialNumber);
    memset(&buf[i],' ',sizeof(buf)-i);
    memcpy(pInfo->serialNumber,buf,16);
  }
#endif // FOOP
  
  pInfo->flags |= CKF_RNG; //  must have for BIND pkcs11
  
  return rv;

#ifdef FOOP
  if(pInfo == NULL) {
    DEBUG_LOG("NULL pInfo\n");
    return CKR_FUNCTION_FAILED;
  }

  DEBUG_LOG("slotID:%d\n",slotID);
  
  // dont care about slot ID since we only have one slot
  memset(pInfo,0,sizeof(CK_TOKEN_INFO));
  strncpy(pInfo->label,MY_TOKEN_NAME,15); // CK_UTF8CHAR label[32]; /* blank padded */
  strncpy(pInfo->manufacturerID,"DC COMMUNICATIONS INC",31); // CK_UTF8CHAR manufacturerID[32]; 
  strncpy(pInfo->model,MY_TOKEN_MODEL,15); // CK_UTF8CHAR model[16]; /* blank padded */
  strncpy(pInfo->serialNumber,MY_TOKEN_SERIAL,15); // CK_CHAR serialNumber[16]; /* blank padded */
  pInfo->flags = CKF_RNG; //  must have

  pInfo->ulMaxSessionCount = 10;
  pInfo->ulSessionCount = 0;
  pInfo->ulMaxRwSessionCount = 0;
  pInfo->ulMaxPinLen = 8;
  pInfo->ulMinPinLen = 4;
  pInfo->ulTotalPublicMemory = 0;
  pInfo->ulFreePublicMemory = 0;
  pInfo->ulTotalPrivateMemory = 0;
  pInfo->ulFreePrivateMemory = 0;

  pInfo->hardwareVersion.major = 0;
  pInfo->hardwareVersion.minor = 1;
  pInfo->firmwareVersion.major = 0;
  pInfo->firmwareVersion.minor = 1;
  
  return CKR_OK;
#endif // FOOP

}

CK_RV C_GetSlotInfo(CK_SLOT_ID       slotID,
		    CK_SLOT_INFO_PTR pInfo)
{
  DEBUG_LOG("\n");
  if(flst == NULL) return CKR_CRYPTOKI_NOT_INITIALIZED;
  return flst->C_GetSlotInfo(slotID,pInfo);  
}

// Use OpenSSL for Verify operations.
// Good for dnssec-signzone as a verification against smarcard sigining operations
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/objects.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include <openssl/ecdsa.h>
#include <openssl/ec.h>

static int verify_mechanism=0;
static MD5_CTX verify_md5ctx;
static SHA_CTX verify_sha1ctx;
static SHA256_CTX verify_sha256ctx;
static SHA512_CTX verify_sha512ctx;
static RSA *verify_rsakey;
static EC_KEY *verify_ecckey;
static int openssl_first=1;

CK_RV C_VerifyInit(
 CK_SESSION_HANDLE hSession,    /* the session's handle */
 CK_MECHANISM_PTR  pMechanism,  /* the verification mechanism */
 CK_OBJECT_HANDLE  hKey         /* verification key */
 )
{
  DEBUG_LOG("sh:0x%08X\n",hSession);
  if(flst == NULL) return CKR_CRYPTOKI_NOT_INITIALIZED;

  DEBUG_LOG("hKey:%p\n",hKey);
  
  //return flst->C_VerifyInit(hSession,pMechanism,hKey);

  if(openssl_first) {
    /* Init OPENSSL */
    SSL_load_error_strings();
    /* SSLeay_add_ssl_algorithms();/**/

    /* Start memory check */
    /*CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);/**/

    /* Init of error messages */
    ERR_load_crypto_strings();

    /*SSLeay_add_all_algorithms();/**/
    OpenSSL_add_all_algorithms();

    openssl_first = 0;
  }
  
  switch(pMechanism->mechanism) {
  case CKM_MD5_RSA_PKCS: DEBUG_LOG("CKM_MD5_RSA_PKCS\n");
    if(!MD5_Init(&verify_md5ctx)) {
      DEBUG_LOG("Cannot open objects directory\n");
      return CKR_FUNCTION_FAILED;
    }
    verify_rsakey = RSA_new();
    break;
  case CKM_SHA1_RSA_PKCS: DEBUG_LOG("CKM_SHA1_RSA_PKCS\n");
    if(!SHA1_Init(&verify_sha1ctx)) {
      DEBUG_LOG("Cannot open objects directory\n");
      return CKR_FUNCTION_FAILED;
    }
    verify_rsakey = RSA_new();
    break;
  case CKM_SHA256_RSA_PKCS: DEBUG_LOG("CKM_SHA256_RSA_PKCS\n");
    if(!SHA256_Init(&verify_sha256ctx)) {
      DEBUG_LOG("Cannot open objects directory\n");
      return CKR_FUNCTION_FAILED;
    }
    verify_rsakey = RSA_new();
    break;
  case CKM_SHA512_RSA_PKCS: DEBUG_LOG("CKM_SHA512_RSA_PKCS\n");
    if(!SHA512_Init(&verify_sha512ctx)) {
      DEBUG_LOG("Cannot open objects directory\n");
      return CKR_FUNCTION_FAILED;
    }
    verify_rsakey = RSA_new();
    break;
  case CKM_ECDSA:
    verify_ecckey = EC_KEY_new();
    break;
  default: DEBUG_LOG("Unsupported mechanism 0x%x\n",pMechanism->mechanism);
    return CKR_FUNCTION_FAILED;
  }
  
  verify_mechanism = pMechanism->mechanism;  

  uint8_t *p;
  CK_ULONG ptype,plen;
  uint8_t secp256r1[]={0x06,0x08,0x2A,0x86,0x48,0xCE,0x3D,0x03,0x01,0x07};
  // https://www.ietf.org/rfc/rfc5480.txt
  EC_POINT *ec_p;
  EC_GROUP *ec_g;
  BN_CTX *ec_ctx;
  
  ec_ctx = BN_CTX_new();
  
  p = (uint8_t *)hKey;
  for(;;) {
    ptype = *(CK_ULONG *)p; p += sizeof(CK_ULONG);
    plen = *(CK_ULONG *)p; p += sizeof(CK_ULONG);
    DEBUG_LOG("  %s len:%u\n",cka_str(ptype),plen);
    rdump(p,plen);
    
    if(ptype == 0x12345678) break; // end of object attribute
    
    switch(ptype) {
    case CKA_MODULUS:
      DEBUG_LOG("==== mod\n");
      verify_rsakey->n = BN_bin2bn(p,plen,NULL);
      break;
    case CKA_PUBLIC_EXPONENT:
      DEBUG_LOG("==== exp\n");
      verify_rsakey->e = BN_bin2bn(p,plen,NULL);
      break;
    case CKA_ECDSA_PARAMS:
      DEBUG_LOG("==== ecdsa params\n");
      if(plen == 10 && memcmp(secp256r1,p,plen) == 0) {
	
	ec_g = EC_GROUP_new_by_curve_name(NID_secp256k1);
	// EC_KEY_set_group(verify_ecckey,ec_g);
	//EC_GROUP_free(ec_g);
	
	if(!SHA256_Init(&verify_sha256ctx)) {
	  DEBUG_LOG("Cannot open objects directory\n");
	  return CKR_FUNCTION_FAILED;
	}
      }
      break;
    case CKA_EC_POINT:
      DEBUG_LOG("==== ec point\n");
      ec_p = EC_POINT_new(ec_g);
      EC_POINT_oct2point(ec_g,ec_p,p,plen,ec_ctx);
      EC_KEY_set_group(verify_ecckey,ec_g);
      

      break;
    default: break;
    }
    p += plen;
  }
  
  return CKR_OK;  
}
CK_RV C_VerifyUpdate(
 CK_SESSION_HANDLE hSession,  /* the session's handle */
 CK_BYTE_PTR       pPart,     /* signed data */
 CK_ULONG          ulPartLen  /* length of signed data */
 )
{
  DEBUG_LOG("sh:0x%08X\n",hSession);
  if(flst == NULL) return CKR_CRYPTOKI_NOT_INITIALIZED;
  if(verify_mechanism == 0) {
    DEBUG_LOG("Not initialized\n");
    return CKR_FUNCTION_FAILED;
  }

  switch(verify_mechanism) {
  case CKM_MD5_RSA_PKCS: DEBUG_LOG("CKM_MD5_RSA_PKCS\n");
    if(!MD5_Update(&verify_md5ctx,pPart,ulPartLen)) {
      DEBUG_LOG("Cannot open objects directory\n");
      return CKR_FUNCTION_FAILED;
    }
    break;
  case CKM_SHA1_RSA_PKCS: DEBUG_LOG("CKM_SHA1_RSA_PKCS\n");
    if(!SHA1_Update(&verify_sha1ctx,pPart,ulPartLen)) {
      DEBUG_LOG("Cannot open objects directory\n");
      return CKR_FUNCTION_FAILED;
    }
    break;
  case CKM_SHA256_RSA_PKCS: DEBUG_LOG("CKM_SHA256_RSA_PKCS\n");
    if(!SHA256_Update(&verify_sha256ctx,pPart,ulPartLen)) {
      DEBUG_LOG("Cannot open objects directory\n");
      return CKR_FUNCTION_FAILED;
    }
    break;
  case CKM_SHA512_RSA_PKCS: DEBUG_LOG("CKM_SHA512_RSA_PKCS\n");
    if(!SHA512_Update(&verify_sha512ctx,pPart,ulPartLen)) {
      DEBUG_LOG("Cannot open objects directory\n");
      return CKR_FUNCTION_FAILED;
    }    
    break;
  default: DEBUG_LOG("Unsupported mechanism %d\n",verify_mechanism);
    return CKR_FUNCTION_FAILED;
  }
  
  return CKR_OK;
}
CK_RV C_VerifyFinal(
 CK_SESSION_HANDLE hSession,       /* the session's handle */
 CK_BYTE_PTR       pSignature,     /* signature to verify */
 CK_ULONG          ulSignatureLen  /* signature length */
 )
{
  uint8_t md[1024];
  int mdlen,mdtype;
  
  DEBUG_LOG("sh:0x%08X\n",hSession);
  if(flst == NULL) return CKR_CRYPTOKI_NOT_INITIALIZED;

  switch(verify_mechanism) {
  case CKM_MD5_RSA_PKCS: DEBUG_LOG("CKM_MD5_RSA_PKCS\n");
    if(!MD5_Final(md,&verify_md5ctx)) {
      DEBUG_LOG("Cannot open objects directory\n");
      return CKR_FUNCTION_FAILED;
    }
    mdlen = 16;
    mdtype = NID_md5;
    break;
  case CKM_SHA1_RSA_PKCS: DEBUG_LOG("CKM_SHA1_RSA_PKCS\n");
    if(!SHA1_Final(md,&verify_sha1ctx)) {
      DEBUG_LOG("Cannot open objects directory\n");
      return CKR_FUNCTION_FAILED;
    }
    mdlen = 20;
    mdtype = NID_sha1;
    break;
  case CKM_SHA256_RSA_PKCS: DEBUG_LOG("CKM_SHA256_RSA_PKCS\n");
    if(!SHA256_Final(md,&verify_sha256ctx)) {
      DEBUG_LOG("Cannot open objects directory\n");
      return CKR_FUNCTION_FAILED;
    }
    mdlen = 32;
    mdtype = NID_sha256;
    break;
  case CKM_SHA512_RSA_PKCS: DEBUG_LOG("CKM_SHA512_RSA_PKCS\n");
    if(!SHA512_Final(md,&verify_sha512ctx)) {
      DEBUG_LOG("Cannot open objects directory\n");
      return CKR_FUNCTION_FAILED;
    }
    mdlen = 64;
    mdtype = NID_sha512;
    break;
  default: DEBUG_LOG("Unsupported mechanism %d\n",verify_mechanism);
    return CKR_FUNCTION_FAILED;
  }
  
  DEBUG_LOG("data n:%d\n",mdlen);
  rdump(md,mdlen);
  DEBUG_LOG("sig n:%d\n",ulSignatureLen);
  //rdump(pSignature,ulSignatureLen);

  
  if(!RSA_verify(mdtype,md,mdlen,pSignature,ulSignatureLen,verify_rsakey)) {
    DEBUG_LOG("RSA_verify failed\n");
    RSA_free(verify_rsakey);
    return CKR_FUNCTION_FAILED;
  }
  RSA_free(verify_rsakey);

#ifdef FOOP  
  if(!ECDSA_verify(0,md,mdlen,pSignature,ulSignatureLen,verify_ecckey)) {
    DEBUG_LOG("ECDSA_verify failed\n");
    EC_KEY_free(verify_ecckey);
    return CKR_FUNCTION_FAILED;
  }
  EC_KEY_free(verify_ecckey);
#endif
  
  return CKR_OK;
}
CK_RV C_Verify(
 CK_SESSION_HANDLE hSession,       /* the session's handle */
 CK_BYTE_PTR       pData,          /* signed data */
 CK_ULONG          ulDataLen,      /* length of signed data */
 CK_BYTE_PTR       pSignature,     /* signature */
 CK_ULONG          ulSignatureLen  /* signature length*/
 )
{
  DEBUG_LOG("sh:0x%08X\n",hSession);
  if(flst == NULL) return CKR_CRYPTOKI_NOT_INITIALIZED;
  
  DEBUG_LOG("data n:%d\n",ulDataLen);
  rdump(pData,ulDataLen);
  DEBUG_LOG("sig n:%d\n",ulSignatureLen);
  rdump(pSignature,ulSignatureLen);

  if(!ECDSA_verify(0,pData,ulDataLen,pSignature,ulSignatureLen,verify_ecckey)) {
    DEBUG_LOG("ECDSA_verify failed\n");
    EC_KEY_free(verify_ecckey);
    return CKR_FUNCTION_FAILED;
  }
  EC_KEY_free(verify_ecckey);

  return CKR_OK;
}

CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppfl)
{
  static int gotfunctions=0;

  if(gotfunctions) return CKR_OK;
  
  //initialize some things stuff

  DEBUG_LOG("\n");

  memset(&FuncList,0,sizeof(FuncList));
  
  FuncList.version.major = VERSION_MAJOR;
  FuncList.version.minor = VERSION_MINOR;
  FuncList.C_Initialize = C_Initialize;
  FuncList.C_Finalize = C_Finalize;
  //FuncList.C_GetInfo = C_GetInfo;  
  FuncList.C_GetFunctionList = C_GetFunctionList;
  FuncList.C_GetSlotList = C_GetSlotList;
  FuncList.C_GetSlotInfo = C_GetSlotInfo;
  
  FuncList.C_GetTokenInfo = C_GetTokenInfo;  
  //FuncList.C_GetMechanismList = C_GetMechanismList;
  FuncList.C_GetMechanismInfo = C_GetMechanismInfo; // FOO
  //FuncList.C_InitToken = C_InitToken;
  //FuncList.C_InitPIN = C_InitPIN;
  //FuncList.C_SetPIN = C_SetPIN;
  FuncList.C_OpenSession = C_OpenSession;
  FuncList.C_CloseSession = C_CloseSession;
  //FuncList.C_CloseAllSessions = C_CloseAllSessions;
  //FuncList.C_GetSessionInfo = C_GetSessionInfo;
  //FuncList.C_GetOperationState = C_GetOperationState;
  //FuncList.C_SetOperationState = C_SetOperationState;
  FuncList.C_Login = C_Login;
  FuncList.C_Logout = C_Logout;
  FuncList.C_CreateObject = C_CreateObject;
  //FuncList.C_CopyObject = C_CopyObject;
  FuncList.C_DestroyObject = C_DestroyObject;
  //FuncList.C_GetObjectSize = C_GetObjectSize;
  FuncList.C_GetAttributeValue = C_GetAttributeValue;
  FuncList.C_SetAttributeValue = C_SetAttributeValue;
  FuncList.C_FindObjectsInit = C_FindObjectsInit;
  FuncList.C_FindObjects = C_FindObjects;
  FuncList.C_FindObjectsFinal = C_FindObjectsFinal;
  //FuncList.C_EncryptInit = C_EncryptInit;
  //FuncList.C_Encrypt = C_Encrypt;
  //FuncList.C_EncryptUpdate = C_EncryptUpdate;
  //FuncList.C_EncryptFinal = C_EncryptFinal;
  //FuncList.C_DecryptInit = C_DecryptInit;
  //FuncList.C_Decrypt = C_Decrypt;
  //FuncList.C_DecryptUpdate = C_DecryptUpdate;
  //FuncList.C_DecryptFinal = C_DecryptFinal;
  FuncList.C_DigestInit = C_DigestInit; // FOOP
  FuncList.C_Digest = C_Digest; // FOOP
  FuncList.C_DigestUpdate = C_DigestUpdate; // FOOP
  FuncList.C_DigestKey = C_DigestKey; // FOOP
  FuncList.C_DigestFinal = C_DigestFinal; // FOOP
  FuncList.C_SignInit = C_SignInit;
  FuncList.C_Sign = C_Sign;
  FuncList.C_SignUpdate = C_SignUpdate;
  FuncList.C_SignFinal = C_SignFinal;
  //FuncList.C_SignRecoverInit = C_SignRecoverInit;
  //FuncList.C_SignRecover = C_SignRecover;
  FuncList.C_VerifyInit = C_VerifyInit;
  FuncList.C_Verify = C_Verify;
  //FuncList.C_VerifyUpdate = C_VerifyUpdate;
  //FuncList.C_VerifyFinal = C_VerifyFinal;
  //FuncList.C_VerifyRecoverInit = C_VerifyRecoverInit;
  //FuncList.C_VerifyRecover = C_VerifyRecover;
  //FuncList.C_DigestEncryptUpdate = C_DigestEncryptUpdate;
  //FuncList.C_DecryptDigestUpdate = C_DecryptDigestUpdate;
  //FuncList.C_SignEncryptUpdate = C_SignEncryptUpdate;
  //FuncList.C_DecryptVerifyUpdate = C_DecryptVerifyUpdate;
  //FuncList.C_GenerateKey = C_GenerateKey;
  FuncList.C_GenerateKeyPair = C_GenerateKeyPair;
  //FuncList.C_WrapKey = C_WrapKey;
  //FuncList.C_UnwrapKey = C_UnwrapKey;
  //FuncList.C_DeriveKey = C_DeriveKey;
  //FuncList.C_SeedRandom = C_SeedRandom;
  FuncList.C_GenerateRandom = C_GenerateRandom;
  //FuncList.C_GetFunctionStatus = C_GetFunctionStatus;
  //FuncList.C_CancelFunction = C_CancelFunction;
  //FuncList.C_WaitForSlotEvent = C_WaitForSlotEvent;

  if(ppfl) {
    (*ppfl) = &FuncList;
    gotfunctions = 1;
    return CKR_OK;
  }
  return CKR_ARGUMENTS_BAD;
}

