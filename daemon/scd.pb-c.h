/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: scd.proto */

#ifndef PROTOBUF_C_scd_2eproto__INCLUDED
#define PROTOBUF_C_scd_2eproto__INCLUDED

#include <protobuf-c/protobuf-c.h>

PROTOBUF_C__BEGIN_DECLS

#if PROTOBUF_C_VERSION_NUMBER < 1000000
# error This file was generated by a newer version of protoc-c which is incompatible with your libprotobuf-c headers. Please update your headers.
#elif 1002001 < PROTOBUF_C_MIN_COMPILER_VERSION
# error This file was generated by an older version of protoc-c which is incompatible with your libprotobuf-c headers. Please regenerate this file with a newer version of protoc-c.
#endif


typedef struct _DaemonToToken DaemonToToken;
typedef struct _TokenToDaemon TokenToDaemon;


/* --- enums --- */

typedef enum _DaemonToToken__Code {
  /*
   * Locks the token
   */
  DAEMON_TO_TOKEN__CODE__LOCK = 1,
  /*
   * Unlocks the token (need [token_pin])
   */
  DAEMON_TO_TOKEN__CODE__UNLOCK = 2,
  /*
   * Wraps a key ([unwrapped_key])
   */
  DAEMON_TO_TOKEN__CODE__WRAP_KEY = 10,
  /*
   * Unwraps a key ([wrapped_key])
   */
  DAEMON_TO_TOKEN__CODE__UNWRAP_KEY = 11,
  /*
   * Derives a key from [pbdfk_salt] and [pbkdf_pass].
   */
  DAEMON_TO_TOKEN__CODE__DERIVE_KEY = 20,
  /*
   * crypto commands unrelated to actual secure element (FIXME move elsewhere?!)
   */
  /*
   * compute hash for file [hash_file]
   */
  DAEMON_TO_TOKEN__CODE__CRYPTO_HASH_FILE = 50,
  /*
   * verify certificate and signature on data given in [verify_*_file]
   */
  DAEMON_TO_TOKEN__CODE__CRYPTO_VERIFY_FILE = 60
    PROTOBUF_C__FORCE_ENUM_TO_BE_INT_SIZE(DAEMON_TO_TOKEN__CODE)
} DaemonToToken__Code;
typedef enum _TokenToDaemon__Code {
  /*
   * -> [derived_key]
   */
  TOKEN_TO_DAEMON__CODE__DERIVED_KEY = 20,
  /*
   * unlocking the token failed
   */
  TOKEN_TO_DAEMON__CODE__UNLOCK_FAILED = 21,
  /*
   * unlocking the token succeeded
   */
  TOKEN_TO_DAEMON__CODE__UNLOCK_SUCCESSFUL = 22,
  /*
   * locking the token failed
   */
  TOKEN_TO_DAEMON__CODE__LOCK_FAILED = 23,
  /*
   * locking the token succeeded
   */
  TOKEN_TO_DAEMON__CODE__LOCK_SUCCESSFUL = 24,
  /*
   * wrong password to unlock the token
   */
  TOKEN_TO_DAEMON__CODE__PASSWD_WRONG = 25,
  /*
   * -> [wrapped_key] 
   */
  TOKEN_TO_DAEMON__CODE__WRAPPED_KEY = 26,
  /*
   * -> [unwrapped key]
   */
  TOKEN_TO_DAEMON__CODE__UNWRAPPED_KEY = 27,
  TOKEN_TO_DAEMON__CODE__LOCKED_TILL_REBOOT = 28,
  /*
   * hash computed successfully and stored in hash_value
   */
  TOKEN_TO_DAEMON__CODE__CRYPTO_HASH_OK = 50,
  /*
   * some error occurred
   */
  TOKEN_TO_DAEMON__CODE__CRYPTO_HASH_ERROR = 51,
  /*
   * signature on data is valid
   */
  TOKEN_TO_DAEMON__CODE__CRYPTO_VERIFY_GOOD = 60,
  /*
   * some error occurred
   */
  TOKEN_TO_DAEMON__CODE__CRYPTO_VERIFY_ERROR = 61,
  /*
   * signature on data is invalid
   */
  TOKEN_TO_DAEMON__CODE__CRYPTO_VERIFY_BAD_SIGNATURE = 62,
  /*
   * certificate is invalid
   */
  TOKEN_TO_DAEMON__CODE__CRYPTO_VERIFY_BAD_CERTIFICATE = 63
    PROTOBUF_C__FORCE_ENUM_TO_BE_INT_SIZE(TOKEN_TO_DAEMON__CODE)
} TokenToDaemon__Code;
/*
 **
 * Supported hash algorithms.
 */
typedef enum _HashAlgo {
  HASH_ALGO__SHA1 = 1,
  HASH_ALGO__SHA256 = 2,
  HASH_ALGO__SHA512 = 3
    PROTOBUF_C__FORCE_ENUM_TO_BE_INT_SIZE(HASH_ALGO)
} HashAlgo;

/* --- messages --- */

struct  _DaemonToToken
{
  ProtobufCMessage base;
  DaemonToToken__Code code;
  /*
   * for unlocking the token
   */
  char *token_pin;
  /*
   * for wrapping a key
   */
  protobuf_c_boolean has_unwrapped_key;
  ProtobufCBinaryData unwrapped_key;
  /*
   * for (un)wrapping a key
   */
  protobuf_c_boolean has_wrapped_key;
  ProtobufCBinaryData wrapped_key;
  /*
   * for key derivation
   */
  char *pbkdf_pass;
  /*
   * for key derivation
   */
  protobuf_c_boolean has_pbkdf_salt;
  ProtobufCBinaryData pbkdf_salt;
  /*
   * determines hash algorithm for hashing
   */
  protobuf_c_boolean has_hash_algo;
  HashAlgo hash_algo;
  /*
   * the full path to the file to hash
   */
  char *hash_file;
  /*
   * file with data to verify
   */
  char *verify_data_file;
  /*
   * file with signature for data file
   */
  char *verify_sig_file;
  /*
   * file with certificate
   */
  char *verify_cert_file;
};
#define DAEMON_TO_TOKEN__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&daemon_to_token__descriptor) \
    , 0, NULL, 0,{0,NULL}, 0,{0,NULL}, NULL, 0,{0,NULL}, 0,0, NULL, NULL, NULL, NULL }


struct  _TokenToDaemon
{
  ProtobufCMessage base;
  TokenToDaemon__Code code;
  /*
   * unwrapped key in response to UNWRAP_KEY
   */
  protobuf_c_boolean has_unwrapped_key;
  ProtobufCBinaryData unwrapped_key;
  /*
   * wrapped key in response to WRAP_KEY
   */
  protobuf_c_boolean has_wrapped_key;
  ProtobufCBinaryData wrapped_key;
  /*
   * derived key in response to DERIVE_KEY
   */
  protobuf_c_boolean has_derived_key;
  ProtobufCBinaryData derived_key;
  /*
   * hash_value in reponse to CRYPTO_HASH_FILE
   */
  protobuf_c_boolean has_hash_value;
  ProtobufCBinaryData hash_value;
};
#define TOKEN_TO_DAEMON__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&token_to_daemon__descriptor) \
    , 0, 0,{0,NULL}, 0,{0,NULL}, 0,{0,NULL}, 0,{0,NULL} }


/* DaemonToToken methods */
void   daemon_to_token__init
                     (DaemonToToken         *message);
size_t daemon_to_token__get_packed_size
                     (const DaemonToToken   *message);
size_t daemon_to_token__pack
                     (const DaemonToToken   *message,
                      uint8_t             *out);
size_t daemon_to_token__pack_to_buffer
                     (const DaemonToToken   *message,
                      ProtobufCBuffer     *buffer);
DaemonToToken *
       daemon_to_token__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   daemon_to_token__free_unpacked
                     (DaemonToToken *message,
                      ProtobufCAllocator *allocator);
/* TokenToDaemon methods */
void   token_to_daemon__init
                     (TokenToDaemon         *message);
size_t token_to_daemon__get_packed_size
                     (const TokenToDaemon   *message);
size_t token_to_daemon__pack
                     (const TokenToDaemon   *message,
                      uint8_t             *out);
size_t token_to_daemon__pack_to_buffer
                     (const TokenToDaemon   *message,
                      ProtobufCBuffer     *buffer);
TokenToDaemon *
       token_to_daemon__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   token_to_daemon__free_unpacked
                     (TokenToDaemon *message,
                      ProtobufCAllocator *allocator);
/* --- per-message closures --- */

typedef void (*DaemonToToken_Closure)
                 (const DaemonToToken *message,
                  void *closure_data);
typedef void (*TokenToDaemon_Closure)
                 (const TokenToDaemon *message,
                  void *closure_data);

/* --- services --- */


/* --- descriptors --- */

extern const ProtobufCEnumDescriptor    hash_algo__descriptor;
extern const ProtobufCMessageDescriptor daemon_to_token__descriptor;
extern const ProtobufCEnumDescriptor    daemon_to_token__code__descriptor;
extern const ProtobufCMessageDescriptor token_to_daemon__descriptor;
extern const ProtobufCEnumDescriptor    token_to_daemon__code__descriptor;

PROTOBUF_C__END_DECLS


#endif  /* PROTOBUF_C_scd_2eproto__INCLUDED */
