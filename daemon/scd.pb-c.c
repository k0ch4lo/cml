/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: scd.proto */

/* Do not generate deprecated warnings for self */
#ifndef PROTOBUF_C__NO_DEPRECATED
#define PROTOBUF_C__NO_DEPRECATED
#endif

#include "scd.pb-c.h"
void   daemon_to_token__init
                     (DaemonToToken         *message)
{
  static DaemonToToken init_value = DAEMON_TO_TOKEN__INIT;
  *message = init_value;
}
size_t daemon_to_token__get_packed_size
                     (const DaemonToToken *message)
{
  assert(message->base.descriptor == &daemon_to_token__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t daemon_to_token__pack
                     (const DaemonToToken *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &daemon_to_token__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t daemon_to_token__pack_to_buffer
                     (const DaemonToToken *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &daemon_to_token__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
DaemonToToken *
       daemon_to_token__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (DaemonToToken *)
     protobuf_c_message_unpack (&daemon_to_token__descriptor,
                                allocator, len, data);
}
void   daemon_to_token__free_unpacked
                     (DaemonToToken *message,
                      ProtobufCAllocator *allocator)
{
  assert(message->base.descriptor == &daemon_to_token__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   token_to_daemon__init
                     (TokenToDaemon         *message)
{
  static TokenToDaemon init_value = TOKEN_TO_DAEMON__INIT;
  *message = init_value;
}
size_t token_to_daemon__get_packed_size
                     (const TokenToDaemon *message)
{
  assert(message->base.descriptor == &token_to_daemon__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t token_to_daemon__pack
                     (const TokenToDaemon *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &token_to_daemon__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t token_to_daemon__pack_to_buffer
                     (const TokenToDaemon *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &token_to_daemon__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
TokenToDaemon *
       token_to_daemon__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (TokenToDaemon *)
     protobuf_c_message_unpack (&token_to_daemon__descriptor,
                                allocator, len, data);
}
void   token_to_daemon__free_unpacked
                     (TokenToDaemon *message,
                      ProtobufCAllocator *allocator)
{
  assert(message->base.descriptor == &token_to_daemon__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
static const ProtobufCEnumValue daemon_to_token__code__enum_values_by_number[7] =
{
  { "LOCK", "DAEMON_TO_TOKEN__CODE__LOCK", 1 },
  { "UNLOCK", "DAEMON_TO_TOKEN__CODE__UNLOCK", 2 },
  { "WRAP_KEY", "DAEMON_TO_TOKEN__CODE__WRAP_KEY", 10 },
  { "UNWRAP_KEY", "DAEMON_TO_TOKEN__CODE__UNWRAP_KEY", 11 },
  { "DERIVE_KEY", "DAEMON_TO_TOKEN__CODE__DERIVE_KEY", 20 },
  { "CRYPTO_HASH_FILE", "DAEMON_TO_TOKEN__CODE__CRYPTO_HASH_FILE", 50 },
  { "CRYPTO_VERIFY_FILE", "DAEMON_TO_TOKEN__CODE__CRYPTO_VERIFY_FILE", 60 },
};
static const ProtobufCIntRange daemon_to_token__code__value_ranges[] = {
{1, 0},{10, 2},{20, 4},{50, 5},{60, 6},{0, 7}
};
static const ProtobufCEnumValueIndex daemon_to_token__code__enum_values_by_name[7] =
{
  { "CRYPTO_HASH_FILE", 5 },
  { "CRYPTO_VERIFY_FILE", 6 },
  { "DERIVE_KEY", 4 },
  { "LOCK", 0 },
  { "UNLOCK", 1 },
  { "UNWRAP_KEY", 3 },
  { "WRAP_KEY", 2 },
};
const ProtobufCEnumDescriptor daemon_to_token__code__descriptor =
{
  PROTOBUF_C__ENUM_DESCRIPTOR_MAGIC,
  "DaemonToToken.Code",
  "Code",
  "DaemonToToken__Code",
  "",
  7,
  daemon_to_token__code__enum_values_by_number,
  7,
  daemon_to_token__code__enum_values_by_name,
  5,
  daemon_to_token__code__value_ranges,
  NULL,NULL,NULL,NULL   /* reserved[1234] */
};
static const ProtobufCFieldDescriptor daemon_to_token__field_descriptors[11] =
{
  {
    "code",
    1,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_ENUM,
    0,   /* quantifier_offset */
    offsetof(DaemonToToken, code),
    &daemon_to_token__code__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "token_pin",
    2,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(DaemonToToken, token_pin),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "unwrapped_key",
    10,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_BYTES,
    offsetof(DaemonToToken, has_unwrapped_key),
    offsetof(DaemonToToken, unwrapped_key),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "wrapped_key",
    11,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_BYTES,
    offsetof(DaemonToToken, has_wrapped_key),
    offsetof(DaemonToToken, wrapped_key),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "pbkdf_pass",
    20,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(DaemonToToken, pbkdf_pass),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "pbkdf_salt",
    21,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_BYTES,
    offsetof(DaemonToToken, has_pbkdf_salt),
    offsetof(DaemonToToken, pbkdf_salt),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "hash_algo",
    50,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_ENUM,
    offsetof(DaemonToToken, has_hash_algo),
    offsetof(DaemonToToken, hash_algo),
    &hash_algo__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "hash_file",
    51,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(DaemonToToken, hash_file),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "verify_data_file",
    60,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(DaemonToToken, verify_data_file),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "verify_sig_file",
    61,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(DaemonToToken, verify_sig_file),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "verify_cert_file",
    62,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(DaemonToToken, verify_cert_file),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned daemon_to_token__field_indices_by_name[] = {
  0,   /* field[0] = code */
  6,   /* field[6] = hash_algo */
  7,   /* field[7] = hash_file */
  4,   /* field[4] = pbkdf_pass */
  5,   /* field[5] = pbkdf_salt */
  1,   /* field[1] = token_pin */
  2,   /* field[2] = unwrapped_key */
  10,   /* field[10] = verify_cert_file */
  8,   /* field[8] = verify_data_file */
  9,   /* field[9] = verify_sig_file */
  3,   /* field[3] = wrapped_key */
};
static const ProtobufCIntRange daemon_to_token__number_ranges[5 + 1] =
{
  { 1, 0 },
  { 10, 2 },
  { 20, 4 },
  { 50, 6 },
  { 60, 8 },
  { 0, 11 }
};
const ProtobufCMessageDescriptor daemon_to_token__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "DaemonToToken",
  "DaemonToToken",
  "DaemonToToken",
  "",
  sizeof(DaemonToToken),
  11,
  daemon_to_token__field_descriptors,
  daemon_to_token__field_indices_by_name,
  5,  daemon_to_token__number_ranges,
  (ProtobufCMessageInit) daemon_to_token__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCEnumValue token_to_daemon__code__enum_values_by_number[15] =
{
  { "DERIVED_KEY", "TOKEN_TO_DAEMON__CODE__DERIVED_KEY", 20 },
  { "UNLOCK_FAILED", "TOKEN_TO_DAEMON__CODE__UNLOCK_FAILED", 21 },
  { "UNLOCK_SUCCESSFUL", "TOKEN_TO_DAEMON__CODE__UNLOCK_SUCCESSFUL", 22 },
  { "LOCK_FAILED", "TOKEN_TO_DAEMON__CODE__LOCK_FAILED", 23 },
  { "LOCK_SUCCESSFUL", "TOKEN_TO_DAEMON__CODE__LOCK_SUCCESSFUL", 24 },
  { "PASSWD_WRONG", "TOKEN_TO_DAEMON__CODE__PASSWD_WRONG", 25 },
  { "WRAPPED_KEY", "TOKEN_TO_DAEMON__CODE__WRAPPED_KEY", 26 },
  { "UNWRAPPED_KEY", "TOKEN_TO_DAEMON__CODE__UNWRAPPED_KEY", 27 },
  { "LOCKED_TILL_REBOOT", "TOKEN_TO_DAEMON__CODE__LOCKED_TILL_REBOOT", 28 },
  { "CRYPTO_HASH_OK", "TOKEN_TO_DAEMON__CODE__CRYPTO_HASH_OK", 50 },
  { "CRYPTO_HASH_ERROR", "TOKEN_TO_DAEMON__CODE__CRYPTO_HASH_ERROR", 51 },
  { "CRYPTO_VERIFY_GOOD", "TOKEN_TO_DAEMON__CODE__CRYPTO_VERIFY_GOOD", 60 },
  { "CRYPTO_VERIFY_ERROR", "TOKEN_TO_DAEMON__CODE__CRYPTO_VERIFY_ERROR", 61 },
  { "CRYPTO_VERIFY_BAD_SIGNATURE", "TOKEN_TO_DAEMON__CODE__CRYPTO_VERIFY_BAD_SIGNATURE", 62 },
  { "CRYPTO_VERIFY_BAD_CERTIFICATE", "TOKEN_TO_DAEMON__CODE__CRYPTO_VERIFY_BAD_CERTIFICATE", 63 },
};
static const ProtobufCIntRange token_to_daemon__code__value_ranges[] = {
{20, 0},{50, 9},{60, 11},{0, 15}
};
static const ProtobufCEnumValueIndex token_to_daemon__code__enum_values_by_name[15] =
{
  { "CRYPTO_HASH_ERROR", 10 },
  { "CRYPTO_HASH_OK", 9 },
  { "CRYPTO_VERIFY_BAD_CERTIFICATE", 14 },
  { "CRYPTO_VERIFY_BAD_SIGNATURE", 13 },
  { "CRYPTO_VERIFY_ERROR", 12 },
  { "CRYPTO_VERIFY_GOOD", 11 },
  { "DERIVED_KEY", 0 },
  { "LOCKED_TILL_REBOOT", 8 },
  { "LOCK_FAILED", 3 },
  { "LOCK_SUCCESSFUL", 4 },
  { "PASSWD_WRONG", 5 },
  { "UNLOCK_FAILED", 1 },
  { "UNLOCK_SUCCESSFUL", 2 },
  { "UNWRAPPED_KEY", 7 },
  { "WRAPPED_KEY", 6 },
};
const ProtobufCEnumDescriptor token_to_daemon__code__descriptor =
{
  PROTOBUF_C__ENUM_DESCRIPTOR_MAGIC,
  "TokenToDaemon.Code",
  "Code",
  "TokenToDaemon__Code",
  "",
  15,
  token_to_daemon__code__enum_values_by_number,
  15,
  token_to_daemon__code__enum_values_by_name,
  3,
  token_to_daemon__code__value_ranges,
  NULL,NULL,NULL,NULL   /* reserved[1234] */
};
static const ProtobufCFieldDescriptor token_to_daemon__field_descriptors[5] =
{
  {
    "code",
    1,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_ENUM,
    0,   /* quantifier_offset */
    offsetof(TokenToDaemon, code),
    &token_to_daemon__code__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "unwrapped_key",
    10,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_BYTES,
    offsetof(TokenToDaemon, has_unwrapped_key),
    offsetof(TokenToDaemon, unwrapped_key),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "wrapped_key",
    11,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_BYTES,
    offsetof(TokenToDaemon, has_wrapped_key),
    offsetof(TokenToDaemon, wrapped_key),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "derived_key",
    20,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_BYTES,
    offsetof(TokenToDaemon, has_derived_key),
    offsetof(TokenToDaemon, derived_key),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "hash_value",
    50,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_BYTES,
    offsetof(TokenToDaemon, has_hash_value),
    offsetof(TokenToDaemon, hash_value),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned token_to_daemon__field_indices_by_name[] = {
  0,   /* field[0] = code */
  3,   /* field[3] = derived_key */
  4,   /* field[4] = hash_value */
  1,   /* field[1] = unwrapped_key */
  2,   /* field[2] = wrapped_key */
};
static const ProtobufCIntRange token_to_daemon__number_ranges[4 + 1] =
{
  { 1, 0 },
  { 10, 1 },
  { 20, 3 },
  { 50, 4 },
  { 0, 5 }
};
const ProtobufCMessageDescriptor token_to_daemon__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "TokenToDaemon",
  "TokenToDaemon",
  "TokenToDaemon",
  "",
  sizeof(TokenToDaemon),
  5,
  token_to_daemon__field_descriptors,
  token_to_daemon__field_indices_by_name,
  4,  token_to_daemon__number_ranges,
  (ProtobufCMessageInit) token_to_daemon__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCEnumValue hash_algo__enum_values_by_number[3] =
{
  { "SHA1", "HASH_ALGO__SHA1", 1 },
  { "SHA256", "HASH_ALGO__SHA256", 2 },
  { "SHA512", "HASH_ALGO__SHA512", 3 },
};
static const ProtobufCIntRange hash_algo__value_ranges[] = {
{1, 0},{0, 3}
};
static const ProtobufCEnumValueIndex hash_algo__enum_values_by_name[3] =
{
  { "SHA1", 0 },
  { "SHA256", 1 },
  { "SHA512", 2 },
};
const ProtobufCEnumDescriptor hash_algo__descriptor =
{
  PROTOBUF_C__ENUM_DESCRIPTOR_MAGIC,
  "HashAlgo",
  "HashAlgo",
  "HashAlgo",
  "",
  3,
  hash_algo__enum_values_by_number,
  3,
  hash_algo__enum_values_by_name,
  1,
  hash_algo__value_ranges,
  NULL,NULL,NULL,NULL   /* reserved[1234] */
};
