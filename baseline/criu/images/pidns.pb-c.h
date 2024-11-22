/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: pidns.proto */

#ifndef PROTOBUF_C_pidns_2eproto__INCLUDED
#define PROTOBUF_C_pidns_2eproto__INCLUDED

#include <protobuf-c/protobuf-c.h>

PROTOBUF_C__BEGIN_DECLS

#if PROTOBUF_C_VERSION_NUMBER < 1000000
# error This file was generated by a newer version of protoc-c which is incompatible with your libprotobuf-c headers. Please update your headers.
#elif 1002001 < PROTOBUF_C_MIN_COMPILER_VERSION
# error This file was generated by an older version of protoc-c which is incompatible with your libprotobuf-c headers. Please regenerate this file with a newer version of protoc-c.
#endif


typedef struct _PidnsEntry PidnsEntry;


/* --- enums --- */


/* --- messages --- */

struct  _PidnsEntry
{
  ProtobufCMessage base;
  char *ext_key;
};
#define PIDNS_ENTRY__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&pidns_entry__descriptor) \
    , NULL }


/* PidnsEntry methods */
void   pidns_entry__init
                     (PidnsEntry         *message);
size_t pidns_entry__get_packed_size
                     (const PidnsEntry   *message);
size_t pidns_entry__pack
                     (const PidnsEntry   *message,
                      uint8_t             *out);
size_t pidns_entry__pack_to_buffer
                     (const PidnsEntry   *message,
                      ProtobufCBuffer     *buffer);
PidnsEntry *
       pidns_entry__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   pidns_entry__free_unpacked
                     (PidnsEntry *message,
                      ProtobufCAllocator *allocator);
/* --- per-message closures --- */

typedef void (*PidnsEntry_Closure)
                 (const PidnsEntry *message,
                  void *closure_data);

/* --- services --- */


/* --- descriptors --- */

extern const ProtobufCMessageDescriptor pidns_entry__descriptor;

PROTOBUF_C__END_DECLS


#endif  /* PROTOBUF_C_pidns_2eproto__INCLUDED */
