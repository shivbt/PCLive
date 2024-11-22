/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: pipe.proto */

#ifndef PROTOBUF_C_pipe_2eproto__INCLUDED
#define PROTOBUF_C_pipe_2eproto__INCLUDED

#include <protobuf-c/protobuf-c.h>

PROTOBUF_C__BEGIN_DECLS

#if PROTOBUF_C_VERSION_NUMBER < 1000000
# error This file was generated by a newer version of protoc-c which is incompatible with your libprotobuf-c headers. Please update your headers.
#elif 1002001 < PROTOBUF_C_MIN_COMPILER_VERSION
# error This file was generated by an older version of protoc-c which is incompatible with your libprotobuf-c headers. Please regenerate this file with a newer version of protoc-c.
#endif

#include "opts.pb-c.h"
#include "fown.pb-c.h"

typedef struct _PipeEntry PipeEntry;


/* --- enums --- */


/* --- messages --- */

struct  _PipeEntry
{
  ProtobufCMessage base;
  uint32_t id;
  uint32_t pipe_id;
  uint32_t flags;
  FownEntry *fown;
};
#define PIPE_ENTRY__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&pipe_entry__descriptor) \
    , 0, 0, 0, NULL }


/* PipeEntry methods */
void   pipe_entry__init
                     (PipeEntry         *message);
size_t pipe_entry__get_packed_size
                     (const PipeEntry   *message);
size_t pipe_entry__pack
                     (const PipeEntry   *message,
                      uint8_t             *out);
size_t pipe_entry__pack_to_buffer
                     (const PipeEntry   *message,
                      ProtobufCBuffer     *buffer);
PipeEntry *
       pipe_entry__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   pipe_entry__free_unpacked
                     (PipeEntry *message,
                      ProtobufCAllocator *allocator);
/* --- per-message closures --- */

typedef void (*PipeEntry_Closure)
                 (const PipeEntry *message,
                  void *closure_data);

/* --- services --- */


/* --- descriptors --- */

extern const ProtobufCMessageDescriptor pipe_entry__descriptor;

PROTOBUF_C__END_DECLS


#endif  /* PROTOBUF_C_pipe_2eproto__INCLUDED */