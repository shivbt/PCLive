/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: time.proto */

#ifndef PROTOBUF_C_time_2eproto__INCLUDED
#define PROTOBUF_C_time_2eproto__INCLUDED

#include <protobuf-c/protobuf-c.h>

PROTOBUF_C__BEGIN_DECLS

#if PROTOBUF_C_VERSION_NUMBER < 1000000
# error This file was generated by a newer version of protoc-c which is incompatible with your libprotobuf-c headers. Please update your headers.
#elif 1002001 < PROTOBUF_C_MIN_COMPILER_VERSION
# error This file was generated by an older version of protoc-c which is incompatible with your libprotobuf-c headers. Please regenerate this file with a newer version of protoc-c.
#endif


typedef struct _Timeval Timeval;


/* --- enums --- */


/* --- messages --- */

struct  _Timeval
{
  ProtobufCMessage base;
  uint64_t tv_sec;
  uint64_t tv_usec;
};
#define TIMEVAL__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&timeval__descriptor) \
    , 0, 0 }


/* Timeval methods */
void   timeval__init
                     (Timeval         *message);
size_t timeval__get_packed_size
                     (const Timeval   *message);
size_t timeval__pack
                     (const Timeval   *message,
                      uint8_t             *out);
size_t timeval__pack_to_buffer
                     (const Timeval   *message,
                      ProtobufCBuffer     *buffer);
Timeval *
       timeval__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   timeval__free_unpacked
                     (Timeval *message,
                      ProtobufCAllocator *allocator);
/* --- per-message closures --- */

typedef void (*Timeval_Closure)
                 (const Timeval *message,
                  void *closure_data);

/* --- services --- */


/* --- descriptors --- */

extern const ProtobufCMessageDescriptor timeval__descriptor;

PROTOBUF_C__END_DECLS


#endif  /* PROTOBUF_C_time_2eproto__INCLUDED */