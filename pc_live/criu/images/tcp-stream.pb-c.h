/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: tcp-stream.proto */

#ifndef PROTOBUF_C_tcp_2dstream_2eproto__INCLUDED
#define PROTOBUF_C_tcp_2dstream_2eproto__INCLUDED

#include <protobuf-c/protobuf-c.h>

PROTOBUF_C__BEGIN_DECLS

#if PROTOBUF_C_VERSION_NUMBER < 1000000
# error This file was generated by a newer version of protoc-c which is incompatible with your libprotobuf-c headers. Please update your headers.
#elif 1002001 < PROTOBUF_C_MIN_COMPILER_VERSION
# error This file was generated by an older version of protoc-c which is incompatible with your libprotobuf-c headers. Please regenerate this file with a newer version of protoc-c.
#endif

#include "opts.pb-c.h"

typedef struct _TcpStreamEntry TcpStreamEntry;


/* --- enums --- */


/* --- messages --- */

struct  _TcpStreamEntry
{
  ProtobufCMessage base;
  uint32_t inq_len;
  uint32_t inq_seq;
  /*
   * unsent and sent data in the send queue
   */
  uint32_t outq_len;
  uint32_t outq_seq;
  /*
   * TCPI_OPT_ bits 
   */
  uint32_t opt_mask;
  uint32_t snd_wscale;
  uint32_t mss_clamp;
  protobuf_c_boolean has_rcv_wscale;
  uint32_t rcv_wscale;
  protobuf_c_boolean has_timestamp;
  uint32_t timestamp;
  protobuf_c_boolean has_cork;
  protobuf_c_boolean cork;
  protobuf_c_boolean has_nodelay;
  protobuf_c_boolean nodelay;
  /*
   * unsent data in the send queue 
   */
  protobuf_c_boolean has_unsq_len;
  uint32_t unsq_len;
  protobuf_c_boolean has_snd_wl1;
  uint32_t snd_wl1;
  protobuf_c_boolean has_snd_wnd;
  uint32_t snd_wnd;
  protobuf_c_boolean has_max_window;
  uint32_t max_window;
  protobuf_c_boolean has_rcv_wnd;
  uint32_t rcv_wnd;
  protobuf_c_boolean has_rcv_wup;
  uint32_t rcv_wup;
};
#define TCP_STREAM_ENTRY__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&tcp_stream_entry__descriptor) \
    , 0, 0, 0, 0, 0, 0, 0, 0,0, 0,0, 0,0, 0,0, 0,0, 0,0, 0,0, 0,0, 0,0, 0,0 }


/* TcpStreamEntry methods */
void   tcp_stream_entry__init
                     (TcpStreamEntry         *message);
size_t tcp_stream_entry__get_packed_size
                     (const TcpStreamEntry   *message);
size_t tcp_stream_entry__pack
                     (const TcpStreamEntry   *message,
                      uint8_t             *out);
size_t tcp_stream_entry__pack_to_buffer
                     (const TcpStreamEntry   *message,
                      ProtobufCBuffer     *buffer);
TcpStreamEntry *
       tcp_stream_entry__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   tcp_stream_entry__free_unpacked
                     (TcpStreamEntry *message,
                      ProtobufCAllocator *allocator);
/* --- per-message closures --- */

typedef void (*TcpStreamEntry_Closure)
                 (const TcpStreamEntry *message,
                  void *closure_data);

/* --- services --- */


/* --- descriptors --- */

extern const ProtobufCMessageDescriptor tcp_stream_entry__descriptor;

PROTOBUF_C__END_DECLS


#endif  /* PROTOBUF_C_tcp_2dstream_2eproto__INCLUDED */