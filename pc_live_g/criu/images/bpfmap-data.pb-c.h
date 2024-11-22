/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: bpfmap-data.proto */

#ifndef PROTOBUF_C_bpfmap_2ddata_2eproto__INCLUDED
#define PROTOBUF_C_bpfmap_2ddata_2eproto__INCLUDED

#include <protobuf-c/protobuf-c.h>

PROTOBUF_C__BEGIN_DECLS

#if PROTOBUF_C_VERSION_NUMBER < 1000000
# error This file was generated by a newer version of protoc-c which is incompatible with your libprotobuf-c headers. Please update your headers.
#elif 1002001 < PROTOBUF_C_MIN_COMPILER_VERSION
# error This file was generated by an older version of protoc-c which is incompatible with your libprotobuf-c headers. Please regenerate this file with a newer version of protoc-c.
#endif


typedef struct _BpfmapDataEntry BpfmapDataEntry;


/* --- enums --- */


/* --- messages --- */

struct  _BpfmapDataEntry
{
  ProtobufCMessage base;
  uint32_t map_id;
  /*
   * Bytes required to store keys 
   */
  uint32_t keys_bytes;
  /*
   * Bytes required to store values 
   */
  uint32_t values_bytes;
  /*
   * Number of key-value pairs stored 
   */
  uint32_t count;
};
#define BPFMAP_DATA_ENTRY__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&bpfmap_data_entry__descriptor) \
    , 0, 0, 0, 0 }


/* BpfmapDataEntry methods */
void   bpfmap_data_entry__init
                     (BpfmapDataEntry         *message);
size_t bpfmap_data_entry__get_packed_size
                     (const BpfmapDataEntry   *message);
size_t bpfmap_data_entry__pack
                     (const BpfmapDataEntry   *message,
                      uint8_t             *out);
size_t bpfmap_data_entry__pack_to_buffer
                     (const BpfmapDataEntry   *message,
                      ProtobufCBuffer     *buffer);
BpfmapDataEntry *
       bpfmap_data_entry__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   bpfmap_data_entry__free_unpacked
                     (BpfmapDataEntry *message,
                      ProtobufCAllocator *allocator);
/* --- per-message closures --- */

typedef void (*BpfmapDataEntry_Closure)
                 (const BpfmapDataEntry *message,
                  void *closure_data);

/* --- services --- */


/* --- descriptors --- */

extern const ProtobufCMessageDescriptor bpfmap_data_entry__descriptor;

PROTOBUF_C__END_DECLS


#endif  /* PROTOBUF_C_bpfmap_2ddata_2eproto__INCLUDED */