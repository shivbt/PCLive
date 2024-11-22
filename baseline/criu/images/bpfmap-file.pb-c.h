/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: bpfmap-file.proto */

#ifndef PROTOBUF_C_bpfmap_2dfile_2eproto__INCLUDED
#define PROTOBUF_C_bpfmap_2dfile_2eproto__INCLUDED

#include <protobuf-c/protobuf-c.h>

PROTOBUF_C__BEGIN_DECLS

#if PROTOBUF_C_VERSION_NUMBER < 1000000
# error This file was generated by a newer version of protoc-c which is incompatible with your libprotobuf-c headers. Please update your headers.
#elif 1002001 < PROTOBUF_C_MIN_COMPILER_VERSION
# error This file was generated by an older version of protoc-c which is incompatible with your libprotobuf-c headers. Please regenerate this file with a newer version of protoc-c.
#endif

#include "opts.pb-c.h"
#include "fown.pb-c.h"

typedef struct _BpfmapFileEntry BpfmapFileEntry;


/* --- enums --- */


/* --- messages --- */

struct  _BpfmapFileEntry
{
  ProtobufCMessage base;
  uint32_t id;
  uint32_t flags;
  uint64_t pos;
  FownEntry *fown;
  uint32_t map_type;
  uint32_t key_size;
  uint32_t value_size;
  uint32_t map_id;
  uint32_t max_entries;
  uint32_t map_flags;
  uint64_t memlock;
  protobuf_c_boolean frozen;
  char *map_name;
  uint32_t ifindex;
  protobuf_c_boolean has_mnt_id;
  int32_t mnt_id;
};
#define BPFMAP_FILE_ENTRY__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&bpfmap_file_entry__descriptor) \
    , 0, 0, 0, NULL, 0, 0, 0, 0, 0, 0, 0, 0, NULL, 0u, 0,-1 }


/* BpfmapFileEntry methods */
void   bpfmap_file_entry__init
                     (BpfmapFileEntry         *message);
size_t bpfmap_file_entry__get_packed_size
                     (const BpfmapFileEntry   *message);
size_t bpfmap_file_entry__pack
                     (const BpfmapFileEntry   *message,
                      uint8_t             *out);
size_t bpfmap_file_entry__pack_to_buffer
                     (const BpfmapFileEntry   *message,
                      ProtobufCBuffer     *buffer);
BpfmapFileEntry *
       bpfmap_file_entry__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   bpfmap_file_entry__free_unpacked
                     (BpfmapFileEntry *message,
                      ProtobufCAllocator *allocator);
/* --- per-message closures --- */

typedef void (*BpfmapFileEntry_Closure)
                 (const BpfmapFileEntry *message,
                  void *closure_data);

/* --- services --- */


/* --- descriptors --- */

extern const ProtobufCMessageDescriptor bpfmap_file_entry__descriptor;

PROTOBUF_C__END_DECLS


#endif  /* PROTOBUF_C_bpfmap_2dfile_2eproto__INCLUDED */
