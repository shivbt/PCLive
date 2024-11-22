/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: fs.proto */

#ifndef PROTOBUF_C_fs_2eproto__INCLUDED
#define PROTOBUF_C_fs_2eproto__INCLUDED

#include <protobuf-c/protobuf-c.h>

PROTOBUF_C__BEGIN_DECLS

#if PROTOBUF_C_VERSION_NUMBER < 1000000
# error This file was generated by a newer version of protoc-c which is incompatible with your libprotobuf-c headers. Please update your headers.
#elif 1002001 < PROTOBUF_C_MIN_COMPILER_VERSION
# error This file was generated by an older version of protoc-c which is incompatible with your libprotobuf-c headers. Please regenerate this file with a newer version of protoc-c.
#endif


typedef struct _FsEntry FsEntry;


/* --- enums --- */


/* --- messages --- */

struct  _FsEntry
{
  ProtobufCMessage base;
  uint32_t cwd_id;
  uint32_t root_id;
  protobuf_c_boolean has_umask;
  uint32_t umask;
};
#define FS_ENTRY__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&fs_entry__descriptor) \
    , 0, 0, 0,0 }


/* FsEntry methods */
void   fs_entry__init
                     (FsEntry         *message);
size_t fs_entry__get_packed_size
                     (const FsEntry   *message);
size_t fs_entry__pack
                     (const FsEntry   *message,
                      uint8_t             *out);
size_t fs_entry__pack_to_buffer
                     (const FsEntry   *message,
                      ProtobufCBuffer     *buffer);
FsEntry *
       fs_entry__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   fs_entry__free_unpacked
                     (FsEntry *message,
                      ProtobufCAllocator *allocator);
/* --- per-message closures --- */

typedef void (*FsEntry_Closure)
                 (const FsEntry *message,
                  void *closure_data);

/* --- services --- */


/* --- descriptors --- */

extern const ProtobufCMessageDescriptor fs_entry__descriptor;

PROTOBUF_C__END_DECLS


#endif  /* PROTOBUF_C_fs_2eproto__INCLUDED */
