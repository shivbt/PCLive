/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: fs.proto */

/* Do not generate deprecated warnings for self */
#ifndef PROTOBUF_C__NO_DEPRECATED
#define PROTOBUF_C__NO_DEPRECATED
#endif

#include "fs.pb-c.h"
void   fs_entry__init
                     (FsEntry         *message)
{
  static FsEntry init_value = FS_ENTRY__INIT;
  *message = init_value;
}
size_t fs_entry__get_packed_size
                     (const FsEntry *message)
{
  assert(message->base.descriptor == &fs_entry__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t fs_entry__pack
                     (const FsEntry *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &fs_entry__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t fs_entry__pack_to_buffer
                     (const FsEntry *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &fs_entry__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
FsEntry *
       fs_entry__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (FsEntry *)
     protobuf_c_message_unpack (&fs_entry__descriptor,
                                allocator, len, data);
}
void   fs_entry__free_unpacked
                     (FsEntry *message,
                      ProtobufCAllocator *allocator)
{
  assert(message->base.descriptor == &fs_entry__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
static const ProtobufCFieldDescriptor fs_entry__field_descriptors[3] =
{
  {
    "cwd_id",
    1,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(FsEntry, cwd_id),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "root_id",
    2,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(FsEntry, root_id),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "umask",
    3,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_UINT32,
    offsetof(FsEntry, has_umask),
    offsetof(FsEntry, umask),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned fs_entry__field_indices_by_name[] = {
  0,   /* field[0] = cwd_id */
  1,   /* field[1] = root_id */
  2,   /* field[2] = umask */
};
static const ProtobufCIntRange fs_entry__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 3 }
};
const ProtobufCMessageDescriptor fs_entry__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "fs_entry",
  "FsEntry",
  "FsEntry",
  "",
  sizeof(FsEntry),
  3,
  fs_entry__field_descriptors,
  fs_entry__field_indices_by_name,
  1,  fs_entry__number_ranges,
  (ProtobufCMessageInit) fs_entry__init,
  NULL,NULL,NULL    /* reserved[123] */
};