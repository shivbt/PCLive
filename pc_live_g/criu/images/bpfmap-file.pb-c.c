/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: bpfmap-file.proto */

/* Do not generate deprecated warnings for self */
#ifndef PROTOBUF_C__NO_DEPRECATED
#define PROTOBUF_C__NO_DEPRECATED
#endif

#include "bpfmap-file.pb-c.h"
void   bpfmap_file_entry__init
                     (BpfmapFileEntry         *message)
{
  static BpfmapFileEntry init_value = BPFMAP_FILE_ENTRY__INIT;
  *message = init_value;
}
size_t bpfmap_file_entry__get_packed_size
                     (const BpfmapFileEntry *message)
{
  assert(message->base.descriptor == &bpfmap_file_entry__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t bpfmap_file_entry__pack
                     (const BpfmapFileEntry *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &bpfmap_file_entry__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t bpfmap_file_entry__pack_to_buffer
                     (const BpfmapFileEntry *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &bpfmap_file_entry__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
BpfmapFileEntry *
       bpfmap_file_entry__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (BpfmapFileEntry *)
     protobuf_c_message_unpack (&bpfmap_file_entry__descriptor,
                                allocator, len, data);
}
void   bpfmap_file_entry__free_unpacked
                     (BpfmapFileEntry *message,
                      ProtobufCAllocator *allocator)
{
  assert(message->base.descriptor == &bpfmap_file_entry__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
static const protobuf_c_boolean bpfmap_file_entry__frozen__default_value = 0;
static const uint32_t bpfmap_file_entry__ifindex__default_value = 0u;
static const int32_t bpfmap_file_entry__mnt_id__default_value = -1;
static const ProtobufCFieldDescriptor bpfmap_file_entry__field_descriptors[15] =
{
  {
    "id",
    1,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(BpfmapFileEntry, id),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "flags",
    2,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(BpfmapFileEntry, flags),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "pos",
    3,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_UINT64,
    0,   /* quantifier_offset */
    offsetof(BpfmapFileEntry, pos),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "fown",
    4,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_MESSAGE,
    0,   /* quantifier_offset */
    offsetof(BpfmapFileEntry, fown),
    &fown_entry__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "map_type",
    5,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(BpfmapFileEntry, map_type),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "key_size",
    6,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(BpfmapFileEntry, key_size),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "value_size",
    7,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(BpfmapFileEntry, value_size),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "map_id",
    8,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(BpfmapFileEntry, map_id),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "max_entries",
    9,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(BpfmapFileEntry, max_entries),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "map_flags",
    10,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(BpfmapFileEntry, map_flags),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "memlock",
    11,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_UINT64,
    0,   /* quantifier_offset */
    offsetof(BpfmapFileEntry, memlock),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "frozen",
    12,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_BOOL,
    0,   /* quantifier_offset */
    offsetof(BpfmapFileEntry, frozen),
    NULL,
    &bpfmap_file_entry__frozen__default_value,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "map_name",
    13,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(BpfmapFileEntry, map_name),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "ifindex",
    14,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(BpfmapFileEntry, ifindex),
    NULL,
    &bpfmap_file_entry__ifindex__default_value,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "mnt_id",
    15,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_SINT32,
    offsetof(BpfmapFileEntry, has_mnt_id),
    offsetof(BpfmapFileEntry, mnt_id),
    NULL,
    &bpfmap_file_entry__mnt_id__default_value,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned bpfmap_file_entry__field_indices_by_name[] = {
  1,   /* field[1] = flags */
  3,   /* field[3] = fown */
  11,   /* field[11] = frozen */
  0,   /* field[0] = id */
  13,   /* field[13] = ifindex */
  5,   /* field[5] = key_size */
  9,   /* field[9] = map_flags */
  7,   /* field[7] = map_id */
  12,   /* field[12] = map_name */
  4,   /* field[4] = map_type */
  8,   /* field[8] = max_entries */
  10,   /* field[10] = memlock */
  14,   /* field[14] = mnt_id */
  2,   /* field[2] = pos */
  6,   /* field[6] = value_size */
};
static const ProtobufCIntRange bpfmap_file_entry__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 15 }
};
const ProtobufCMessageDescriptor bpfmap_file_entry__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "bpfmap_file_entry",
  "BpfmapFileEntry",
  "BpfmapFileEntry",
  "",
  sizeof(BpfmapFileEntry),
  15,
  bpfmap_file_entry__field_descriptors,
  bpfmap_file_entry__field_indices_by_name,
  1,  bpfmap_file_entry__number_ranges,
  (ProtobufCMessageInit) bpfmap_file_entry__init,
  NULL,NULL,NULL    /* reserved[123] */
};
