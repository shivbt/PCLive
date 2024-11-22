/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: mnt.proto */

/* Do not generate deprecated warnings for self */
#ifndef PROTOBUF_C__NO_DEPRECATED
#define PROTOBUF_C__NO_DEPRECATED
#endif

#include "mnt.pb-c.h"
void   mnt_entry__init
                     (MntEntry         *message)
{
  static MntEntry init_value = MNT_ENTRY__INIT;
  *message = init_value;
}
size_t mnt_entry__get_packed_size
                     (const MntEntry *message)
{
  assert(message->base.descriptor == &mnt_entry__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t mnt_entry__pack
                     (const MntEntry *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &mnt_entry__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t mnt_entry__pack_to_buffer
                     (const MntEntry *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &mnt_entry__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
MntEntry *
       mnt_entry__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (MntEntry *)
     protobuf_c_message_unpack (&mnt_entry__descriptor,
                                allocator, len, data);
}
void   mnt_entry__free_unpacked
                     (MntEntry *message,
                      ProtobufCAllocator *allocator)
{
  assert(message->base.descriptor == &mnt_entry__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
static const ProtobufCFieldDescriptor mnt_entry__field_descriptors[18] =
{
  {
    "fstype",
    1,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(MntEntry, fstype),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "mnt_id",
    2,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(MntEntry, mnt_id),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "root_dev",
    3,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(MntEntry, root_dev),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "parent_mnt_id",
    4,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(MntEntry, parent_mnt_id),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "flags",
    5,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(MntEntry, flags),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "root",
    6,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(MntEntry, root),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "mountpoint",
    7,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(MntEntry, mountpoint),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "source",
    8,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(MntEntry, source),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "options",
    9,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(MntEntry, options),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "shared_id",
    10,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_UINT32,
    offsetof(MntEntry, has_shared_id),
    offsetof(MntEntry, shared_id),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "master_id",
    11,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_UINT32,
    offsetof(MntEntry, has_master_id),
    offsetof(MntEntry, master_id),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "with_plugin",
    12,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_BOOL,
    offsetof(MntEntry, has_with_plugin),
    offsetof(MntEntry, with_plugin),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "ext_mount",
    13,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_BOOL,
    offsetof(MntEntry, has_ext_mount),
    offsetof(MntEntry, ext_mount),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "fsname",
    14,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(MntEntry, fsname),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "internal_sharing",
    15,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_BOOL,
    offsetof(MntEntry, has_internal_sharing),
    offsetof(MntEntry, internal_sharing),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "deleted",
    16,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_BOOL,
    offsetof(MntEntry, has_deleted),
    offsetof(MntEntry, deleted),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "sb_flags",
    17,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_UINT32,
    offsetof(MntEntry, has_sb_flags),
    offsetof(MntEntry, sb_flags),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "ext_key",
    18,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(MntEntry, ext_key),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned mnt_entry__field_indices_by_name[] = {
  15,   /* field[15] = deleted */
  17,   /* field[17] = ext_key */
  12,   /* field[12] = ext_mount */
  4,   /* field[4] = flags */
  13,   /* field[13] = fsname */
  0,   /* field[0] = fstype */
  14,   /* field[14] = internal_sharing */
  10,   /* field[10] = master_id */
  1,   /* field[1] = mnt_id */
  6,   /* field[6] = mountpoint */
  8,   /* field[8] = options */
  3,   /* field[3] = parent_mnt_id */
  5,   /* field[5] = root */
  2,   /* field[2] = root_dev */
  16,   /* field[16] = sb_flags */
  9,   /* field[9] = shared_id */
  7,   /* field[7] = source */
  11,   /* field[11] = with_plugin */
};
static const ProtobufCIntRange mnt_entry__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 18 }
};
const ProtobufCMessageDescriptor mnt_entry__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "mnt_entry",
  "MntEntry",
  "MntEntry",
  "",
  sizeof(MntEntry),
  18,
  mnt_entry__field_descriptors,
  mnt_entry__field_indices_by_name,
  1,  mnt_entry__number_ranges,
  (ProtobufCMessageInit) mnt_entry__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCEnumValue fstype__enum_values_by_number[21] =
{
  { "UNSUPPORTED", "FSTYPE__UNSUPPORTED", 0 },
  { "PROC", "FSTYPE__PROC", 1 },
  { "SYSFS", "FSTYPE__SYSFS", 2 },
  { "DEVTMPFS", "FSTYPE__DEVTMPFS", 3 },
  { "BINFMT_MISC", "FSTYPE__BINFMT_MISC", 4 },
  { "TMPFS", "FSTYPE__TMPFS", 5 },
  { "DEVPTS", "FSTYPE__DEVPTS", 6 },
  { "SIMFS", "FSTYPE__SIMFS", 7 },
  { "PSTORE", "FSTYPE__PSTORE", 8 },
  { "SECURITYFS", "FSTYPE__SECURITYFS", 9 },
  { "FUSECTL", "FSTYPE__FUSECTL", 10 },
  { "DEBUGFS", "FSTYPE__DEBUGFS", 11 },
  { "CGROUP", "FSTYPE__CGROUP", 12 },
  { "AUFS", "FSTYPE__AUFS", 13 },
  { "MQUEUE", "FSTYPE__MQUEUE", 14 },
  { "FUSE", "FSTYPE__FUSE", 15 },
  { "AUTO", "FSTYPE__AUTO", 16 },
  { "OVERLAYFS", "FSTYPE__OVERLAYFS", 17 },
  { "AUTOFS", "FSTYPE__AUTOFS", 18 },
  { "TRACEFS", "FSTYPE__TRACEFS", 19 },
  { "CGROUP2", "FSTYPE__CGROUP2", 23 },
};
static const ProtobufCIntRange fstype__value_ranges[] = {
{0, 0},{23, 20},{0, 21}
};
static const ProtobufCEnumValueIndex fstype__enum_values_by_name[21] =
{
  { "AUFS", 13 },
  { "AUTO", 16 },
  { "AUTOFS", 18 },
  { "BINFMT_MISC", 4 },
  { "CGROUP", 12 },
  { "CGROUP2", 20 },
  { "DEBUGFS", 11 },
  { "DEVPTS", 6 },
  { "DEVTMPFS", 3 },
  { "FUSE", 15 },
  { "FUSECTL", 10 },
  { "MQUEUE", 14 },
  { "OVERLAYFS", 17 },
  { "PROC", 1 },
  { "PSTORE", 8 },
  { "SECURITYFS", 9 },
  { "SIMFS", 7 },
  { "SYSFS", 2 },
  { "TMPFS", 5 },
  { "TRACEFS", 19 },
  { "UNSUPPORTED", 0 },
};
const ProtobufCEnumDescriptor fstype__descriptor =
{
  PROTOBUF_C__ENUM_DESCRIPTOR_MAGIC,
  "fstype",
  "fstype",
  "Fstype",
  "",
  21,
  fstype__enum_values_by_number,
  21,
  fstype__enum_values_by_name,
  2,
  fstype__value_ranges,
  NULL,NULL,NULL,NULL   /* reserved[1234] */
};