/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: cgroup.proto */

/* Do not generate deprecated warnings for self */
#ifndef PROTOBUF_C__NO_DEPRECATED
#define PROTOBUF_C__NO_DEPRECATED
#endif

#include "cgroup.pb-c.h"
void   cgroup_perms__init
                     (CgroupPerms         *message)
{
  static CgroupPerms init_value = CGROUP_PERMS__INIT;
  *message = init_value;
}
size_t cgroup_perms__get_packed_size
                     (const CgroupPerms *message)
{
  assert(message->base.descriptor == &cgroup_perms__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t cgroup_perms__pack
                     (const CgroupPerms *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &cgroup_perms__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t cgroup_perms__pack_to_buffer
                     (const CgroupPerms *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &cgroup_perms__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
CgroupPerms *
       cgroup_perms__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (CgroupPerms *)
     protobuf_c_message_unpack (&cgroup_perms__descriptor,
                                allocator, len, data);
}
void   cgroup_perms__free_unpacked
                     (CgroupPerms *message,
                      ProtobufCAllocator *allocator)
{
  assert(message->base.descriptor == &cgroup_perms__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   cgroup_prop_entry__init
                     (CgroupPropEntry         *message)
{
  static CgroupPropEntry init_value = CGROUP_PROP_ENTRY__INIT;
  *message = init_value;
}
size_t cgroup_prop_entry__get_packed_size
                     (const CgroupPropEntry *message)
{
  assert(message->base.descriptor == &cgroup_prop_entry__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t cgroup_prop_entry__pack
                     (const CgroupPropEntry *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &cgroup_prop_entry__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t cgroup_prop_entry__pack_to_buffer
                     (const CgroupPropEntry *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &cgroup_prop_entry__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
CgroupPropEntry *
       cgroup_prop_entry__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (CgroupPropEntry *)
     protobuf_c_message_unpack (&cgroup_prop_entry__descriptor,
                                allocator, len, data);
}
void   cgroup_prop_entry__free_unpacked
                     (CgroupPropEntry *message,
                      ProtobufCAllocator *allocator)
{
  assert(message->base.descriptor == &cgroup_prop_entry__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   cgroup_dir_entry__init
                     (CgroupDirEntry         *message)
{
  static CgroupDirEntry init_value = CGROUP_DIR_ENTRY__INIT;
  *message = init_value;
}
size_t cgroup_dir_entry__get_packed_size
                     (const CgroupDirEntry *message)
{
  assert(message->base.descriptor == &cgroup_dir_entry__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t cgroup_dir_entry__pack
                     (const CgroupDirEntry *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &cgroup_dir_entry__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t cgroup_dir_entry__pack_to_buffer
                     (const CgroupDirEntry *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &cgroup_dir_entry__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
CgroupDirEntry *
       cgroup_dir_entry__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (CgroupDirEntry *)
     protobuf_c_message_unpack (&cgroup_dir_entry__descriptor,
                                allocator, len, data);
}
void   cgroup_dir_entry__free_unpacked
                     (CgroupDirEntry *message,
                      ProtobufCAllocator *allocator)
{
  assert(message->base.descriptor == &cgroup_dir_entry__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   cg_controller_entry__init
                     (CgControllerEntry         *message)
{
  static CgControllerEntry init_value = CG_CONTROLLER_ENTRY__INIT;
  *message = init_value;
}
size_t cg_controller_entry__get_packed_size
                     (const CgControllerEntry *message)
{
  assert(message->base.descriptor == &cg_controller_entry__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t cg_controller_entry__pack
                     (const CgControllerEntry *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &cg_controller_entry__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t cg_controller_entry__pack_to_buffer
                     (const CgControllerEntry *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &cg_controller_entry__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
CgControllerEntry *
       cg_controller_entry__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (CgControllerEntry *)
     protobuf_c_message_unpack (&cg_controller_entry__descriptor,
                                allocator, len, data);
}
void   cg_controller_entry__free_unpacked
                     (CgControllerEntry *message,
                      ProtobufCAllocator *allocator)
{
  assert(message->base.descriptor == &cg_controller_entry__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   cg_member_entry__init
                     (CgMemberEntry         *message)
{
  static CgMemberEntry init_value = CG_MEMBER_ENTRY__INIT;
  *message = init_value;
}
size_t cg_member_entry__get_packed_size
                     (const CgMemberEntry *message)
{
  assert(message->base.descriptor == &cg_member_entry__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t cg_member_entry__pack
                     (const CgMemberEntry *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &cg_member_entry__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t cg_member_entry__pack_to_buffer
                     (const CgMemberEntry *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &cg_member_entry__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
CgMemberEntry *
       cg_member_entry__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (CgMemberEntry *)
     protobuf_c_message_unpack (&cg_member_entry__descriptor,
                                allocator, len, data);
}
void   cg_member_entry__free_unpacked
                     (CgMemberEntry *message,
                      ProtobufCAllocator *allocator)
{
  assert(message->base.descriptor == &cg_member_entry__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   cg_set_entry__init
                     (CgSetEntry         *message)
{
  static CgSetEntry init_value = CG_SET_ENTRY__INIT;
  *message = init_value;
}
size_t cg_set_entry__get_packed_size
                     (const CgSetEntry *message)
{
  assert(message->base.descriptor == &cg_set_entry__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t cg_set_entry__pack
                     (const CgSetEntry *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &cg_set_entry__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t cg_set_entry__pack_to_buffer
                     (const CgSetEntry *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &cg_set_entry__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
CgSetEntry *
       cg_set_entry__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (CgSetEntry *)
     protobuf_c_message_unpack (&cg_set_entry__descriptor,
                                allocator, len, data);
}
void   cg_set_entry__free_unpacked
                     (CgSetEntry *message,
                      ProtobufCAllocator *allocator)
{
  assert(message->base.descriptor == &cg_set_entry__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   cgroup_entry__init
                     (CgroupEntry         *message)
{
  static CgroupEntry init_value = CGROUP_ENTRY__INIT;
  *message = init_value;
}
size_t cgroup_entry__get_packed_size
                     (const CgroupEntry *message)
{
  assert(message->base.descriptor == &cgroup_entry__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t cgroup_entry__pack
                     (const CgroupEntry *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &cgroup_entry__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t cgroup_entry__pack_to_buffer
                     (const CgroupEntry *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &cgroup_entry__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
CgroupEntry *
       cgroup_entry__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (CgroupEntry *)
     protobuf_c_message_unpack (&cgroup_entry__descriptor,
                                allocator, len, data);
}
void   cgroup_entry__free_unpacked
                     (CgroupEntry *message,
                      ProtobufCAllocator *allocator)
{
  assert(message->base.descriptor == &cgroup_entry__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
static const ProtobufCFieldDescriptor cgroup_perms__field_descriptors[3] =
{
  {
    "mode",
    1,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(CgroupPerms, mode),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "uid",
    2,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(CgroupPerms, uid),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "gid",
    3,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(CgroupPerms, gid),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned cgroup_perms__field_indices_by_name[] = {
  2,   /* field[2] = gid */
  0,   /* field[0] = mode */
  1,   /* field[1] = uid */
};
static const ProtobufCIntRange cgroup_perms__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 3 }
};
const ProtobufCMessageDescriptor cgroup_perms__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "cgroup_perms",
  "CgroupPerms",
  "CgroupPerms",
  "",
  sizeof(CgroupPerms),
  3,
  cgroup_perms__field_descriptors,
  cgroup_perms__field_indices_by_name,
  1,  cgroup_perms__number_ranges,
  (ProtobufCMessageInit) cgroup_perms__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor cgroup_prop_entry__field_descriptors[3] =
{
  {
    "name",
    1,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(CgroupPropEntry, name),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "value",
    2,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(CgroupPropEntry, value),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "perms",
    3,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_MESSAGE,
    0,   /* quantifier_offset */
    offsetof(CgroupPropEntry, perms),
    &cgroup_perms__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned cgroup_prop_entry__field_indices_by_name[] = {
  0,   /* field[0] = name */
  2,   /* field[2] = perms */
  1,   /* field[1] = value */
};
static const ProtobufCIntRange cgroup_prop_entry__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 3 }
};
const ProtobufCMessageDescriptor cgroup_prop_entry__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "cgroup_prop_entry",
  "CgroupPropEntry",
  "CgroupPropEntry",
  "",
  sizeof(CgroupPropEntry),
  3,
  cgroup_prop_entry__field_descriptors,
  cgroup_prop_entry__field_indices_by_name,
  1,  cgroup_prop_entry__number_ranges,
  (ProtobufCMessageInit) cgroup_prop_entry__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor cgroup_dir_entry__field_descriptors[4] =
{
  {
    "dir_name",
    1,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(CgroupDirEntry, dir_name),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "children",
    2,
    PROTOBUF_C_LABEL_REPEATED,
    PROTOBUF_C_TYPE_MESSAGE,
    offsetof(CgroupDirEntry, n_children),
    offsetof(CgroupDirEntry, children),
    &cgroup_dir_entry__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "properties",
    3,
    PROTOBUF_C_LABEL_REPEATED,
    PROTOBUF_C_TYPE_MESSAGE,
    offsetof(CgroupDirEntry, n_properties),
    offsetof(CgroupDirEntry, properties),
    &cgroup_prop_entry__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "dir_perms",
    4,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_MESSAGE,
    0,   /* quantifier_offset */
    offsetof(CgroupDirEntry, dir_perms),
    &cgroup_perms__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned cgroup_dir_entry__field_indices_by_name[] = {
  1,   /* field[1] = children */
  0,   /* field[0] = dir_name */
  3,   /* field[3] = dir_perms */
  2,   /* field[2] = properties */
};
static const ProtobufCIntRange cgroup_dir_entry__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 4 }
};
const ProtobufCMessageDescriptor cgroup_dir_entry__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "cgroup_dir_entry",
  "CgroupDirEntry",
  "CgroupDirEntry",
  "",
  sizeof(CgroupDirEntry),
  4,
  cgroup_dir_entry__field_descriptors,
  cgroup_dir_entry__field_indices_by_name,
  1,  cgroup_dir_entry__number_ranges,
  (ProtobufCMessageInit) cgroup_dir_entry__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor cg_controller_entry__field_descriptors[2] =
{
  {
    "cnames",
    1,
    PROTOBUF_C_LABEL_REPEATED,
    PROTOBUF_C_TYPE_STRING,
    offsetof(CgControllerEntry, n_cnames),
    offsetof(CgControllerEntry, cnames),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "dirs",
    2,
    PROTOBUF_C_LABEL_REPEATED,
    PROTOBUF_C_TYPE_MESSAGE,
    offsetof(CgControllerEntry, n_dirs),
    offsetof(CgControllerEntry, dirs),
    &cgroup_dir_entry__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned cg_controller_entry__field_indices_by_name[] = {
  0,   /* field[0] = cnames */
  1,   /* field[1] = dirs */
};
static const ProtobufCIntRange cg_controller_entry__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 2 }
};
const ProtobufCMessageDescriptor cg_controller_entry__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "cg_controller_entry",
  "CgControllerEntry",
  "CgControllerEntry",
  "",
  sizeof(CgControllerEntry),
  2,
  cg_controller_entry__field_descriptors,
  cg_controller_entry__field_indices_by_name,
  1,  cg_controller_entry__number_ranges,
  (ProtobufCMessageInit) cg_controller_entry__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor cg_member_entry__field_descriptors[3] =
{
  {
    "name",
    1,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(CgMemberEntry, name),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "path",
    2,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(CgMemberEntry, path),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "cgns_prefix",
    3,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_UINT32,
    offsetof(CgMemberEntry, has_cgns_prefix),
    offsetof(CgMemberEntry, cgns_prefix),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned cg_member_entry__field_indices_by_name[] = {
  2,   /* field[2] = cgns_prefix */
  0,   /* field[0] = name */
  1,   /* field[1] = path */
};
static const ProtobufCIntRange cg_member_entry__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 3 }
};
const ProtobufCMessageDescriptor cg_member_entry__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "cg_member_entry",
  "CgMemberEntry",
  "CgMemberEntry",
  "",
  sizeof(CgMemberEntry),
  3,
  cg_member_entry__field_descriptors,
  cg_member_entry__field_indices_by_name,
  1,  cg_member_entry__number_ranges,
  (ProtobufCMessageInit) cg_member_entry__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor cg_set_entry__field_descriptors[2] =
{
  {
    "id",
    1,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(CgSetEntry, id),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "ctls",
    2,
    PROTOBUF_C_LABEL_REPEATED,
    PROTOBUF_C_TYPE_MESSAGE,
    offsetof(CgSetEntry, n_ctls),
    offsetof(CgSetEntry, ctls),
    &cg_member_entry__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned cg_set_entry__field_indices_by_name[] = {
  1,   /* field[1] = ctls */
  0,   /* field[0] = id */
};
static const ProtobufCIntRange cg_set_entry__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 2 }
};
const ProtobufCMessageDescriptor cg_set_entry__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "cg_set_entry",
  "CgSetEntry",
  "CgSetEntry",
  "",
  sizeof(CgSetEntry),
  2,
  cg_set_entry__field_descriptors,
  cg_set_entry__field_indices_by_name,
  1,  cg_set_entry__number_ranges,
  (ProtobufCMessageInit) cg_set_entry__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor cgroup_entry__field_descriptors[2] =
{
  {
    "sets",
    1,
    PROTOBUF_C_LABEL_REPEATED,
    PROTOBUF_C_TYPE_MESSAGE,
    offsetof(CgroupEntry, n_sets),
    offsetof(CgroupEntry, sets),
    &cg_set_entry__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "controllers",
    2,
    PROTOBUF_C_LABEL_REPEATED,
    PROTOBUF_C_TYPE_MESSAGE,
    offsetof(CgroupEntry, n_controllers),
    offsetof(CgroupEntry, controllers),
    &cg_controller_entry__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned cgroup_entry__field_indices_by_name[] = {
  1,   /* field[1] = controllers */
  0,   /* field[0] = sets */
};
static const ProtobufCIntRange cgroup_entry__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 2 }
};
const ProtobufCMessageDescriptor cgroup_entry__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "cgroup_entry",
  "CgroupEntry",
  "CgroupEntry",
  "",
  sizeof(CgroupEntry),
  2,
  cgroup_entry__field_descriptors,
  cgroup_entry__field_indices_by_name,
  1,  cgroup_entry__number_ranges,
  (ProtobufCMessageInit) cgroup_entry__init,
  NULL,NULL,NULL    /* reserved[123] */
};