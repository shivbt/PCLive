/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: sysctl.proto */

/* Do not generate deprecated warnings for self */
#ifndef PROTOBUF_C__NO_DEPRECATED
#define PROTOBUF_C__NO_DEPRECATED
#endif

#include "sysctl.pb-c.h"
void   sysctl_entry__init
                     (SysctlEntry         *message)
{
  static SysctlEntry init_value = SYSCTL_ENTRY__INIT;
  *message = init_value;
}
size_t sysctl_entry__get_packed_size
                     (const SysctlEntry *message)
{
  assert(message->base.descriptor == &sysctl_entry__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t sysctl_entry__pack
                     (const SysctlEntry *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &sysctl_entry__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t sysctl_entry__pack_to_buffer
                     (const SysctlEntry *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &sysctl_entry__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
SysctlEntry *
       sysctl_entry__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (SysctlEntry *)
     protobuf_c_message_unpack (&sysctl_entry__descriptor,
                                allocator, len, data);
}
void   sysctl_entry__free_unpacked
                     (SysctlEntry *message,
                      ProtobufCAllocator *allocator)
{
  assert(message->base.descriptor == &sysctl_entry__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
static const ProtobufCFieldDescriptor sysctl_entry__field_descriptors[3] =
{
  {
    "type",
    1,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_ENUM,
    0,   /* quantifier_offset */
    offsetof(SysctlEntry, type),
    &sysctl_type__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "iarg",
    2,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_INT32,
    offsetof(SysctlEntry, has_iarg),
    offsetof(SysctlEntry, iarg),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "sarg",
    3,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(SysctlEntry, sarg),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned sysctl_entry__field_indices_by_name[] = {
  1,   /* field[1] = iarg */
  2,   /* field[2] = sarg */
  0,   /* field[0] = type */
};
static const ProtobufCIntRange sysctl_entry__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 3 }
};
const ProtobufCMessageDescriptor sysctl_entry__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "sysctl_entry",
  "SysctlEntry",
  "SysctlEntry",
  "",
  sizeof(SysctlEntry),
  3,
  sysctl_entry__field_descriptors,
  sysctl_entry__field_indices_by_name,
  1,  sysctl_entry__number_ranges,
  (ProtobufCMessageInit) sysctl_entry__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCEnumValue sysctl_type__enum_values_by_number[2] =
{
  { "CTL_STR", "SYSCTL_TYPE__CTL_STR", 5 },
  { "CTL_32", "SYSCTL_TYPE__CTL_32", 6 },
};
static const ProtobufCIntRange sysctl_type__value_ranges[] = {
{5, 0},{0, 2}
};
static const ProtobufCEnumValueIndex sysctl_type__enum_values_by_name[2] =
{
  { "CTL_32", 1 },
  { "CTL_STR", 0 },
};
const ProtobufCEnumDescriptor sysctl_type__descriptor =
{
  PROTOBUF_C__ENUM_DESCRIPTOR_MAGIC,
  "SysctlType",
  "SysctlType",
  "SysctlType",
  "",
  2,
  sysctl_type__enum_values_by_number,
  2,
  sysctl_type__enum_values_by_name,
  1,
  sysctl_type__value_ranges,
  NULL,NULL,NULL,NULL   /* reserved[1234] */
};
