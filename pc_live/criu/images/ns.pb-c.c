/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: ns.proto */

/* Do not generate deprecated warnings for self */
#ifndef PROTOBUF_C__NO_DEPRECATED
#define PROTOBUF_C__NO_DEPRECATED
#endif

#include "ns.pb-c.h"
void   ns_file_entry__init
                     (NsFileEntry         *message)
{
  static NsFileEntry init_value = NS_FILE_ENTRY__INIT;
  *message = init_value;
}
size_t ns_file_entry__get_packed_size
                     (const NsFileEntry *message)
{
  assert(message->base.descriptor == &ns_file_entry__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t ns_file_entry__pack
                     (const NsFileEntry *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &ns_file_entry__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t ns_file_entry__pack_to_buffer
                     (const NsFileEntry *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &ns_file_entry__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
NsFileEntry *
       ns_file_entry__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (NsFileEntry *)
     protobuf_c_message_unpack (&ns_file_entry__descriptor,
                                allocator, len, data);
}
void   ns_file_entry__free_unpacked
                     (NsFileEntry *message,
                      ProtobufCAllocator *allocator)
{
  assert(message->base.descriptor == &ns_file_entry__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
static const ProtobufCFieldDescriptor ns_file_entry__field_descriptors[4] =
{
  {
    "id",
    1,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(NsFileEntry, id),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "ns_id",
    2,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(NsFileEntry, ns_id),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "ns_cflag",
    3,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(NsFileEntry, ns_cflag),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "flags",
    4,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(NsFileEntry, flags),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned ns_file_entry__field_indices_by_name[] = {
  3,   /* field[3] = flags */
  0,   /* field[0] = id */
  2,   /* field[2] = ns_cflag */
  1,   /* field[1] = ns_id */
};
static const ProtobufCIntRange ns_file_entry__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 4 }
};
const ProtobufCMessageDescriptor ns_file_entry__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "ns_file_entry",
  "NsFileEntry",
  "NsFileEntry",
  "",
  sizeof(NsFileEntry),
  4,
  ns_file_entry__field_descriptors,
  ns_file_entry__field_indices_by_name,
  1,  ns_file_entry__number_ranges,
  (ProtobufCMessageInit) ns_file_entry__init,
  NULL,NULL,NULL    /* reserved[123] */
};