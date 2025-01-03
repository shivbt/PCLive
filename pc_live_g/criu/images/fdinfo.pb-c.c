/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: fdinfo.proto */

/* Do not generate deprecated warnings for self */
#ifndef PROTOBUF_C__NO_DEPRECATED
#define PROTOBUF_C__NO_DEPRECATED
#endif

#include "fdinfo.pb-c.h"
void   fdinfo_entry__init
                     (FdinfoEntry         *message)
{
  static FdinfoEntry init_value = FDINFO_ENTRY__INIT;
  *message = init_value;
}
size_t fdinfo_entry__get_packed_size
                     (const FdinfoEntry *message)
{
  assert(message->base.descriptor == &fdinfo_entry__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t fdinfo_entry__pack
                     (const FdinfoEntry *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &fdinfo_entry__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t fdinfo_entry__pack_to_buffer
                     (const FdinfoEntry *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &fdinfo_entry__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
FdinfoEntry *
       fdinfo_entry__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (FdinfoEntry *)
     protobuf_c_message_unpack (&fdinfo_entry__descriptor,
                                allocator, len, data);
}
void   fdinfo_entry__free_unpacked
                     (FdinfoEntry *message,
                      ProtobufCAllocator *allocator)
{
  assert(message->base.descriptor == &fdinfo_entry__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   file_entry__init
                     (FileEntry         *message)
{
  static FileEntry init_value = FILE_ENTRY__INIT;
  *message = init_value;
}
size_t file_entry__get_packed_size
                     (const FileEntry *message)
{
  assert(message->base.descriptor == &file_entry__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t file_entry__pack
                     (const FileEntry *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &file_entry__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t file_entry__pack_to_buffer
                     (const FileEntry *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &file_entry__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
FileEntry *
       file_entry__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (FileEntry *)
     protobuf_c_message_unpack (&file_entry__descriptor,
                                allocator, len, data);
}
void   file_entry__free_unpacked
                     (FileEntry *message,
                      ProtobufCAllocator *allocator)
{
  assert(message->base.descriptor == &file_entry__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
static const ProtobufCFieldDescriptor fdinfo_entry__field_descriptors[5] =
{
  {
    "id",
    1,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(FdinfoEntry, id),
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
    offsetof(FdinfoEntry, flags),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "type",
    3,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_ENUM,
    0,   /* quantifier_offset */
    offsetof(FdinfoEntry, type),
    &fd_types__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "fd",
    4,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(FdinfoEntry, fd),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "xattr_security_selinux",
    5,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(FdinfoEntry, xattr_security_selinux),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned fdinfo_entry__field_indices_by_name[] = {
  3,   /* field[3] = fd */
  1,   /* field[1] = flags */
  0,   /* field[0] = id */
  2,   /* field[2] = type */
  4,   /* field[4] = xattr_security_selinux */
};
static const ProtobufCIntRange fdinfo_entry__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 5 }
};
const ProtobufCMessageDescriptor fdinfo_entry__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "fdinfo_entry",
  "FdinfoEntry",
  "FdinfoEntry",
  "",
  sizeof(FdinfoEntry),
  5,
  fdinfo_entry__field_descriptors,
  fdinfo_entry__field_indices_by_name,
  1,  fdinfo_entry__number_ranges,
  (ProtobufCMessageInit) fdinfo_entry__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor file_entry__field_descriptors[21] =
{
  {
    "type",
    1,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_ENUM,
    0,   /* quantifier_offset */
    offsetof(FileEntry, type),
    &fd_types__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "id",
    2,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_UINT32,
    0,   /* quantifier_offset */
    offsetof(FileEntry, id),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "reg",
    3,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_MESSAGE,
    0,   /* quantifier_offset */
    offsetof(FileEntry, reg),
    &reg_file_entry__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "isk",
    4,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_MESSAGE,
    0,   /* quantifier_offset */
    offsetof(FileEntry, isk),
    &inet_sk_entry__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "nsf",
    5,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_MESSAGE,
    0,   /* quantifier_offset */
    offsetof(FileEntry, nsf),
    &ns_file_entry__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "psk",
    6,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_MESSAGE,
    0,   /* quantifier_offset */
    offsetof(FileEntry, psk),
    &packet_sock_entry__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "nlsk",
    7,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_MESSAGE,
    0,   /* quantifier_offset */
    offsetof(FileEntry, nlsk),
    &netlink_sk_entry__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "efd",
    8,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_MESSAGE,
    0,   /* quantifier_offset */
    offsetof(FileEntry, efd),
    &eventfd_file_entry__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "epfd",
    9,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_MESSAGE,
    0,   /* quantifier_offset */
    offsetof(FileEntry, epfd),
    &eventpoll_file_entry__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "sgfd",
    10,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_MESSAGE,
    0,   /* quantifier_offset */
    offsetof(FileEntry, sgfd),
    &signalfd_entry__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "tunf",
    11,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_MESSAGE,
    0,   /* quantifier_offset */
    offsetof(FileEntry, tunf),
    &tunfile_entry__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "tfd",
    12,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_MESSAGE,
    0,   /* quantifier_offset */
    offsetof(FileEntry, tfd),
    &timerfd_entry__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "ify",
    13,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_MESSAGE,
    0,   /* quantifier_offset */
    offsetof(FileEntry, ify),
    &inotify_file_entry__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "ffy",
    14,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_MESSAGE,
    0,   /* quantifier_offset */
    offsetof(FileEntry, ffy),
    &fanotify_file_entry__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "ext",
    15,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_MESSAGE,
    0,   /* quantifier_offset */
    offsetof(FileEntry, ext),
    &ext_file_entry__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "usk",
    16,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_MESSAGE,
    0,   /* quantifier_offset */
    offsetof(FileEntry, usk),
    &unix_sk_entry__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "fifo",
    17,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_MESSAGE,
    0,   /* quantifier_offset */
    offsetof(FileEntry, fifo),
    &fifo_entry__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "pipe",
    18,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_MESSAGE,
    0,   /* quantifier_offset */
    offsetof(FileEntry, pipe),
    &pipe_entry__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "tty",
    19,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_MESSAGE,
    0,   /* quantifier_offset */
    offsetof(FileEntry, tty),
    &tty_file_entry__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "memfd",
    20,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_MESSAGE,
    0,   /* quantifier_offset */
    offsetof(FileEntry, memfd),
    &memfd_file_entry__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "bpf",
    21,
    PROTOBUF_C_LABEL_OPTIONAL,
    PROTOBUF_C_TYPE_MESSAGE,
    0,   /* quantifier_offset */
    offsetof(FileEntry, bpf),
    &bpfmap_file_entry__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned file_entry__field_indices_by_name[] = {
  20,   /* field[20] = bpf */
  7,   /* field[7] = efd */
  8,   /* field[8] = epfd */
  14,   /* field[14] = ext */
  13,   /* field[13] = ffy */
  16,   /* field[16] = fifo */
  1,   /* field[1] = id */
  12,   /* field[12] = ify */
  3,   /* field[3] = isk */
  19,   /* field[19] = memfd */
  6,   /* field[6] = nlsk */
  4,   /* field[4] = nsf */
  17,   /* field[17] = pipe */
  5,   /* field[5] = psk */
  2,   /* field[2] = reg */
  9,   /* field[9] = sgfd */
  11,   /* field[11] = tfd */
  18,   /* field[18] = tty */
  10,   /* field[10] = tunf */
  0,   /* field[0] = type */
  15,   /* field[15] = usk */
};
static const ProtobufCIntRange file_entry__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 21 }
};
const ProtobufCMessageDescriptor file_entry__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "file_entry",
  "FileEntry",
  "FileEntry",
  "",
  sizeof(FileEntry),
  21,
  file_entry__field_descriptors,
  file_entry__field_indices_by_name,
  1,  file_entry__number_ranges,
  (ProtobufCMessageInit) file_entry__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCEnumValue fd_types__enum_values_by_number[22] =
{
  { "UND", "FD_TYPES__UND", 0 },
  { "REG", "FD_TYPES__REG", 1 },
  { "PIPE", "FD_TYPES__PIPE", 2 },
  { "FIFO", "FD_TYPES__FIFO", 3 },
  { "INETSK", "FD_TYPES__INETSK", 4 },
  { "UNIXSK", "FD_TYPES__UNIXSK", 5 },
  { "EVENTFD", "FD_TYPES__EVENTFD", 6 },
  { "EVENTPOLL", "FD_TYPES__EVENTPOLL", 7 },
  { "INOTIFY", "FD_TYPES__INOTIFY", 8 },
  { "SIGNALFD", "FD_TYPES__SIGNALFD", 9 },
  { "PACKETSK", "FD_TYPES__PACKETSK", 10 },
  { "TTY", "FD_TYPES__TTY", 11 },
  { "FANOTIFY", "FD_TYPES__FANOTIFY", 12 },
  { "NETLINKSK", "FD_TYPES__NETLINKSK", 13 },
  { "NS", "FD_TYPES__NS", 14 },
  { "TUNF", "FD_TYPES__TUNF", 15 },
  { "EXT", "FD_TYPES__EXT", 16 },
  { "TIMERFD", "FD_TYPES__TIMERFD", 17 },
  { "MEMFD", "FD_TYPES__MEMFD", 18 },
  { "BPFMAP", "FD_TYPES__BPFMAP", 19 },
  { "CTL_TTY", "FD_TYPES__CTL_TTY", 65534 },
  { "AUTOFS_PIPE", "FD_TYPES__AUTOFS_PIPE", 65535 },
};
static const ProtobufCIntRange fd_types__value_ranges[] = {
{0, 0},{65534, 20},{0, 22}
};
static const ProtobufCEnumValueIndex fd_types__enum_values_by_name[22] =
{
  { "AUTOFS_PIPE", 21 },
  { "BPFMAP", 19 },
  { "CTL_TTY", 20 },
  { "EVENTFD", 6 },
  { "EVENTPOLL", 7 },
  { "EXT", 16 },
  { "FANOTIFY", 12 },
  { "FIFO", 3 },
  { "INETSK", 4 },
  { "INOTIFY", 8 },
  { "MEMFD", 18 },
  { "NETLINKSK", 13 },
  { "NS", 14 },
  { "PACKETSK", 10 },
  { "PIPE", 2 },
  { "REG", 1 },
  { "SIGNALFD", 9 },
  { "TIMERFD", 17 },
  { "TTY", 11 },
  { "TUNF", 15 },
  { "UND", 0 },
  { "UNIXSK", 5 },
};
const ProtobufCEnumDescriptor fd_types__descriptor =
{
  PROTOBUF_C__ENUM_DESCRIPTOR_MAGIC,
  "fd_types",
  "fd_types",
  "FdTypes",
  "",
  22,
  fd_types__enum_values_by_number,
  22,
  fd_types__enum_values_by_name,
  2,
  fd_types__value_ranges,
  NULL,NULL,NULL,NULL   /* reserved[1234] */
};
