# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: memfd.proto
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


import opts_pb2 as opts__pb2
import fown_pb2 as fown__pb2


DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x0bmemfd.proto\x1a\nopts.proto\x1a\nfown.proto\"y\n\x10memfd_file_entry\x12\n\n\x02id\x18\x01 \x02(\r\x12\x1f\n\x05\x66lags\x18\x02 \x02(\rB\x10\xd2?\r\x1a\x0brfile.flags\x12\x0b\n\x03pos\x18\x03 \x02(\x04\x12\x19\n\x04\x66own\x18\x04 \x02(\x0b\x32\x0b.fown_entry\x12\x10\n\x08inode_id\x18\x05 \x02(\r\"\x8b\x01\n\x11memfd_inode_entry\x12\x0c\n\x04name\x18\x01 \x02(\t\x12\x0b\n\x03uid\x18\x02 \x02(\r\x12\x0b\n\x03gid\x18\x03 \x02(\r\x12\x0c\n\x04size\x18\x04 \x02(\x04\x12\r\n\x05shmid\x18\x05 \x02(\r\x12\x1f\n\x05seals\x18\x06 \x02(\rB\x10\xd2?\r\x1a\x0bseals.flags\x12\x10\n\x08inode_id\x18\x07 \x02(\x04')



_MEMFD_FILE_ENTRY = DESCRIPTOR.message_types_by_name['memfd_file_entry']
_MEMFD_INODE_ENTRY = DESCRIPTOR.message_types_by_name['memfd_inode_entry']
memfd_file_entry = _reflection.GeneratedProtocolMessageType('memfd_file_entry', (_message.Message,), {
  'DESCRIPTOR' : _MEMFD_FILE_ENTRY,
  '__module__' : 'memfd_pb2'
  # @@protoc_insertion_point(class_scope:memfd_file_entry)
  })
_sym_db.RegisterMessage(memfd_file_entry)

memfd_inode_entry = _reflection.GeneratedProtocolMessageType('memfd_inode_entry', (_message.Message,), {
  'DESCRIPTOR' : _MEMFD_INODE_ENTRY,
  '__module__' : 'memfd_pb2'
  # @@protoc_insertion_point(class_scope:memfd_inode_entry)
  })
_sym_db.RegisterMessage(memfd_inode_entry)

if _descriptor._USE_C_DESCRIPTORS == False:

  DESCRIPTOR._options = None
  _MEMFD_FILE_ENTRY.fields_by_name['flags']._options = None
  _MEMFD_FILE_ENTRY.fields_by_name['flags']._serialized_options = b'\322?\r\032\013rfile.flags'
  _MEMFD_INODE_ENTRY.fields_by_name['seals']._options = None
  _MEMFD_INODE_ENTRY.fields_by_name['seals']._serialized_options = b'\322?\r\032\013seals.flags'
  _MEMFD_FILE_ENTRY._serialized_start=39
  _MEMFD_FILE_ENTRY._serialized_end=160
  _MEMFD_INODE_ENTRY._serialized_start=163
  _MEMFD_INODE_ENTRY._serialized_end=302
# @@protoc_insertion_point(module_scope)