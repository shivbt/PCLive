# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: autofs.proto
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x0c\x61utofs.proto\"\x96\x01\n\x0c\x61utofs_entry\x12\n\n\x02\x66\x64\x18\x01 \x02(\x05\x12\x0c\n\x04pgrp\x18\x02 \x02(\x05\x12\x0f\n\x07timeout\x18\x03 \x02(\x05\x12\x10\n\x08minproto\x18\x04 \x02(\x05\x12\x10\n\x08maxproto\x18\x05 \x02(\x05\x12\x0c\n\x04mode\x18\x06 \x02(\x05\x12\x0b\n\x03uid\x18\x07 \x01(\x05\x12\x0b\n\x03gid\x18\x08 \x01(\x05\x12\x0f\n\x07read_fd\x18\t \x01(\x05')



_AUTOFS_ENTRY = DESCRIPTOR.message_types_by_name['autofs_entry']
autofs_entry = _reflection.GeneratedProtocolMessageType('autofs_entry', (_message.Message,), {
  'DESCRIPTOR' : _AUTOFS_ENTRY,
  '__module__' : 'autofs_pb2'
  # @@protoc_insertion_point(class_scope:autofs_entry)
  })
_sym_db.RegisterMessage(autofs_entry)

if _descriptor._USE_C_DESCRIPTORS == False:

  DESCRIPTOR._options = None
  _AUTOFS_ENTRY._serialized_start=17
  _AUTOFS_ENTRY._serialized_end=167
# @@protoc_insertion_point(module_scope)
