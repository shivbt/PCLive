# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: timerfd.proto
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


DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\rtimerfd.proto\x1a\nopts.proto\x1a\nfown.proto\"\xc4\x01\n\rtimerfd_entry\x12\n\n\x02id\x18\x01 \x02(\r\x12\x14\n\x05\x66lags\x18\x02 \x02(\rB\x05\xd2?\x02\x08\x01\x12\x19\n\x04\x66own\x18\x03 \x02(\x0b\x32\x0b.fown_entry\x12\x0f\n\x07\x63lockid\x18\x04 \x02(\r\x12\r\n\x05ticks\x18\x05 \x02(\x04\x12\x1c\n\rsettime_flags\x18\x06 \x02(\rB\x05\xd2?\x02\x08\x01\x12\x0c\n\x04vsec\x18\x07 \x02(\x04\x12\r\n\x05vnsec\x18\x08 \x02(\x04\x12\x0c\n\x04isec\x18\t \x02(\x04\x12\r\n\x05insec\x18\n \x02(\x04')



_TIMERFD_ENTRY = DESCRIPTOR.message_types_by_name['timerfd_entry']
timerfd_entry = _reflection.GeneratedProtocolMessageType('timerfd_entry', (_message.Message,), {
  'DESCRIPTOR' : _TIMERFD_ENTRY,
  '__module__' : 'timerfd_pb2'
  # @@protoc_insertion_point(class_scope:timerfd_entry)
  })
_sym_db.RegisterMessage(timerfd_entry)

if _descriptor._USE_C_DESCRIPTORS == False:

  DESCRIPTOR._options = None
  _TIMERFD_ENTRY.fields_by_name['flags']._options = None
  _TIMERFD_ENTRY.fields_by_name['flags']._serialized_options = b'\322?\002\010\001'
  _TIMERFD_ENTRY.fields_by_name['settime_flags']._options = None
  _TIMERFD_ENTRY.fields_by_name['settime_flags']._serialized_options = b'\322?\002\010\001'
  _TIMERFD_ENTRY._serialized_start=42
  _TIMERFD_ENTRY._serialized_end=238
# @@protoc_insertion_point(module_scope)