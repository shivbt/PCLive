# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: macvlan.proto
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\rmacvlan.proto\"1\n\x12macvlan_link_entry\x12\x0c\n\x04mode\x18\x01 \x02(\r\x12\r\n\x05\x66lags\x18\x02 \x01(\r')



_MACVLAN_LINK_ENTRY = DESCRIPTOR.message_types_by_name['macvlan_link_entry']
macvlan_link_entry = _reflection.GeneratedProtocolMessageType('macvlan_link_entry', (_message.Message,), {
  'DESCRIPTOR' : _MACVLAN_LINK_ENTRY,
  '__module__' : 'macvlan_pb2'
  # @@protoc_insertion_point(class_scope:macvlan_link_entry)
  })
_sym_db.RegisterMessage(macvlan_link_entry)

if _descriptor._USE_C_DESCRIPTORS == False:

  DESCRIPTOR._options = None
  _MACVLAN_LINK_ENTRY._serialized_start=17
  _MACVLAN_LINK_ENTRY._serialized_end=66
# @@protoc_insertion_point(module_scope)