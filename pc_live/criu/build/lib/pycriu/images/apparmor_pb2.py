# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: apparmor.proto
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x0e\x61pparmor.proto\"\'\n\taa_policy\x12\x0c\n\x04name\x18\x01 \x02(\t\x12\x0c\n\x04\x62lob\x18\x02 \x02(\x0c\"]\n\x0c\x61\x61_namespace\x12\x0c\n\x04name\x18\x01 \x02(\t\x12\x1c\n\x08policies\x18\x02 \x03(\x0b\x32\n.aa_policy\x12!\n\nnamespaces\x18\x03 \x03(\x0b\x32\r.aa_namespace\"3\n\x0e\x61pparmor_entry\x12!\n\nnamespaces\x18\x01 \x03(\x0b\x32\r.aa_namespace')



_AA_POLICY = DESCRIPTOR.message_types_by_name['aa_policy']
_AA_NAMESPACE = DESCRIPTOR.message_types_by_name['aa_namespace']
_APPARMOR_ENTRY = DESCRIPTOR.message_types_by_name['apparmor_entry']
aa_policy = _reflection.GeneratedProtocolMessageType('aa_policy', (_message.Message,), {
  'DESCRIPTOR' : _AA_POLICY,
  '__module__' : 'apparmor_pb2'
  # @@protoc_insertion_point(class_scope:aa_policy)
  })
_sym_db.RegisterMessage(aa_policy)

aa_namespace = _reflection.GeneratedProtocolMessageType('aa_namespace', (_message.Message,), {
  'DESCRIPTOR' : _AA_NAMESPACE,
  '__module__' : 'apparmor_pb2'
  # @@protoc_insertion_point(class_scope:aa_namespace)
  })
_sym_db.RegisterMessage(aa_namespace)

apparmor_entry = _reflection.GeneratedProtocolMessageType('apparmor_entry', (_message.Message,), {
  'DESCRIPTOR' : _APPARMOR_ENTRY,
  '__module__' : 'apparmor_pb2'
  # @@protoc_insertion_point(class_scope:apparmor_entry)
  })
_sym_db.RegisterMessage(apparmor_entry)

if _descriptor._USE_C_DESCRIPTORS == False:

  DESCRIPTOR._options = None
  _AA_POLICY._serialized_start=18
  _AA_POLICY._serialized_end=57
  _AA_NAMESPACE._serialized_start=59
  _AA_NAMESPACE._serialized_end=152
  _APPARMOR_ENTRY._serialized_start=154
  _APPARMOR_ENTRY._serialized_end=205
# @@protoc_insertion_point(module_scope)
