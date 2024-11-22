# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: cgroup.proto
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x0c\x63group.proto\"6\n\x0c\x63group_perms\x12\x0c\n\x04mode\x18\x01 \x02(\r\x12\x0b\n\x03uid\x18\x02 \x02(\r\x12\x0b\n\x03gid\x18\x03 \x02(\r\"N\n\x11\x63group_prop_entry\x12\x0c\n\x04name\x18\x01 \x02(\t\x12\r\n\x05value\x18\x02 \x02(\t\x12\x1c\n\x05perms\x18\x03 \x01(\x0b\x32\r.cgroup_perms\"\x93\x01\n\x10\x63group_dir_entry\x12\x10\n\x08\x64ir_name\x18\x01 \x02(\t\x12#\n\x08\x63hildren\x18\x02 \x03(\x0b\x32\x11.cgroup_dir_entry\x12&\n\nproperties\x18\x03 \x03(\x0b\x32\x12.cgroup_prop_entry\x12 \n\tdir_perms\x18\x04 \x01(\x0b\x32\r.cgroup_perms\"F\n\x13\x63g_controller_entry\x12\x0e\n\x06\x63names\x18\x01 \x03(\t\x12\x1f\n\x04\x64irs\x18\x02 \x03(\x0b\x32\x11.cgroup_dir_entry\"B\n\x0f\x63g_member_entry\x12\x0c\n\x04name\x18\x01 \x02(\t\x12\x0c\n\x04path\x18\x02 \x02(\t\x12\x13\n\x0b\x63gns_prefix\x18\x03 \x01(\r\":\n\x0c\x63g_set_entry\x12\n\n\x02id\x18\x01 \x02(\r\x12\x1e\n\x04\x63tls\x18\x02 \x03(\x0b\x32\x10.cg_member_entry\"V\n\x0c\x63group_entry\x12\x1b\n\x04sets\x18\x01 \x03(\x0b\x32\r.cg_set_entry\x12)\n\x0b\x63ontrollers\x18\x02 \x03(\x0b\x32\x14.cg_controller_entry')



_CGROUP_PERMS = DESCRIPTOR.message_types_by_name['cgroup_perms']
_CGROUP_PROP_ENTRY = DESCRIPTOR.message_types_by_name['cgroup_prop_entry']
_CGROUP_DIR_ENTRY = DESCRIPTOR.message_types_by_name['cgroup_dir_entry']
_CG_CONTROLLER_ENTRY = DESCRIPTOR.message_types_by_name['cg_controller_entry']
_CG_MEMBER_ENTRY = DESCRIPTOR.message_types_by_name['cg_member_entry']
_CG_SET_ENTRY = DESCRIPTOR.message_types_by_name['cg_set_entry']
_CGROUP_ENTRY = DESCRIPTOR.message_types_by_name['cgroup_entry']
cgroup_perms = _reflection.GeneratedProtocolMessageType('cgroup_perms', (_message.Message,), {
  'DESCRIPTOR' : _CGROUP_PERMS,
  '__module__' : 'cgroup_pb2'
  # @@protoc_insertion_point(class_scope:cgroup_perms)
  })
_sym_db.RegisterMessage(cgroup_perms)

cgroup_prop_entry = _reflection.GeneratedProtocolMessageType('cgroup_prop_entry', (_message.Message,), {
  'DESCRIPTOR' : _CGROUP_PROP_ENTRY,
  '__module__' : 'cgroup_pb2'
  # @@protoc_insertion_point(class_scope:cgroup_prop_entry)
  })
_sym_db.RegisterMessage(cgroup_prop_entry)

cgroup_dir_entry = _reflection.GeneratedProtocolMessageType('cgroup_dir_entry', (_message.Message,), {
  'DESCRIPTOR' : _CGROUP_DIR_ENTRY,
  '__module__' : 'cgroup_pb2'
  # @@protoc_insertion_point(class_scope:cgroup_dir_entry)
  })
_sym_db.RegisterMessage(cgroup_dir_entry)

cg_controller_entry = _reflection.GeneratedProtocolMessageType('cg_controller_entry', (_message.Message,), {
  'DESCRIPTOR' : _CG_CONTROLLER_ENTRY,
  '__module__' : 'cgroup_pb2'
  # @@protoc_insertion_point(class_scope:cg_controller_entry)
  })
_sym_db.RegisterMessage(cg_controller_entry)

cg_member_entry = _reflection.GeneratedProtocolMessageType('cg_member_entry', (_message.Message,), {
  'DESCRIPTOR' : _CG_MEMBER_ENTRY,
  '__module__' : 'cgroup_pb2'
  # @@protoc_insertion_point(class_scope:cg_member_entry)
  })
_sym_db.RegisterMessage(cg_member_entry)

cg_set_entry = _reflection.GeneratedProtocolMessageType('cg_set_entry', (_message.Message,), {
  'DESCRIPTOR' : _CG_SET_ENTRY,
  '__module__' : 'cgroup_pb2'
  # @@protoc_insertion_point(class_scope:cg_set_entry)
  })
_sym_db.RegisterMessage(cg_set_entry)

cgroup_entry = _reflection.GeneratedProtocolMessageType('cgroup_entry', (_message.Message,), {
  'DESCRIPTOR' : _CGROUP_ENTRY,
  '__module__' : 'cgroup_pb2'
  # @@protoc_insertion_point(class_scope:cgroup_entry)
  })
_sym_db.RegisterMessage(cgroup_entry)

if _descriptor._USE_C_DESCRIPTORS == False:

  DESCRIPTOR._options = None
  _CGROUP_PERMS._serialized_start=16
  _CGROUP_PERMS._serialized_end=70
  _CGROUP_PROP_ENTRY._serialized_start=72
  _CGROUP_PROP_ENTRY._serialized_end=150
  _CGROUP_DIR_ENTRY._serialized_start=153
  _CGROUP_DIR_ENTRY._serialized_end=300
  _CG_CONTROLLER_ENTRY._serialized_start=302
  _CG_CONTROLLER_ENTRY._serialized_end=372
  _CG_MEMBER_ENTRY._serialized_start=374
  _CG_MEMBER_ENTRY._serialized_end=440
  _CG_SET_ENTRY._serialized_start=442
  _CG_SET_ENTRY._serialized_end=500
  _CGROUP_ENTRY._serialized_start=502
  _CGROUP_ENTRY._serialized_end=588
# @@protoc_insertion_point(module_scope)
