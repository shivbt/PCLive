# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: inventory.proto
"""Generated protocol buffer code."""
from google.protobuf.internal import enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


import core_pb2 as core__pb2


DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x0finventory.proto\x1a\ncore.proto\"\x84\x02\n\x0finventory_entry\x12\x13\n\x0bimg_version\x18\x01 \x02(\r\x12\x15\n\rfdinfo_per_id\x18\x02 \x01(\x08\x12&\n\x08root_ids\x18\x03 \x01(\x0b\x32\x14.task_kobj_ids_entry\x12\x11\n\tns_per_id\x18\x04 \x01(\x08\x12\x13\n\x0broot_cg_set\x18\x05 \x01(\r\x12\x19\n\x07lsmtype\x18\x06 \x01(\x0e\x32\x08.lsmtype\x12\x13\n\x0b\x64ump_uptime\x18\x08 \x01(\x04\x12\x15\n\rpre_dump_mode\x18\t \x01(\r\x12\x11\n\ttcp_close\x18\n \x01(\x08\x12\x1b\n\x13network_lock_method\x18\x0b \x01(\r*0\n\x07lsmtype\x12\n\n\x06NO_LSM\x10\x00\x12\x0b\n\x07SELINUX\x10\x01\x12\x0c\n\x08\x41PPARMOR\x10\x02')

_LSMTYPE = DESCRIPTOR.enum_types_by_name['lsmtype']
lsmtype = enum_type_wrapper.EnumTypeWrapper(_LSMTYPE)
NO_LSM = 0
SELINUX = 1
APPARMOR = 2


_INVENTORY_ENTRY = DESCRIPTOR.message_types_by_name['inventory_entry']
inventory_entry = _reflection.GeneratedProtocolMessageType('inventory_entry', (_message.Message,), {
  'DESCRIPTOR' : _INVENTORY_ENTRY,
  '__module__' : 'inventory_pb2'
  # @@protoc_insertion_point(class_scope:inventory_entry)
  })
_sym_db.RegisterMessage(inventory_entry)

if _descriptor._USE_C_DESCRIPTORS == False:

  DESCRIPTOR._options = None
  _LSMTYPE._serialized_start=294
  _LSMTYPE._serialized_end=342
  _INVENTORY_ENTRY._serialized_start=32
  _INVENTORY_ENTRY._serialized_end=292
# @@protoc_insertion_point(module_scope)