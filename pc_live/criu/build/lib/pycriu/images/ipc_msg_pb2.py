# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: ipc-msg.proto
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


import ipc_desc_pb2 as ipc__desc__pb2


DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\ripc-msg.proto\x1a\x0eipc-desc.proto\"\'\n\x07ipc_msg\x12\r\n\x05mtype\x18\x01 \x02(\x04\x12\r\n\x05msize\x18\x02 \x02(\r\"L\n\ripc_msg_entry\x12\x1d\n\x04\x64\x65sc\x18\x01 \x02(\x0b\x32\x0f.ipc_desc_entry\x12\x0e\n\x06qbytes\x18\x02 \x02(\r\x12\x0c\n\x04qnum\x18\x03 \x02(\r')



_IPC_MSG = DESCRIPTOR.message_types_by_name['ipc_msg']
_IPC_MSG_ENTRY = DESCRIPTOR.message_types_by_name['ipc_msg_entry']
ipc_msg = _reflection.GeneratedProtocolMessageType('ipc_msg', (_message.Message,), {
  'DESCRIPTOR' : _IPC_MSG,
  '__module__' : 'ipc_msg_pb2'
  # @@protoc_insertion_point(class_scope:ipc_msg)
  })
_sym_db.RegisterMessage(ipc_msg)

ipc_msg_entry = _reflection.GeneratedProtocolMessageType('ipc_msg_entry', (_message.Message,), {
  'DESCRIPTOR' : _IPC_MSG_ENTRY,
  '__module__' : 'ipc_msg_pb2'
  # @@protoc_insertion_point(class_scope:ipc_msg_entry)
  })
_sym_db.RegisterMessage(ipc_msg_entry)

if _descriptor._USE_C_DESCRIPTORS == False:

  DESCRIPTOR._options = None
  _IPC_MSG._serialized_start=33
  _IPC_MSG._serialized_end=72
  _IPC_MSG_ENTRY._serialized_start=74
  _IPC_MSG_ENTRY._serialized_end=150
# @@protoc_insertion_point(module_scope)
