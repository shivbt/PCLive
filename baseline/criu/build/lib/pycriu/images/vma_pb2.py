# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: vma.proto
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


import opts_pb2 as opts__pb2


DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\tvma.proto\x1a\nopts.proto\"\xec\x01\n\tvma_entry\x12\x14\n\x05start\x18\x01 \x02(\x04\x42\x05\xd2?\x02\x08\x01\x12\x12\n\x03\x65nd\x18\x02 \x02(\x04\x42\x05\xd2?\x02\x08\x01\x12\r\n\x05pgoff\x18\x03 \x02(\x04\x12\r\n\x05shmid\x18\x04 \x02(\x04\x12\x1c\n\x04prot\x18\x05 \x02(\rB\x0e\xd2?\x0b\x1a\tmmap.prot\x12\x1e\n\x05\x66lags\x18\x06 \x02(\rB\x0f\xd2?\x0c\x1a\nmmap.flags\x12 \n\x06status\x18\x07 \x02(\rB\x10\xd2?\r\x1a\x0bmmap.status\x12\n\n\x02\x66\x64\x18\x08 \x02(\x12\x12\x13\n\x04madv\x18\t \x01(\x04\x42\x05\xd2?\x02\x08\x01\x12\x16\n\x07\x66\x64\x66lags\x18\n \x01(\rB\x05\xd2?\x02\x08\x01')



_VMA_ENTRY = DESCRIPTOR.message_types_by_name['vma_entry']
vma_entry = _reflection.GeneratedProtocolMessageType('vma_entry', (_message.Message,), {
  'DESCRIPTOR' : _VMA_ENTRY,
  '__module__' : 'vma_pb2'
  # @@protoc_insertion_point(class_scope:vma_entry)
  })
_sym_db.RegisterMessage(vma_entry)

if _descriptor._USE_C_DESCRIPTORS == False:

  DESCRIPTOR._options = None
  _VMA_ENTRY.fields_by_name['start']._options = None
  _VMA_ENTRY.fields_by_name['start']._serialized_options = b'\322?\002\010\001'
  _VMA_ENTRY.fields_by_name['end']._options = None
  _VMA_ENTRY.fields_by_name['end']._serialized_options = b'\322?\002\010\001'
  _VMA_ENTRY.fields_by_name['prot']._options = None
  _VMA_ENTRY.fields_by_name['prot']._serialized_options = b'\322?\013\032\tmmap.prot'
  _VMA_ENTRY.fields_by_name['flags']._options = None
  _VMA_ENTRY.fields_by_name['flags']._serialized_options = b'\322?\014\032\nmmap.flags'
  _VMA_ENTRY.fields_by_name['status']._options = None
  _VMA_ENTRY.fields_by_name['status']._serialized_options = b'\322?\r\032\013mmap.status'
  _VMA_ENTRY.fields_by_name['madv']._options = None
  _VMA_ENTRY.fields_by_name['madv']._serialized_options = b'\322?\002\010\001'
  _VMA_ENTRY.fields_by_name['fdflags']._options = None
  _VMA_ENTRY.fields_by_name['fdflags']._serialized_options = b'\322?\002\010\001'
  _VMA_ENTRY._serialized_start=26
  _VMA_ENTRY._serialized_end=262
# @@protoc_insertion_point(module_scope)