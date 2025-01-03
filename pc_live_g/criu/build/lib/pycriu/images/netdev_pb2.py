# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: netdev.proto
"""Generated protocol buffer code."""
from google.protobuf.internal import enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


import macvlan_pb2 as macvlan__pb2
import opts_pb2 as opts__pb2
import tun_pb2 as tun__pb2
import sysctl_pb2 as sysctl__pb2
import sit_pb2 as sit__pb2


DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x0cnetdev.proto\x1a\rmacvlan.proto\x1a\nopts.proto\x1a\ttun.proto\x1a\x0csysctl.proto\x1a\tsit.proto\"\xdd\x02\n\x10net_device_entry\x12\x16\n\x04type\x18\x01 \x02(\x0e\x32\x08.nd_type\x12\x0f\n\x07ifindex\x18\x02 \x02(\r\x12\x0b\n\x03mtu\x18\x03 \x02(\r\x12\x14\n\x05\x66lags\x18\x04 \x02(\rB\x05\xd2?\x02\x08\x01\x12\x0c\n\x04name\x18\x05 \x02(\t\x12\x1c\n\x03tun\x18\x06 \x01(\x0b\x32\x0f.tun_link_entry\x12\x0f\n\x07\x61\x64\x64ress\x18\x07 \x01(\x0c\x12\x0c\n\x04\x63onf\x18\x08 \x03(\x05\x12\x1c\n\x05\x63onf4\x18\t \x03(\x0b\x32\r.sysctl_entry\x12\x1c\n\x05\x63onf6\x18\n \x03(\x0b\x32\r.sysctl_entry\x12$\n\x07macvlan\x18\x0b \x01(\x0b\x32\x13.macvlan_link_entry\x12\x14\n\x0cpeer_ifindex\x18\x0c \x01(\r\x12\x11\n\tpeer_nsid\x18\r \x01(\r\x12\x0e\n\x06master\x18\x0e \x01(\r\x12\x17\n\x03sit\x18\x0f \x01(\x0b\x32\n.sit_entry\"7\n\x08netns_id\x12\x14\n\x0ctarget_ns_id\x18\x01 \x02(\r\x12\x15\n\rnetnsid_value\x18\x02 \x02(\x05\"\x86\x02\n\x0bnetns_entry\x12\x10\n\x08\x64\x65\x66_conf\x18\x01 \x03(\x05\x12\x10\n\x08\x61ll_conf\x18\x02 \x03(\x05\x12 \n\tdef_conf4\x18\x03 \x03(\x0b\x32\r.sysctl_entry\x12 \n\tall_conf4\x18\x04 \x03(\x0b\x32\r.sysctl_entry\x12 \n\tdef_conf6\x18\x05 \x03(\x0b\x32\r.sysctl_entry\x12 \n\tall_conf6\x18\x06 \x03(\x0b\x32\r.sysctl_entry\x12\x18\n\x05nsids\x18\x07 \x03(\x0b\x32\t.netns_id\x12\x0f\n\x07\x65xt_key\x18\x08 \x01(\t\x12 \n\tunix_conf\x18\t \x03(\x0b\x32\r.sysctl_entry*d\n\x07nd_type\x12\x0c\n\x08LOOPBACK\x10\x01\x12\x08\n\x04VETH\x10\x02\x12\x07\n\x03TUN\x10\x03\x12\x0b\n\x07\x45XTLINK\x10\x04\x12\t\n\x05VENET\x10\x05\x12\n\n\x06\x42RIDGE\x10\x06\x12\x0b\n\x07MACVLAN\x10\x07\x12\x07\n\x03SIT\x10\x08')

_ND_TYPE = DESCRIPTOR.enum_types_by_name['nd_type']
nd_type = enum_type_wrapper.EnumTypeWrapper(_ND_TYPE)
LOOPBACK = 1
VETH = 2
TUN = 3
EXTLINK = 4
VENET = 5
BRIDGE = 6
MACVLAN = 7
SIT = 8


_NET_DEVICE_ENTRY = DESCRIPTOR.message_types_by_name['net_device_entry']
_NETNS_ID = DESCRIPTOR.message_types_by_name['netns_id']
_NETNS_ENTRY = DESCRIPTOR.message_types_by_name['netns_entry']
net_device_entry = _reflection.GeneratedProtocolMessageType('net_device_entry', (_message.Message,), {
  'DESCRIPTOR' : _NET_DEVICE_ENTRY,
  '__module__' : 'netdev_pb2'
  # @@protoc_insertion_point(class_scope:net_device_entry)
  })
_sym_db.RegisterMessage(net_device_entry)

netns_id = _reflection.GeneratedProtocolMessageType('netns_id', (_message.Message,), {
  'DESCRIPTOR' : _NETNS_ID,
  '__module__' : 'netdev_pb2'
  # @@protoc_insertion_point(class_scope:netns_id)
  })
_sym_db.RegisterMessage(netns_id)

netns_entry = _reflection.GeneratedProtocolMessageType('netns_entry', (_message.Message,), {
  'DESCRIPTOR' : _NETNS_ENTRY,
  '__module__' : 'netdev_pb2'
  # @@protoc_insertion_point(class_scope:netns_entry)
  })
_sym_db.RegisterMessage(netns_entry)

if _descriptor._USE_C_DESCRIPTORS == False:

  DESCRIPTOR._options = None
  _NET_DEVICE_ENTRY.fields_by_name['flags']._options = None
  _NET_DEVICE_ENTRY.fields_by_name['flags']._serialized_options = b'\322?\002\010\001'
  _ND_TYPE._serialized_start=753
  _ND_TYPE._serialized_end=853
  _NET_DEVICE_ENTRY._serialized_start=80
  _NET_DEVICE_ENTRY._serialized_end=429
  _NETNS_ID._serialized_start=431
  _NETNS_ID._serialized_end=486
  _NETNS_ENTRY._serialized_start=489
  _NETNS_ENTRY._serialized_end=751
# @@protoc_insertion_point(module_scope)
