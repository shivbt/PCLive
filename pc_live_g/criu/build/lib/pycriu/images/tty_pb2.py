# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: tty.proto
"""Generated protocol buffer code."""
from google.protobuf.internal import enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


import opts_pb2 as opts__pb2
import fown_pb2 as fown__pb2


DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\ttty.proto\x1a\nopts.proto\x1a\nfown.proto\"U\n\rwinsize_entry\x12\x0e\n\x06ws_row\x18\x01 \x02(\r\x12\x0e\n\x06ws_col\x18\x02 \x02(\r\x12\x11\n\tws_xpixel\x18\x03 \x02(\r\x12\x11\n\tws_ypixel\x18\x04 \x02(\r\"\x95\x01\n\rtermios_entry\x12\x0f\n\x07\x63_iflag\x18\x01 \x02(\r\x12\x0f\n\x07\x63_oflag\x18\x02 \x02(\r\x12\x0f\n\x07\x63_cflag\x18\x03 \x02(\r\x12\x0f\n\x07\x63_lflag\x18\x04 \x02(\r\x12\x0e\n\x06\x63_line\x18\x05 \x02(\r\x12\x10\n\x08\x63_ispeed\x18\x06 \x02(\r\x12\x10\n\x08\x63_ospeed\x18\x07 \x02(\r\x12\x0c\n\x04\x63_cc\x18\x08 \x03(\r\"\x1e\n\rtty_pty_entry\x12\r\n\x05index\x18\x01 \x02(\r\".\n\x0etty_data_entry\x12\x0e\n\x06tty_id\x18\x01 \x02(\r\x12\x0c\n\x04\x64\x61ta\x18\x02 \x02(\x0c\"\xc3\x02\n\x0etty_info_entry\x12\n\n\x02id\x18\x01 \x02(\r\x12\x16\n\x04type\x18\x02 \x02(\x0e\x32\x08.TtyType\x12\x0e\n\x06locked\x18\x03 \x02(\x08\x12\x11\n\texclusive\x18\x04 \x02(\x08\x12\x13\n\x0bpacket_mode\x18\x05 \x02(\x08\x12\x0b\n\x03sid\x18\x06 \x02(\r\x12\x0c\n\x04pgrp\x18\x07 \x02(\r\x12\x0c\n\x04rdev\x18\x08 \x02(\r\x12\x1f\n\x07termios\x18\t \x01(\x0b\x32\x0e.termios_entry\x12&\n\x0etermios_locked\x18\n \x01(\x0b\x32\x0e.termios_entry\x12\x1f\n\x07winsize\x18\x0b \x01(\x0b\x32\x0e.winsize_entry\x12\x1b\n\x03pty\x18\x0c \x01(\x0b\x32\x0e.tty_pty_entry\x12\x0b\n\x03\x64\x65v\x18\r \x01(\r\x12\x0b\n\x03uid\x18\x0e \x01(\r\x12\x0b\n\x03gid\x18\x0f \x01(\r\"s\n\x0etty_file_entry\x12\n\n\x02id\x18\x01 \x02(\r\x12\x13\n\x0btty_info_id\x18\x02 \x02(\r\x12\x14\n\x05\x66lags\x18\x03 \x02(\rB\x05\xd2?\x02\x08\x01\x12\x19\n\x04\x66own\x18\x04 \x02(\x0b\x32\x0b.fown_entry\x12\x0f\n\x07regf_id\x18\x06 \x01(\r*W\n\x07TtyType\x12\x0b\n\x07UNKNOWN\x10\x00\x12\x07\n\x03PTY\x10\x01\x12\x0b\n\x07\x43ONSOLE\x10\x02\x12\x06\n\x02VT\x10\x03\x12\x08\n\x04\x43TTY\x10\x04\x12\x0b\n\x07\x45XT_TTY\x10\x05\x12\n\n\x06SERIAL\x10\x06')

_TTYTYPE = DESCRIPTOR.enum_types_by_name['TtyType']
TtyType = enum_type_wrapper.EnumTypeWrapper(_TTYTYPE)
UNKNOWN = 0
PTY = 1
CONSOLE = 2
VT = 3
CTTY = 4
EXT_TTY = 5
SERIAL = 6


_WINSIZE_ENTRY = DESCRIPTOR.message_types_by_name['winsize_entry']
_TERMIOS_ENTRY = DESCRIPTOR.message_types_by_name['termios_entry']
_TTY_PTY_ENTRY = DESCRIPTOR.message_types_by_name['tty_pty_entry']
_TTY_DATA_ENTRY = DESCRIPTOR.message_types_by_name['tty_data_entry']
_TTY_INFO_ENTRY = DESCRIPTOR.message_types_by_name['tty_info_entry']
_TTY_FILE_ENTRY = DESCRIPTOR.message_types_by_name['tty_file_entry']
winsize_entry = _reflection.GeneratedProtocolMessageType('winsize_entry', (_message.Message,), {
  'DESCRIPTOR' : _WINSIZE_ENTRY,
  '__module__' : 'tty_pb2'
  # @@protoc_insertion_point(class_scope:winsize_entry)
  })
_sym_db.RegisterMessage(winsize_entry)

termios_entry = _reflection.GeneratedProtocolMessageType('termios_entry', (_message.Message,), {
  'DESCRIPTOR' : _TERMIOS_ENTRY,
  '__module__' : 'tty_pb2'
  # @@protoc_insertion_point(class_scope:termios_entry)
  })
_sym_db.RegisterMessage(termios_entry)

tty_pty_entry = _reflection.GeneratedProtocolMessageType('tty_pty_entry', (_message.Message,), {
  'DESCRIPTOR' : _TTY_PTY_ENTRY,
  '__module__' : 'tty_pb2'
  # @@protoc_insertion_point(class_scope:tty_pty_entry)
  })
_sym_db.RegisterMessage(tty_pty_entry)

tty_data_entry = _reflection.GeneratedProtocolMessageType('tty_data_entry', (_message.Message,), {
  'DESCRIPTOR' : _TTY_DATA_ENTRY,
  '__module__' : 'tty_pb2'
  # @@protoc_insertion_point(class_scope:tty_data_entry)
  })
_sym_db.RegisterMessage(tty_data_entry)

tty_info_entry = _reflection.GeneratedProtocolMessageType('tty_info_entry', (_message.Message,), {
  'DESCRIPTOR' : _TTY_INFO_ENTRY,
  '__module__' : 'tty_pb2'
  # @@protoc_insertion_point(class_scope:tty_info_entry)
  })
_sym_db.RegisterMessage(tty_info_entry)

tty_file_entry = _reflection.GeneratedProtocolMessageType('tty_file_entry', (_message.Message,), {
  'DESCRIPTOR' : _TTY_FILE_ENTRY,
  '__module__' : 'tty_pb2'
  # @@protoc_insertion_point(class_scope:tty_file_entry)
  })
_sym_db.RegisterMessage(tty_file_entry)

if _descriptor._USE_C_DESCRIPTORS == False:

  DESCRIPTOR._options = None
  _TTY_FILE_ENTRY.fields_by_name['flags']._options = None
  _TTY_FILE_ENTRY.fields_by_name['flags']._serialized_options = b'\322?\002\010\001'
  _TTYTYPE._serialized_start=799
  _TTYTYPE._serialized_end=886
  _WINSIZE_ENTRY._serialized_start=37
  _WINSIZE_ENTRY._serialized_end=122
  _TERMIOS_ENTRY._serialized_start=125
  _TERMIOS_ENTRY._serialized_end=274
  _TTY_PTY_ENTRY._serialized_start=276
  _TTY_PTY_ENTRY._serialized_end=306
  _TTY_DATA_ENTRY._serialized_start=308
  _TTY_DATA_ENTRY._serialized_end=354
  _TTY_INFO_ENTRY._serialized_start=357
  _TTY_INFO_ENTRY._serialized_end=680
  _TTY_FILE_ENTRY._serialized_start=682
  _TTY_FILE_ENTRY._serialized_end=797
# @@protoc_insertion_point(module_scope)
