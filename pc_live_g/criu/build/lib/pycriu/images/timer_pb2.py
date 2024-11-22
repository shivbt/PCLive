# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: timer.proto
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x0btimer.proto\"H\n\x0citimer_entry\x12\x0c\n\x04isec\x18\x01 \x02(\x04\x12\r\n\x05iusec\x18\x02 \x02(\x04\x12\x0c\n\x04vsec\x18\x03 \x02(\x04\x12\r\n\x05vusec\x18\x04 \x02(\x04\"\xd7\x01\n\x11posix_timer_entry\x12\r\n\x05it_id\x18\x01 \x02(\r\x12\x10\n\x08\x63lock_id\x18\x02 \x02(\r\x12\x10\n\x08si_signo\x18\x03 \x02(\r\x12\x17\n\x0fit_sigev_notify\x18\x04 \x02(\r\x12\x11\n\tsival_ptr\x18\x05 \x02(\x04\x12\x0f\n\x07overrun\x18\x06 \x02(\r\x12\x0c\n\x04isec\x18\x07 \x02(\x04\x12\r\n\x05insec\x18\x08 \x02(\x04\x12\x0c\n\x04vsec\x18\t \x02(\x04\x12\r\n\x05vnsec\x18\n \x02(\x04\x12\x18\n\x10notify_thread_id\x18\x0b \x01(\x05\"\x8d\x01\n\x11task_timers_entry\x12\x1b\n\x04real\x18\x01 \x02(\x0b\x32\r.itimer_entry\x12\x1b\n\x04virt\x18\x02 \x02(\x0b\x32\r.itimer_entry\x12\x1b\n\x04prof\x18\x03 \x02(\x0b\x32\r.itimer_entry\x12!\n\x05posix\x18\x04 \x03(\x0b\x32\x12.posix_timer_entry')



_ITIMER_ENTRY = DESCRIPTOR.message_types_by_name['itimer_entry']
_POSIX_TIMER_ENTRY = DESCRIPTOR.message_types_by_name['posix_timer_entry']
_TASK_TIMERS_ENTRY = DESCRIPTOR.message_types_by_name['task_timers_entry']
itimer_entry = _reflection.GeneratedProtocolMessageType('itimer_entry', (_message.Message,), {
  'DESCRIPTOR' : _ITIMER_ENTRY,
  '__module__' : 'timer_pb2'
  # @@protoc_insertion_point(class_scope:itimer_entry)
  })
_sym_db.RegisterMessage(itimer_entry)

posix_timer_entry = _reflection.GeneratedProtocolMessageType('posix_timer_entry', (_message.Message,), {
  'DESCRIPTOR' : _POSIX_TIMER_ENTRY,
  '__module__' : 'timer_pb2'
  # @@protoc_insertion_point(class_scope:posix_timer_entry)
  })
_sym_db.RegisterMessage(posix_timer_entry)

task_timers_entry = _reflection.GeneratedProtocolMessageType('task_timers_entry', (_message.Message,), {
  'DESCRIPTOR' : _TASK_TIMERS_ENTRY,
  '__module__' : 'timer_pb2'
  # @@protoc_insertion_point(class_scope:task_timers_entry)
  })
_sym_db.RegisterMessage(task_timers_entry)

if _descriptor._USE_C_DESCRIPTORS == False:

  DESCRIPTOR._options = None
  _ITIMER_ENTRY._serialized_start=15
  _ITIMER_ENTRY._serialized_end=87
  _POSIX_TIMER_ENTRY._serialized_start=90
  _POSIX_TIMER_ENTRY._serialized_end=305
  _TASK_TIMERS_ENTRY._serialized_start=308
  _TASK_TIMERS_ENTRY._serialized_end=449
# @@protoc_insertion_point(module_scope)