/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: rpc.proto */

#ifndef PROTOBUF_C_rpc_2eproto__INCLUDED
#define PROTOBUF_C_rpc_2eproto__INCLUDED

#include <protobuf-c/protobuf-c.h>

PROTOBUF_C__BEGIN_DECLS

#if PROTOBUF_C_VERSION_NUMBER < 1000000
# error This file was generated by a newer version of protoc-c which is incompatible with your libprotobuf-c headers. Please update your headers.
#elif 1002001 < PROTOBUF_C_MIN_COMPILER_VERSION
# error This file was generated by an older version of protoc-c which is incompatible with your libprotobuf-c headers. Please regenerate this file with a newer version of protoc-c.
#endif


typedef struct _CriuPageServerInfo CriuPageServerInfo;
typedef struct _CriuVethPair CriuVethPair;
typedef struct _ExtMountMap ExtMountMap;
typedef struct _JoinNamespace JoinNamespace;
typedef struct _InheritFd InheritFd;
typedef struct _CgroupRoot CgroupRoot;
typedef struct _UnixSk UnixSk;
typedef struct _CriuOpts CriuOpts;
typedef struct _CriuDumpResp CriuDumpResp;
typedef struct _CriuRestoreResp CriuRestoreResp;
typedef struct _CriuNotify CriuNotify;
typedef struct _CriuFeatures CriuFeatures;
typedef struct _CriuReq CriuReq;
typedef struct _CriuResp CriuResp;
typedef struct _CriuVersion CriuVersion;


/* --- enums --- */

typedef enum _CriuCgMode {
  CRIU_CG_MODE__IGNORE = 0,
  CRIU_CG_MODE__CG_NONE = 1,
  CRIU_CG_MODE__PROPS = 2,
  CRIU_CG_MODE__SOFT = 3,
  CRIU_CG_MODE__FULL = 4,
  CRIU_CG_MODE__STRICT = 5,
  CRIU_CG_MODE__DEFAULT = 6
    PROTOBUF_C__FORCE_ENUM_TO_BE_INT_SIZE(CRIU_CG_MODE)
} CriuCgMode;
typedef enum _CriuNetworkLockMethod {
  CRIU_NETWORK_LOCK_METHOD__IPTABLES = 1,
  CRIU_NETWORK_LOCK_METHOD__NFTABLES = 2
    PROTOBUF_C__FORCE_ENUM_TO_BE_INT_SIZE(CRIU_NETWORK_LOCK_METHOD)
} CriuNetworkLockMethod;
typedef enum _CriuPreDumpMode {
  CRIU_PRE_DUMP_MODE__SPLICE = 1,
  CRIU_PRE_DUMP_MODE__VM_READ = 2
    PROTOBUF_C__FORCE_ENUM_TO_BE_INT_SIZE(CRIU_PRE_DUMP_MODE)
} CriuPreDumpMode;
typedef enum _CriuReqType {
  CRIU_REQ_TYPE__EMPTY = 0,
  CRIU_REQ_TYPE__DUMP = 1,
  CRIU_REQ_TYPE__RESTORE = 2,
  CRIU_REQ_TYPE__CHECK = 3,
  CRIU_REQ_TYPE__PRE_DUMP = 4,
  CRIU_REQ_TYPE__PAGE_SERVER = 5,
  CRIU_REQ_TYPE__NOTIFY = 6,
  CRIU_REQ_TYPE__CPUINFO_DUMP = 7,
  CRIU_REQ_TYPE__CPUINFO_CHECK = 8,
  CRIU_REQ_TYPE__FEATURE_CHECK = 9,
  CRIU_REQ_TYPE__VERSION = 10,
  CRIU_REQ_TYPE__WAIT_PID = 11,
  CRIU_REQ_TYPE__PAGE_SERVER_CHLD = 12
    PROTOBUF_C__FORCE_ENUM_TO_BE_INT_SIZE(CRIU_REQ_TYPE)
} CriuReqType;

/* --- messages --- */

struct  _CriuPageServerInfo
{
  ProtobufCMessage base;
  char *address;
  protobuf_c_boolean has_port;
  int32_t port;
  protobuf_c_boolean has_pid;
  int32_t pid;
  protobuf_c_boolean has_fd;
  int32_t fd;
};
#define CRIU_PAGE_SERVER_INFO__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&criu_page_server_info__descriptor) \
    , NULL, 0,0, 0,0, 0,0 }


struct  _CriuVethPair
{
  ProtobufCMessage base;
  char *if_in;
  char *if_out;
};
#define CRIU_VETH_PAIR__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&criu_veth_pair__descriptor) \
    , NULL, NULL }


struct  _ExtMountMap
{
  ProtobufCMessage base;
  char *key;
  char *val;
};
#define EXT_MOUNT_MAP__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&ext_mount_map__descriptor) \
    , NULL, NULL }


struct  _JoinNamespace
{
  ProtobufCMessage base;
  char *ns;
  char *ns_file;
  char *extra_opt;
};
#define JOIN_NAMESPACE__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&join_namespace__descriptor) \
    , NULL, NULL, NULL }


struct  _InheritFd
{
  ProtobufCMessage base;
  char *key;
  int32_t fd;
};
#define INHERIT_FD__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&inherit_fd__descriptor) \
    , NULL, 0 }


struct  _CgroupRoot
{
  ProtobufCMessage base;
  char *ctrl;
  char *path;
};
#define CGROUP_ROOT__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&cgroup_root__descriptor) \
    , NULL, NULL }


struct  _UnixSk
{
  ProtobufCMessage base;
  uint32_t inode;
};
#define UNIX_SK__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&unix_sk__descriptor) \
    , 0 }


struct  _CriuOpts
{
  ProtobufCMessage base;
  int32_t images_dir_fd;
  /*
   * if not set on dump, will dump requesting process 
   */
  protobuf_c_boolean has_pid;
  int32_t pid;
  protobuf_c_boolean has_leave_running;
  protobuf_c_boolean leave_running;
  protobuf_c_boolean has_ext_unix_sk;
  protobuf_c_boolean ext_unix_sk;
  protobuf_c_boolean has_tcp_established;
  protobuf_c_boolean tcp_established;
  protobuf_c_boolean has_evasive_devices;
  protobuf_c_boolean evasive_devices;
  protobuf_c_boolean has_shell_job;
  protobuf_c_boolean shell_job;
  protobuf_c_boolean has_file_locks;
  protobuf_c_boolean file_locks;
  protobuf_c_boolean has_log_level;
  int32_t log_level;
  /*
   * No subdirs are allowed. Consider using work-dir 
   */
  char *log_file;
  CriuPageServerInfo *ps;
  protobuf_c_boolean has_notify_scripts;
  protobuf_c_boolean notify_scripts;
  char *root;
  char *parent_img;
  protobuf_c_boolean has_track_mem;
  protobuf_c_boolean track_mem;
  protobuf_c_boolean has_auto_dedup;
  protobuf_c_boolean auto_dedup;
  protobuf_c_boolean has_work_dir_fd;
  int32_t work_dir_fd;
  protobuf_c_boolean has_link_remap;
  protobuf_c_boolean link_remap;
  /*
   * DEPRECATED, use external instead 
   */
  size_t n_veths;
  CriuVethPair **veths;
  protobuf_c_boolean has_cpu_cap;
  uint32_t cpu_cap;
  protobuf_c_boolean has_force_irmap;
  protobuf_c_boolean force_irmap;
  size_t n_exec_cmd;
  char **exec_cmd;
  /*
   * DEPRECATED, use external instead 
   */
  size_t n_ext_mnt;
  ExtMountMap **ext_mnt;
  /*
   * backward compatibility 
   */
  protobuf_c_boolean has_manage_cgroups;
  protobuf_c_boolean manage_cgroups;
  size_t n_cg_root;
  CgroupRoot **cg_root;
  /*
   * swrk only 
   */
  protobuf_c_boolean has_rst_sibling;
  protobuf_c_boolean rst_sibling;
  /*
   * swrk only 
   */
  size_t n_inherit_fd;
  InheritFd **inherit_fd;
  protobuf_c_boolean has_auto_ext_mnt;
  protobuf_c_boolean auto_ext_mnt;
  protobuf_c_boolean has_ext_sharing;
  protobuf_c_boolean ext_sharing;
  protobuf_c_boolean has_ext_masters;
  protobuf_c_boolean ext_masters;
  size_t n_skip_mnt;
  char **skip_mnt;
  size_t n_enable_fs;
  char **enable_fs;
  /*
   * DEPRECATED, use external instead 
   */
  size_t n_unix_sk_ino;
  UnixSk **unix_sk_ino;
  protobuf_c_boolean has_manage_cgroups_mode;
  CriuCgMode manage_cgroups_mode;
  protobuf_c_boolean has_ghost_limit;
  uint32_t ghost_limit;
  size_t n_irmap_scan_paths;
  char **irmap_scan_paths;
  size_t n_external;
  char **external;
  protobuf_c_boolean has_empty_ns;
  uint32_t empty_ns;
  size_t n_join_ns;
  JoinNamespace **join_ns;
  char *cgroup_props;
  char *cgroup_props_file;
  size_t n_cgroup_dump_controller;
  char **cgroup_dump_controller;
  char *freeze_cgroup;
  protobuf_c_boolean has_timeout;
  uint32_t timeout;
  protobuf_c_boolean has_tcp_skip_in_flight;
  protobuf_c_boolean tcp_skip_in_flight;
  protobuf_c_boolean has_weak_sysctls;
  protobuf_c_boolean weak_sysctls;
  protobuf_c_boolean has_lazy_pages;
  protobuf_c_boolean lazy_pages;
  protobuf_c_boolean has_status_fd;
  int32_t status_fd;
  protobuf_c_boolean has_orphan_pts_master;
  protobuf_c_boolean orphan_pts_master;
  char *config_file;
  protobuf_c_boolean has_tcp_close;
  protobuf_c_boolean tcp_close;
  char *lsm_profile;
  char *tls_cacert;
  char *tls_cacrl;
  char *tls_cert;
  char *tls_key;
  protobuf_c_boolean has_tls;
  protobuf_c_boolean tls;
  protobuf_c_boolean has_tls_no_cn_verify;
  protobuf_c_boolean tls_no_cn_verify;
  char *cgroup_yard;
  protobuf_c_boolean has_pre_dump_mode;
  CriuPreDumpMode pre_dump_mode;
  protobuf_c_boolean has_pidfd_store_sk;
  int32_t pidfd_store_sk;
  char *lsm_mount_context;
  /*
   *	optional bool			check_mounts		= 128;	
   */
  protobuf_c_boolean has_network_lock;
  CriuNetworkLockMethod network_lock;
};
#define CRIU_OPTS__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&criu_opts__descriptor) \
    , 0, 0,0, 0,0, 0,0, 0,0, 0,0, 0,0, 0,0, 0,2, NULL, NULL, 0,0, NULL, NULL, 0,0, 0,0, 0,0, 0,0, 0,NULL, 0,4294967295u, 0,0, 0,NULL, 0,NULL, 0,0, 0,NULL, 0,0, 0,NULL, 0,0, 0,0, 0,0, 0,NULL, 0,NULL, 0,NULL, 0,0, 0,1048576u, 0,NULL, 0,NULL, 0,0, 0,NULL, NULL, NULL, 0,NULL, NULL, 0,0, 0,0, 0,0, 0,0, 0,0, 0,0, NULL, 0,0, NULL, NULL, NULL, NULL, NULL, 0,0, 0,0, NULL, 0,CRIU_PRE_DUMP_MODE__SPLICE, 0,0, NULL, 0,CRIU_NETWORK_LOCK_METHOD__IPTABLES }


struct  _CriuDumpResp
{
  ProtobufCMessage base;
  protobuf_c_boolean has_restored;
  protobuf_c_boolean restored;
};
#define CRIU_DUMP_RESP__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&criu_dump_resp__descriptor) \
    , 0,0 }


struct  _CriuRestoreResp
{
  ProtobufCMessage base;
  int32_t pid;
};
#define CRIU_RESTORE_RESP__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&criu_restore_resp__descriptor) \
    , 0 }


struct  _CriuNotify
{
  ProtobufCMessage base;
  char *script;
  protobuf_c_boolean has_pid;
  int32_t pid;
};
#define CRIU_NOTIFY__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&criu_notify__descriptor) \
    , NULL, 0,0 }


/*
 * List of features which can queried via
 * CRIU_REQ_TYPE__FEATURE_CHECK
 */
struct  _CriuFeatures
{
  ProtobufCMessage base;
  protobuf_c_boolean has_mem_track;
  protobuf_c_boolean mem_track;
  protobuf_c_boolean has_lazy_pages;
  protobuf_c_boolean lazy_pages;
  protobuf_c_boolean has_pidfd_store;
  protobuf_c_boolean pidfd_store;
};
#define CRIU_FEATURES__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&criu_features__descriptor) \
    , 0,0, 0,0, 0,0 }


struct  _CriuReq
{
  ProtobufCMessage base;
  CriuReqType type;
  CriuOpts *opts;
  protobuf_c_boolean has_notify_success;
  protobuf_c_boolean notify_success;
  /*
   * When set service won't close the connection but
   * will wait for more req-s to appear. Works not
   * for all request types.
   */
  protobuf_c_boolean has_keep_open;
  protobuf_c_boolean keep_open;
  /*
   * 'features' can be used to query which features
   * are supported by the installed criu/kernel
   * via RPC.
   */
  CriuFeatures *features;
  /*
   * 'pid' is used for WAIT_PID 
   */
  protobuf_c_boolean has_pid;
  uint32_t pid;
};
#define CRIU_REQ__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&criu_req__descriptor) \
    , 0, NULL, 0,0, 0,0, NULL, 0,0 }


struct  _CriuResp
{
  ProtobufCMessage base;
  CriuReqType type;
  protobuf_c_boolean success;
  CriuDumpResp *dump;
  CriuRestoreResp *restore;
  CriuNotify *notify;
  CriuPageServerInfo *ps;
  protobuf_c_boolean has_cr_errno;
  int32_t cr_errno;
  CriuFeatures *features;
  char *cr_errmsg;
  CriuVersion *version;
  protobuf_c_boolean has_status;
  int32_t status;
};
#define CRIU_RESP__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&criu_resp__descriptor) \
    , 0, 0, NULL, NULL, NULL, NULL, 0,0, NULL, NULL, NULL, 0,0 }


/*
 * Answer for criu_req_type.VERSION requests 
 */
struct  _CriuVersion
{
  ProtobufCMessage base;
  int32_t major_number;
  int32_t minor_number;
  char *gitid;
  protobuf_c_boolean has_sublevel;
  int32_t sublevel;
  protobuf_c_boolean has_extra;
  int32_t extra;
  char *name;
};
#define CRIU_VERSION__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&criu_version__descriptor) \
    , 0, 0, NULL, 0,0, 0,0, NULL }


/* CriuPageServerInfo methods */
void   criu_page_server_info__init
                     (CriuPageServerInfo         *message);
size_t criu_page_server_info__get_packed_size
                     (const CriuPageServerInfo   *message);
size_t criu_page_server_info__pack
                     (const CriuPageServerInfo   *message,
                      uint8_t             *out);
size_t criu_page_server_info__pack_to_buffer
                     (const CriuPageServerInfo   *message,
                      ProtobufCBuffer     *buffer);
CriuPageServerInfo *
       criu_page_server_info__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   criu_page_server_info__free_unpacked
                     (CriuPageServerInfo *message,
                      ProtobufCAllocator *allocator);
/* CriuVethPair methods */
void   criu_veth_pair__init
                     (CriuVethPair         *message);
size_t criu_veth_pair__get_packed_size
                     (const CriuVethPair   *message);
size_t criu_veth_pair__pack
                     (const CriuVethPair   *message,
                      uint8_t             *out);
size_t criu_veth_pair__pack_to_buffer
                     (const CriuVethPair   *message,
                      ProtobufCBuffer     *buffer);
CriuVethPair *
       criu_veth_pair__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   criu_veth_pair__free_unpacked
                     (CriuVethPair *message,
                      ProtobufCAllocator *allocator);
/* ExtMountMap methods */
void   ext_mount_map__init
                     (ExtMountMap         *message);
size_t ext_mount_map__get_packed_size
                     (const ExtMountMap   *message);
size_t ext_mount_map__pack
                     (const ExtMountMap   *message,
                      uint8_t             *out);
size_t ext_mount_map__pack_to_buffer
                     (const ExtMountMap   *message,
                      ProtobufCBuffer     *buffer);
ExtMountMap *
       ext_mount_map__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   ext_mount_map__free_unpacked
                     (ExtMountMap *message,
                      ProtobufCAllocator *allocator);
/* JoinNamespace methods */
void   join_namespace__init
                     (JoinNamespace         *message);
size_t join_namespace__get_packed_size
                     (const JoinNamespace   *message);
size_t join_namespace__pack
                     (const JoinNamespace   *message,
                      uint8_t             *out);
size_t join_namespace__pack_to_buffer
                     (const JoinNamespace   *message,
                      ProtobufCBuffer     *buffer);
JoinNamespace *
       join_namespace__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   join_namespace__free_unpacked
                     (JoinNamespace *message,
                      ProtobufCAllocator *allocator);
/* InheritFd methods */
void   inherit_fd__init
                     (InheritFd         *message);
size_t inherit_fd__get_packed_size
                     (const InheritFd   *message);
size_t inherit_fd__pack
                     (const InheritFd   *message,
                      uint8_t             *out);
size_t inherit_fd__pack_to_buffer
                     (const InheritFd   *message,
                      ProtobufCBuffer     *buffer);
InheritFd *
       inherit_fd__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   inherit_fd__free_unpacked
                     (InheritFd *message,
                      ProtobufCAllocator *allocator);
/* CgroupRoot methods */
void   cgroup_root__init
                     (CgroupRoot         *message);
size_t cgroup_root__get_packed_size
                     (const CgroupRoot   *message);
size_t cgroup_root__pack
                     (const CgroupRoot   *message,
                      uint8_t             *out);
size_t cgroup_root__pack_to_buffer
                     (const CgroupRoot   *message,
                      ProtobufCBuffer     *buffer);
CgroupRoot *
       cgroup_root__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   cgroup_root__free_unpacked
                     (CgroupRoot *message,
                      ProtobufCAllocator *allocator);
/* UnixSk methods */
void   unix_sk__init
                     (UnixSk         *message);
size_t unix_sk__get_packed_size
                     (const UnixSk   *message);
size_t unix_sk__pack
                     (const UnixSk   *message,
                      uint8_t             *out);
size_t unix_sk__pack_to_buffer
                     (const UnixSk   *message,
                      ProtobufCBuffer     *buffer);
UnixSk *
       unix_sk__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   unix_sk__free_unpacked
                     (UnixSk *message,
                      ProtobufCAllocator *allocator);
/* CriuOpts methods */
void   criu_opts__init
                     (CriuOpts         *message);
size_t criu_opts__get_packed_size
                     (const CriuOpts   *message);
size_t criu_opts__pack
                     (const CriuOpts   *message,
                      uint8_t             *out);
size_t criu_opts__pack_to_buffer
                     (const CriuOpts   *message,
                      ProtobufCBuffer     *buffer);
CriuOpts *
       criu_opts__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   criu_opts__free_unpacked
                     (CriuOpts *message,
                      ProtobufCAllocator *allocator);
/* CriuDumpResp methods */
void   criu_dump_resp__init
                     (CriuDumpResp         *message);
size_t criu_dump_resp__get_packed_size
                     (const CriuDumpResp   *message);
size_t criu_dump_resp__pack
                     (const CriuDumpResp   *message,
                      uint8_t             *out);
size_t criu_dump_resp__pack_to_buffer
                     (const CriuDumpResp   *message,
                      ProtobufCBuffer     *buffer);
CriuDumpResp *
       criu_dump_resp__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   criu_dump_resp__free_unpacked
                     (CriuDumpResp *message,
                      ProtobufCAllocator *allocator);
/* CriuRestoreResp methods */
void   criu_restore_resp__init
                     (CriuRestoreResp         *message);
size_t criu_restore_resp__get_packed_size
                     (const CriuRestoreResp   *message);
size_t criu_restore_resp__pack
                     (const CriuRestoreResp   *message,
                      uint8_t             *out);
size_t criu_restore_resp__pack_to_buffer
                     (const CriuRestoreResp   *message,
                      ProtobufCBuffer     *buffer);
CriuRestoreResp *
       criu_restore_resp__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   criu_restore_resp__free_unpacked
                     (CriuRestoreResp *message,
                      ProtobufCAllocator *allocator);
/* CriuNotify methods */
void   criu_notify__init
                     (CriuNotify         *message);
size_t criu_notify__get_packed_size
                     (const CriuNotify   *message);
size_t criu_notify__pack
                     (const CriuNotify   *message,
                      uint8_t             *out);
size_t criu_notify__pack_to_buffer
                     (const CriuNotify   *message,
                      ProtobufCBuffer     *buffer);
CriuNotify *
       criu_notify__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   criu_notify__free_unpacked
                     (CriuNotify *message,
                      ProtobufCAllocator *allocator);
/* CriuFeatures methods */
void   criu_features__init
                     (CriuFeatures         *message);
size_t criu_features__get_packed_size
                     (const CriuFeatures   *message);
size_t criu_features__pack
                     (const CriuFeatures   *message,
                      uint8_t             *out);
size_t criu_features__pack_to_buffer
                     (const CriuFeatures   *message,
                      ProtobufCBuffer     *buffer);
CriuFeatures *
       criu_features__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   criu_features__free_unpacked
                     (CriuFeatures *message,
                      ProtobufCAllocator *allocator);
/* CriuReq methods */
void   criu_req__init
                     (CriuReq         *message);
size_t criu_req__get_packed_size
                     (const CriuReq   *message);
size_t criu_req__pack
                     (const CriuReq   *message,
                      uint8_t             *out);
size_t criu_req__pack_to_buffer
                     (const CriuReq   *message,
                      ProtobufCBuffer     *buffer);
CriuReq *
       criu_req__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   criu_req__free_unpacked
                     (CriuReq *message,
                      ProtobufCAllocator *allocator);
/* CriuResp methods */
void   criu_resp__init
                     (CriuResp         *message);
size_t criu_resp__get_packed_size
                     (const CriuResp   *message);
size_t criu_resp__pack
                     (const CriuResp   *message,
                      uint8_t             *out);
size_t criu_resp__pack_to_buffer
                     (const CriuResp   *message,
                      ProtobufCBuffer     *buffer);
CriuResp *
       criu_resp__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   criu_resp__free_unpacked
                     (CriuResp *message,
                      ProtobufCAllocator *allocator);
/* CriuVersion methods */
void   criu_version__init
                     (CriuVersion         *message);
size_t criu_version__get_packed_size
                     (const CriuVersion   *message);
size_t criu_version__pack
                     (const CriuVersion   *message,
                      uint8_t             *out);
size_t criu_version__pack_to_buffer
                     (const CriuVersion   *message,
                      ProtobufCBuffer     *buffer);
CriuVersion *
       criu_version__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   criu_version__free_unpacked
                     (CriuVersion *message,
                      ProtobufCAllocator *allocator);
/* --- per-message closures --- */

typedef void (*CriuPageServerInfo_Closure)
                 (const CriuPageServerInfo *message,
                  void *closure_data);
typedef void (*CriuVethPair_Closure)
                 (const CriuVethPair *message,
                  void *closure_data);
typedef void (*ExtMountMap_Closure)
                 (const ExtMountMap *message,
                  void *closure_data);
typedef void (*JoinNamespace_Closure)
                 (const JoinNamespace *message,
                  void *closure_data);
typedef void (*InheritFd_Closure)
                 (const InheritFd *message,
                  void *closure_data);
typedef void (*CgroupRoot_Closure)
                 (const CgroupRoot *message,
                  void *closure_data);
typedef void (*UnixSk_Closure)
                 (const UnixSk *message,
                  void *closure_data);
typedef void (*CriuOpts_Closure)
                 (const CriuOpts *message,
                  void *closure_data);
typedef void (*CriuDumpResp_Closure)
                 (const CriuDumpResp *message,
                  void *closure_data);
typedef void (*CriuRestoreResp_Closure)
                 (const CriuRestoreResp *message,
                  void *closure_data);
typedef void (*CriuNotify_Closure)
                 (const CriuNotify *message,
                  void *closure_data);
typedef void (*CriuFeatures_Closure)
                 (const CriuFeatures *message,
                  void *closure_data);
typedef void (*CriuReq_Closure)
                 (const CriuReq *message,
                  void *closure_data);
typedef void (*CriuResp_Closure)
                 (const CriuResp *message,
                  void *closure_data);
typedef void (*CriuVersion_Closure)
                 (const CriuVersion *message,
                  void *closure_data);

/* --- services --- */


/* --- descriptors --- */

extern const ProtobufCEnumDescriptor    criu_cg_mode__descriptor;
extern const ProtobufCEnumDescriptor    criu_network_lock_method__descriptor;
extern const ProtobufCEnumDescriptor    criu_pre_dump_mode__descriptor;
extern const ProtobufCEnumDescriptor    criu_req_type__descriptor;
extern const ProtobufCMessageDescriptor criu_page_server_info__descriptor;
extern const ProtobufCMessageDescriptor criu_veth_pair__descriptor;
extern const ProtobufCMessageDescriptor ext_mount_map__descriptor;
extern const ProtobufCMessageDescriptor join_namespace__descriptor;
extern const ProtobufCMessageDescriptor inherit_fd__descriptor;
extern const ProtobufCMessageDescriptor cgroup_root__descriptor;
extern const ProtobufCMessageDescriptor unix_sk__descriptor;
extern const ProtobufCMessageDescriptor criu_opts__descriptor;
extern const ProtobufCMessageDescriptor criu_dump_resp__descriptor;
extern const ProtobufCMessageDescriptor criu_restore_resp__descriptor;
extern const ProtobufCMessageDescriptor criu_notify__descriptor;
extern const ProtobufCMessageDescriptor criu_features__descriptor;
extern const ProtobufCMessageDescriptor criu_req__descriptor;
extern const ProtobufCMessageDescriptor criu_resp__descriptor;
extern const ProtobufCMessageDescriptor criu_version__descriptor;

PROTOBUF_C__END_DECLS


#endif  /* PROTOBUF_C_rpc_2eproto__INCLUDED */
