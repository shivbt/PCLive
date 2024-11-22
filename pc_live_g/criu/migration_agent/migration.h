#ifndef __MIGRATION_H_
#define __MIGRATION_H_

#define MAX_ABS_PATH_LEN        512
#define MAX_CONT_NAME_LEN       32
#define MAX_PS_DIR_NAME_LEN     32
#define MAX_WORK_DIR_NAME_LEN   32
#define MAX_IPV4_LEN            16

// Macros for parameter and value for the given config file.
#define MAX_PARAMETER_LEN       64
#define MAX_VALUE_LEN           512                 // XXX: This must be same as MAX_ABS_PATH_LEN macro
#define PARAM_CONT_NAME         "container_name"
#define PARAM_ITER              "iterations"
#define PARAM_P_RESTORE         "parallel_restore"
#define PARAM_DST_IP            "dst_ip"
#define PARAM_DST_SERVER_PORT   "dst_server_port"
#define PARAM_NFS_HOST_CONT_DIR "nfs_host_container_dir"
#define PARAM_CONT_WORK_DIR     "container_work_dir"
#define PARAM_PS_DIR            "page_server_dir"


// Request and response message struct between server and client application
// of migration agent
struct msg_mig_agent_req {

    char container_name [MAX_CONT_NAME_LEN];        // Name of the container.
    int iterations;                                 // Number of iterations in iterative migration.
    int prestore;                                   // Restore parallely while migrating.
    char nfs_host_container_dir [MAX_ABS_PATH_LEN]; // Container directory name at the NFS host machine.
    char ps_dir [MAX_PS_DIR_NAME_LEN];              // Page server dir name at Destination and Source.

};
struct msg_mig_agent_res {

    int is_success;                                 // Indicate whether request can be served.
    long int port;                                  // This port should be used to service the request.

};

// Configuration structure for the migration.
struct migration_config {

    char container_name [MAX_CONT_NAME_LEN];        // Name of the container.
    int iterations;                                 // Number of iterations in iterative migration.
    int prestore;                                   // Restore parallely while migrating.
    char dst_ip [MAX_IPV4_LEN];                     // Destination machine IP.
    int dst_server_port;                            // Migration agent Server port at destination.
    char nfs_host_container_dir [MAX_ABS_PATH_LEN]; // Container directory name at the NFS host machine.
    char container_work_dir [MAX_ABS_PATH_LEN];     // Working directory at source machine to save info during migration.
    char ps_dir [MAX_PS_DIR_NAME_LEN];              // Page server dir name at Destination and Source.

};

#endif
