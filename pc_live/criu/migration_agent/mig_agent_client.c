#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "migration.h"


// Function to set/ fill fields of the migration_config structure.
// If success, return 0 otherwise return non-zero number.
int setParamValue (struct migration_config *mig_config
        , char *parameter, char *value) {

    int error = 0;

    // Fill the fields.
    if (!strcmp (parameter, PARAM_CONT_NAME)) {
        strcpy (mig_config -> container_name, value);
    } else if (!strcmp (parameter, PARAM_ITER)) {
        mig_config -> iterations = atoi (value);
    } else if (!strcmp (parameter, PARAM_P_RESTORE)) {
        mig_config -> prestore = atoi (value);
    } else if (!strcmp (parameter, PARAM_DST_IP)) {
        strcpy (mig_config -> dst_ip, value);
    } else if (!strcmp (parameter, PARAM_DST_SERVER_PORT)) {
        mig_config -> dst_server_port = atoi (value);
    } else if (!strcmp (parameter, PARAM_NFS_HOST_CONT_DIR)) {
        strcpy (mig_config -> nfs_host_container_dir, value);
    } else if (!strcmp (parameter, PARAM_CONT_WORK_DIR)) {
        strcpy (mig_config -> container_work_dir, value);
    } else if (!strcmp (parameter, PARAM_PS_DIR)) {
        strcpy (mig_config -> ps_dir, value);
    } else {
        // Here the given parameter in the config file is not valid, so reflect
        // with the error value.
        error = 1;
    }

    // Return error, if any.
    return error;

}

// Function to prepare migration_config structure by parsing the values from
// the given config file.
// If success, return 0 otherwise return non-zero number.
int prepareMigConfig (char *config_file, struct migration_config *mig_config) {

    int error = 0;
    int line_number = 1;
    FILE *fptr;
    char parameter [MAX_PARAMETER_LEN];
    char value [MAX_VALUE_LEN];

    // Open config file and handle any error.
    fptr = fopen(config_file, "r");
    if (fptr == NULL) {
        printf ("Error while opening config file.\n");
        return 1;
    }

    // Read file till the end and set it into the migration_config structure.
    while (fscanf (fptr, "%s %s", parameter, value) == 2) {

        // Set value of the parameter in the migration_config structure.
        // Handle any error while setting.
        error = setParamValue (mig_config, parameter, value);
        if (error) {
            printf ("Parameter at line no %d in config file %s is not valid.\n"
                    , line_number, config_file);
            break;
        }

        line_number++;

    }

    // Close the file.
    fclose (fptr);

    // Return error, if any.
    return error;

}

// Function to prepare migration request structure by getting this data from
// the migration config structure.
void prepareMigRequest (struct msg_mig_agent_req *agent_req
        , struct migration_config *mig_config) {

    // Prepare the migration request structure.
    strcpy (agent_req -> container_name, mig_config -> container_name);
    agent_req -> iterations = mig_config -> iterations;
    agent_req -> prestore = mig_config -> prestore;
    strcpy (agent_req -> nfs_host_container_dir, mig_config -> nfs_host_container_dir);
    strcpy (agent_req -> ps_dir, mig_config -> ps_dir);

}

// Function to start the migration with the given migration config structure
// and migration server agent response.
void startMigration (struct migration_config *mig_config
        , struct msg_mig_agent_res *agent_res) {

    printf ("Going to start migration...\n");

}

// Function to communicate between migration server anmd client agents.
void communicate (int sock_fd, struct migration_config *mig_config) {

    struct msg_mig_agent_req agent_req;
    struct msg_mig_agent_res agent_res;

    // Cleaning...
    memset (&agent_req, '\0', sizeof (agent_req));
    memset (&agent_res, '\0', sizeof (agent_res));
    
    // Prepare request structure and send it to the migration server agent.
    prepareMigRequest (&agent_req, mig_config);
    if (send (sock_fd, &agent_req, sizeof (agent_req), 0) < 0) {
        printf ("Some problem while sending migration request!!!\n");
        exit (-1);
    }

    // Now get the server response.
    if (recv (sock_fd, &agent_res, sizeof (agent_res), 0) < 0) {
        printf ("Some problem while receiving response from server!!!\n");
        exit (-1);
    }

    // Check for successfull response.
    if (agent_res.is_success == 1) {

        printf ("Migration of images can be started with %ld port number :)\n"
                , agent_res.port);

        // Now start the migration.
        startMigration (mig_config, &agent_res);

    } else {
        printf ("Response: Migration of images can not be started :(\n");
    }

}

int main (int argc, char **argv) {

    struct sockaddr_in server_address;
    int sock_fd;
    long int port;
    struct migration_config mig_config;
    int error = 0;

    // You must get config file from the command line.
    if (argc < 2) {
        printf ("You must provide config file for the migration!!!");
        return -1;
    }

    // Prepare migration configuration structure from the config file and
    // handle error while preparing, if any.
    //
    // Config file will be strictly like:
    //      PARAMETER_1 VALUE_1
    //      PARAMETER_2 VALUE_2
    //
    error = prepareMigConfig (argv[1], &mig_config);
    if (error) {
        printf ("Error: %s\n", argv[1]);
        return -1;
    }

    // Clear sockaddr_in struct.
    memset (&server_address, '\0', sizeof (server_address));
    
    // Create socket and handle any error.
    sock_fd = socket (AF_INET, SOCK_STREAM, 0);
    if (sock_fd < 0) {
        printf ("Socket creation failed!!!\n");
        return -1;
    }

    // Set port and IP for the server.
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons (mig_config.dst_server_port);
    server_address.sin_addr.s_addr = inet_addr (mig_config.dst_ip);
    
    // Try to connect with server agent.
    if (connect (sock_fd, (struct sockaddr *)&server_address, sizeof (server_address)) < 0) {
        printf ("Connection error!!!\n");
        exit (-1);
    }

    // Now communicate with the server.
    communicate (sock_fd, &mig_config);

    // Close the socket.
    close (sock_fd);
    
    // Simple return.
    return 0;

}
