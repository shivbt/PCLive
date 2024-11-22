/*##############################################################################
*                                                                              #
#   Description: This is used to perform iterative migration with parallel     #
#                restore. This should be running at the destination machine    #
#                to accpet migration request from various machine.             #
#                                                                              #
#   Assumptions: This program expect following assumption:                     #
#                   1. The NFS container directory is mounted at dst machine   #
#                   2. The received dumped image willnot be saved anywhere     #
#                                                                              #
#   Author:      Shiv Bhushan Tripathi                                         #
#                                                                              *
##############################################################################*/


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "migration.h"
#define BACKLOG                     10
#define MAX_DIGITS_IN_PORT          10
#define MAX_DIGITS_IN_MIG_ITER      3
#define XFER_PORT_START             10000
#define PS_LOG_FILE_NAME            "ps_debug"


long int ps_port_global = XFER_PORT_START;


// TODO: This function is Not completed
//
// This function prepares arguments to be passed to the page server script and
// call execlp to execute the script.
void executePageServerScript (struct msg_mig_agent_req *agent_req
        , char *workspace, long int ps_port) {

    // char ps_script_path [MAX_ABS_PATH_LEN];
    char ps_dir_path [MAX_ABS_PATH_LEN];
    char ps_log_file_path [MAX_ABS_PATH_LEN];
    char port_number [MAX_DIGITS_IN_PORT];
    char current_mig_iter [MAX_DIGITS_IN_MIG_ITER];

    // Cleaning...
    // memset (ps_script_path, '\0', sizeof (ps_script_path));
    memset (ps_dir_path, '\0', sizeof (ps_dir_path));
    memset (ps_log_file_path, '\0', sizeof (ps_log_file_path));
    memset (port_number, '\0', sizeof (port_number));
    memset (current_mig_iter, '\0', sizeof (current_mig_iter));
    
    // Now call execlp.
    //execlp ("criu", "criu", "page-server", "-D", ps_dir_path, "-o"
    //        , ps_log_file_path, "-v4", "--port", port_number, "--auto-dedup"
    //        , NULL);

}

// Function to start xfer server which is resposible for getting dumped images
// from the client (source machine).
long int startXferServer (struct msg_mig_agent_req *agent_req
        , char *agent_ip_addr, char *workspace, long int ps_port) {

    int pid;
    long int port = ps_port; 

    // Use fork-exec model to start the page-server script and wait for child
    // to finish, i.e. wait for page transfer to finish.
    /*pid = fork();
    if (pid < 0) {

        printf ("\t: Forking a child to start page-server is failed!!!\n");
        return -1;

    } else if (pid == 0) {
    
        // Now execute the page server script.
        // 
        // TODO:
        // Return the status of page-server to the parent process using pipe or
        // any other construct.
        //
        executeXferCommand (agent_req, workspace, ps_port);
        printf ("\t: This should not be printed while executing page server script!!!");
        exit (-1);

    }*/

    // Now return the port.
    return port;

}

// Function to send response to the connected client.
void sendResponse (int client_sock, long int port) {

    struct msg_mig_agent_res agent_res;

    // Send port number and request success indicator to the client.
    memset (&agent_res, '\0', sizeof (agent_res));
    agent_res.is_success = (port < 0) ? 0 : 1;
    agent_res.port = port;
    if (send (client_sock, &agent_res, sizeof (agent_res), 0) < 0) {
        
        // Debug msg.
        printf ("\t: Problem while sending response to the client!!!\n");
        
        // Close the sockets.
        close (client_sock);

    }

}

// Function to perform commuication between migration server and client agents.
void communicate (int client_sock, char *agent_ip_addr, char *workspace) {

    struct msg_mig_agent_req agent_req;
    long int port;

    // Get the request packet from the incoming client connection.
    memset (&agent_req, '\0', sizeof (agent_req));
    if (recv (client_sock, &agent_req, sizeof (agent_req), 0) < 0) {
        
        // Debug msg.
        printf ("\t: Problem while receiving req packet from the client!!!\n");
        
        // Close the socket.
        close (client_sock);

    }
    printf ("\t: --- Migration Configs: \n");
    printf ("\t\t: container_name: %s\n", agent_req.container_name);
    printf ("\t\t: iterations: %d\n", agent_req.iterations);
    printf ("\t\t: prestore: %d\n", agent_req.prestore);
    printf ("\t\t: nfs_host_ip: %s\n", agent_req.nfs_host_ip);
    printf ("\t\t: nfs_host_container_dir: %s\n", agent_req.nfs_host_container_dir);
    printf ("\t\t: Page Server dir: %s\n", agent_req.ps_dir);

    // Start xfer server.
    port = startXferServer (&agent_req, agent_ip_addr, workspace, ps_port_global);
    ps_port_global = (port < 0) ? ps_port_global : (ps_port_global + 2);

    // Now send the response to the client.
    sendResponse (client_sock, port);

}

// Function which accept incoming connections and perform communications.
void acceptConnections (int server_sock, char *workspace) {

    int client_sock, client_size;
    struct sockaddr_in client_address;

    // Keep accepting connections infinitely.
    while (1) {

        // Accept the incoming connection and handle any error.
        client_size = sizeof (client_address);
        client_sock = accept (server_sock, (struct sockaddr *)&client_address, &client_size);
        if (client_sock < 0) {
            printf ("Accepting the connection is failed!!!\n");
            exit (-1);
        }
        printf("Client connected with IP: %s and Port: %i\n", inet_ntoa(client_address.sin_addr), ntohs(client_address.sin_port));

        // Now perform communications.
        communicate (client_sock, inet_ntoa(client_address.sin_addr), workspace);

        // Close the client connection.
        close (client_sock);

    }

}


int main (int argc, char **argv) {

    struct sockaddr_in server_address;
    int server_sock;
    long int port;

    // Get port and server IP from the command line.
    // First argument is IP and second one is port.
    if (argc < 4) {
        printf ("You must provide IP, port and workspace (absolute path with ending /) for the server agent!!!");
        return -1;
    }
    port = atol (argv[2]);
    printf ("IP: %s, Port: %ld\n", argv[1], port);

    // Clear sockaddr_in struct.
    memset (&server_address, '\0', sizeof (server_address));
    
    // Create socket and handle any error.
    server_sock = socket (AF_INET, SOCK_STREAM, 0);
    if (server_sock < 0) {

        printf ("Socket creation is failed!!!\n");
        return -1;

    }

    // Set port and IP for the server.
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons (port);
    server_address.sin_addr.s_addr = inet_addr (argv[1]);
    
    // Bind newly created socket to given server config.
    if ((bind (server_sock, (struct sockaddr *)&server_address, sizeof (server_address))) != 0) {
        printf("Socket binding is failed!!!\n");
        exit(-1);
    }

    // Now listen to incoming connections...
    if ((listen (server_sock, BACKLOG)) != 0) {
        printf ("Listening for incoming connection is failed!!!\n");
        exit (-1);
    }

    // Accept incoming connections and start communications.
    acceptConnections (server_sock, argv[3]);

    // Close the socket.
    close (server_sock);
    
    return 0;

}
