#include "common.h"

void usage(char *command)
{
 printf("Usage: %s <--list |-l|--action|-a> [OPTIONS]\n", command);
 printf("OPTIONS\n");
 printf("-P\n");
 printf("\t with --list or -l, lists all processes. No arguments necessary\n");
 printf("\t with --action or -a, the followig actions are allowed.\n");
 printf("\t <-c> Create a process\n");
 printf("\t <-d> Kill a process, Must provide -p option specifying the pid, see below\n");
 
 printf("-F\n");
 printf("\t with --list or -l, lists all files opened by the process. The pid must be provided with -p argument\n");
 printf("\t with --action or -a, the followig actions are allowed.\n");
 printf("\t <-c> Open a file for a process specified with -p option\n");
 printf("\t <-d> Close the file (fd specified by -i) opened by a process (specified with -p)\n");
 printf("\t Must provide -p and -i option specifying the pid and fd, respectively\n");
 printf("\t <-w> Writes pages (specified by -s) to a file (fd specified by -i) for a process specified with -p option\n");
 printf("\t Must provide -p, -i, -s option specifying the pid, fd and pages, respectively\n");
 printf("\t <-r> Reads pages (specified by -s) from a file (fd specified by -i) for a process specified with -p option\n");
 printf("\t Must provide -p, -i, -s option specifying the pid, fd and pages, respectively\n");
 printf("\t <-k> Seeks to a file offset (specified by -s) for a process specified with -p option\n");
 printf("\t Must provide -p, -i, -s option specifying the pid, fd and pages, respectively\n");
 printf("\t Note: for read, write and seek, the size or offset is specified by -s option in pages.\n");
 printf("\n");
 
 printf("-T\n");
 printf("\t with --list or -l, lists all threads active in the process. The pid must be provided with -p argument\n");
 printf("\t with --action or -a, the followig actions are allowed.\n");
 printf("\t <-c> Create a thread within a process specified with -p option\n");
 printf("\t <-d> Terminate the thread (tid specified by -i) opened by a process (specified with -p)\n");
 printf("\t Must provide -p and -i option specifying the pid and tid, respectively\n");
 printf("\n");

 printf("-M\n");
 printf("\t with --list or -l, lists all memory areas mapped by the process. The pid must be provided with -p argument\n");
 printf("\t with --action or -a, the followig actions are allowed.\n");
 printf("\t <-c> Create a memory map within a process specified with -p option.\n"); 
 printf("\t Size of the mapping (in pages) must be provided with -s option \n");
 printf("\t <-d> Unmap the memory map (mapid specified by -i) created by a process (specified with -p)\n");
 printf("\t Must provide -p and -i option specifying the pid and mapid, respectively\n");
 printf("\t <-w> Writes pages (specified by -s) to the start of memory (mapid specified by -i) for process specified with -p option\n");
 printf("\t Must provide -p, -i, -s option specifying the pid, mapid and pages, respectively\n");
 printf("\t <-r> Reads pages (specified by -s) from the start of memory (mapid specified by -i) for process specified with -p option\n");
 printf("\t Must provide -p, -i, -s option specifying the pid, fd and pages, respectively\n");
 printf("\t Note: for read and write, the size is specified by -s option in pages. Operations performed at the starting address\n");
 printf("\n");

 printf("-p <pid>\n");
 printf("\t Specify the PID of the process for which the action is performed\n");
 printf("\n");
 
 printf("-i <id>\n");
 printf("\t Specify the ID of the construct (file, memory or thread)on which the action is performed\n");
 printf("\n");
 
 printf("-s <pages>\n");
 printf("\t Specify the size in pages for memory and file operations\n");
 printf("\n");
}

int parse_args(int argc, char **argv, struct command *cmd)
{
   bool listing = false, action=false;
   bool create = false, destroy=false, read=false, write=false, seek=false;
   char *exe = *argv;
   argv++;
   argc--;
   if(argc <= 0)
       return -1;
   if(!strcmp(*argv, "--list") || !strcmp(*argv, "-l"))
       listing = true; 
   else if(!strcmp(*argv, "--action") || !strcmp(*argv, "-a"))
       action = true;
   else if(!strcmp(*argv, "--help") || !strcmp(*argv, "-h")){
       usage(exe); 
       return 0;
   }
   else
        return -1;
   memset(cmd, 0, sizeof(struct command));
    
   argv++;
   argc--;

   while(argc > 0){
         char *ptr = *argv;
         if(ptr[0] != '-')
             return -1;
         switch(ptr[1]){
             case 'F'://file
                       cmd->command = CMD_INFO_FILES; //For the time being  
                       break;
             case 'T':      // thread
                       cmd->command = CMD_INFO_THREADS; //For the time being 
                       break;
 
             case 'M':      // memory
                       cmd->command = CMD_INFO_MEM; //For the time being 
                       break;

             case 'P':      // process           
                       cmd->command = CMD_INFO_PROCESS; //For the time being 
                       break;
             
             case 'p':  //This is the pid
                       argv++;
                       argc--;
                       cmd->id_1 = atol(*argv);
                       break;
             case 's':  //This is the size, valid for memory and file only
                       argv++;
                       argc--;
                       cmd->pages = atoi(*argv);
                       break;
             case 'c': // This is the create action (create process, open file etc.)
                       create=true;
                       break;
             case 'd':  // This is the destroy action (kill process, thread, close file etc.)
                       destroy=true;
                       break;
             case 'r':
                       read=true;
                       break;
             case 'w':
                       write=true;
                       break;
             case 'k':
                       seek=true;
                       break;
             case 'i':  // The secondary ID (fd, mid, tid etc.)
                       argv++;
                       argc--;
                       cmd->id_2 = atol(*argv);
                       break;
             default:
                      return -1;
         }       
         argv++; 
         argc--;
   }
   // Now we have collected all information. Let us apply rules and finalize commands
  
   if(!listing && ((create + destroy + read + write + seek) != true)) 
          return -1;
   switch(cmd->command){
       case CMD_INFO_PROCESS:
              if(listing){
                  if(cmd->pages | cmd->id_1 | cmd->id_2)
                       return -1;
              }else{
                  if(read || write || seek)
                         return -1;
                  if(create && (cmd->pages | cmd->id_1 | cmd->id_2))
                        return -1;
                  if(create){
                         cmd->command = CMD_CREATE_PROCESS;
                  }else{
                         if(!cmd->id_1 || (cmd->pages | cmd->id_2))
                            return -1;
                         cmd->command = CMD_KILL_PROCESS;
                  }
                }
                break;
          case CMD_INFO_FILES:
              if(!cmd->id_1)
                     return -1;
              if(listing){
                      if(cmd->id_2)
                           return -1;
              }else{
                      if(create){ 
                            if(cmd->id_2)
                                 return -1;
                             cmd->command=CMD_OPEN_FILE;
                      }
                      if(destroy){
                             if(!cmd->id_2)
                                     return -1;
                             cmd->command=CMD_CLOSE_FILE;
                      }
                      if(read || write || seek){
                              if(!cmd->id_2 || !cmd->pages)
                                    return -1;
                              cmd->command = CMD_OP_FILE;
                              if(read)
                                     cmd->operation = OP_READ;
                              if(write)
                                      cmd->operation = OP_WRITE;
                              if(seek)
                                      cmd->operation = OP_SEEK;     
                      } 
              }  
              break;
          case CMD_INFO_THREADS:
              if(!cmd->id_1 || cmd->pages)
                     return -1;
              if(listing){
                      if(cmd->id_2)
                           return -1;
              }else{
                      if(read || write || seek)
                         return -1;
                      if(create){ 
                            if(cmd->id_2)
                                 return -1;
                             cmd->command=CMD_THREAD_CREATE;
                      }
                      if(destroy){
                             if(!cmd->id_2)
                                     return -1;
                             cmd->command=CMD_THREAD_DESTROY;
                      }
              }  
              break;
          case CMD_INFO_MEM:
              if(!cmd->id_1)
                     return -1;
              if(listing){
                      if(cmd->id_2 | cmd->pages)
                           return -1;
              }else{
                      if(seek)
                           return -1;
                      if(create){ 
                            if(cmd->id_2 || cmd->pages <= 0)
                                 return -1;
                             cmd->command=CMD_MALLOC;
                      }
                      if(destroy){
                             if(!cmd->id_2 || cmd->pages)
                                     return -1;
                             cmd->command=CMD_MFREE;
                      }
                      if(read || write){
                              if(!cmd->id_2 || !cmd->pages)
                                    return -1;
                              cmd->command = CMD_MOP;
                              if(read)
                                     cmd->operation = OP_READ;
                              if(write)
                                      cmd->operation = OP_WRITE;
                      } 
                     
              }  
              break;
         default:
                 return -1;
             
   }
   return 1;  //success
}
long fire_a_command(struct command *cmd)
{
  int ret;
  int sockfd;
  struct sockaddr_un sun;
  char buf[8192];
  struct response *rsp = (struct response*)buf;
  bzero(buf, 8192);
  sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (sockfd < 0) {
         perror("socket");
         exit(-1);
  }
  sun.sun_family = AF_UNIX;
  ret = snprintf(sun.sun_path, sizeof(sun.sun_path), "%s",
                   UNIX_SOCK_PATH);
  assert(ret == strlen(UNIX_SOCK_PATH));

  if (connect(sockfd, (struct sockaddr *) &sun, sizeof(struct sockaddr_un)) < 0) {
          perror("connect");
          exit(-1);
  }
  
  if(send(sockfd, (const void *)cmd, sizeof(struct command), 0) < 0){
       perror("send");
       exit(-1);     
  }
  if(recv(sockfd, rsp, sizeof(struct response), MSG_WAITALL) < sizeof(struct response)){
      perror("recv");
      exit(-1);
  }  
  printf("Response status: %d size: %d rsp_id: %ld\n", rsp->status, rsp->size, rsp->rsp_id);
  if(rsp->size){
         if(recv(sockfd, rsp->args, rsp->size, MSG_WAITALL) < rsp->size){
             printf("Error getting details\n");
             exit(-1);
         }
   printf("%s", rsp->args); 
  }
  close(sockfd); 
  return rsp->rsp_id;
}
int main(int argc, char **argv)
{
   struct command cmd;
   int retval = parse_args(argc, argv, &cmd);
   if(retval < 0){
          printf("Invalid command\n");
          usage(*argv);
          exit(-1);
   }    
   if(retval)
         fire_a_command(&cmd);
   return 0;
}
