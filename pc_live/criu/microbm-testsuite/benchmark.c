#include"common.h"

static struct process *plist = NULL; 

static void create_tmpfs_file_handle(char *name)
{
  int size;
  int fd = open(name, O_RDWR|O_CREAT, 0666);
  assert(fd >= 0);
  size = MAX_PROCESS*sizeof(struct process);
  size = ((size >> 12) + 1) << 12;
  assert(ftruncate(fd, size) == 0);
  if((plist = mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0)) == MAP_FAILED){
         perror("mmap");
         exit(-1);
  }
  close(fd);
  bzero(plist, size);
  // Lets create information about ourselves
  plist->status = STATUS_USED;
  plist->pid = getpid();
  plist->ppid = getppid();
  return;
}


static void prep_process_info(struct response *rsp)
{
  struct process *p = plist;
  for(int i=0; i<MAX_PROCESS; ++i, p++)
        if(p->status == STATUS_USED)
            rsp->size += sprintf(rsp->args + rsp->size, "pid: %d ppid: %d\n", p->pid, p->ppid);
  return;
}

static void prep_thread_info(struct process *p, struct response *rsp)
{
   struct thread *th = &p->threads[0];
   for(int i=0; i<MAX_THREADS_PROCESS; ++i, th++)
        if(th->status == STATUS_USED)
              rsp->size += sprintf(rsp->args + rsp->size, "tid: %ld ppid: %d\n", th->tid, th->parent_pid);
  return;
}

static void prep_file_info(struct process *p, struct response *rsp)
{
   struct file *f = &p->files[0];
   for(int i=0; i<MAX_FILES_PROCESS; ++i, f++)
        if(f->status == STATUS_USED)
              rsp->size += sprintf(rsp->args + rsp->size, "fd: %d\n", f->fd);
  return;
}

static void prep_mem_info(struct process *p, struct response *rsp)
{
   struct memory *m = &p->mem_areas[0];
   for(int i=0; i<MAX_MEM_PROCESS; ++i, m++)
        if(m->status == STATUS_USED)
              rsp->size += sprintf(rsp->args + rsp->size, "mid: %d start: %p size: 0x%lx\n", m->mid, m->start, m->size);
  return;
}
static int do_fork(struct response *rsp)
{
  int pid = fork();
  if(pid < 0){
          rsp->status = CMD_ERR;
          return -1;
  }
  if(!pid)
        child_main(plist);
  else
        rsp->rsp_id = pid;
  return 0;
}
static int handle_command(struct command *cmd, struct response *rsp)
{
  bool wait_response = false;
  struct process *p;

  if(cmd->command != CMD_INFO_PROCESS && cmd->command != CMD_CREATE_PROCESS){
        p = find_process_by_id(plist, cmd->id_1);
        if(!p)
               goto err_rsp;
        bzero((void *)(&p->todo), sizeof(struct internal_command));
  }
  switch(cmd->command){
     // First the info commands
     case CMD_INFO_PROCESS:
                             prep_process_info(rsp);
                             break;
     case CMD_INFO_THREADS:
                             prep_thread_info(p, rsp);
                             break;   
     case CMD_INFO_FILES:
                             prep_file_info(p, rsp);
                             break;
     case CMD_INFO_MEM:
                             prep_mem_info(p, rsp);
                             break;
     // Now the actions!
     case CMD_CREATE_PROCESS:
                             if(!find_unused_process(plist)) 
                                  goto err_rsp;
                             do_fork(rsp);
                             break;
     case CMD_KILL_PROCESS:
                             p->todo.cmd = IC_EXIT; //send internal command to the child process
                             wait_response = true;
                             break;
     // specialized actions
     case CMD_OPEN_FILE:
                             p->todo.cmd = IC_OPEN_FILE; 
                             wait_response = true;
                             break;
     case CMD_CLOSE_FILE:
                             p->todo.id = cmd->id_2;
                             p->todo.cmd = IC_CLOSE_FILE;
                             wait_response = true;
                             break;
     case CMD_OP_FILE:
                             p->todo.id = cmd->id_2;
                             p->todo.pages = cmd->pages;
                             wait_response = true;
                             
                             switch(cmd->operation){
                                  case OP_READ:
                                                 p->todo.cmd = IC_READ_FILE;
                                                 break;
                                  case OP_WRITE:
                                                 p->todo.cmd = IC_WRITE_FILE;
                                                 break;
                                  case OP_SEEK:
                                                 p->todo.cmd = IC_SEEK_FILE;
                                                 break;
                                  default: 
                                       goto err_rsp;
                                        
                             }        
                            break;
     case CMD_MALLOC:
                            p->todo.pages = cmd->pages;
                            p->todo.cmd = IC_MMAP_MEM;
                            wait_response = true;
                            break;
     case CMD_MFREE:
                            p->todo.id = cmd->id_2;
                            p->todo.cmd = IC_UNMAP_MEM;
                            wait_response = true;
                            break;
     case CMD_MOP:
                             p->todo.id = cmd->id_2;
                             p->todo.pages = cmd->pages;
                             wait_response = true;
                             
                             switch(cmd->operation){
                                  case OP_READ:
                                                 p->todo.cmd = IC_READ_MEM;
                                                 break;
                                  case OP_WRITE:
                                                 p->todo.cmd = IC_WRITE_MEM;
                                                 break;
                                  default: 
                                       goto err_rsp;
                                        
                             }    
                             break;    
     case CMD_THREAD_CREATE:
                            p->todo.cmd=IC_CREATE_THREAD;
                            wait_response = true;
                            break;
     case CMD_THREAD_DESTROY:
                           p->todo.id = cmd->id_2;
                           p->todo.cmd = IC_DELETE_THREAD;
                           wait_response = true;
                           break;
                             
     default:
                      goto err_rsp;
    }   
    while(wait_response){
           assert(p);
           if(p->pid == getpid()){
              if(cmd->command == CMD_KILL_PROCESS)
                   kill_all_child(plist);
              p->todo.response = handle_process_command(p);        
           }else if(cmd->command == CMD_KILL_PROCESS){
              int status;
              waitpid(p->pid, &status, 0);  
           }
           if(!p->todo.response){
               usleep(100);
           }else if(p->todo.response == IC_RESPONSE_ERR){
               rsp->status = CMD_ERR;
               rsp->size = 0;
               wait_response = false;
           }else{
               rsp->rsp_id = p->todo.response; 
               wait_response = false;
           } 
               
    } 
    return rsp->status; 
err_rsp:
           rsp->status = CMD_ERR;
           rsp->size = 0;
           return -1; 
}
static int bind_unix_domain(void)
{
    int ret;
    int sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un sun;
    assert(sockfd >= 0);
    if(!access(UNIX_SOCK_PATH, F_OK)) 
         assert(!unlink(UNIX_SOCK_PATH));
    sun.sun_family = AF_UNIX;
    ret = snprintf(sun.sun_path, sizeof(sun.sun_path), "%s",
                   UNIX_SOCK_PATH);
    assert(ret == strlen(UNIX_SOCK_PATH));

    assert(bind(sockfd, (struct sockaddr *)&sun, sizeof(sun)) == 0);

    assert(listen(sockfd, 5) == 0);
    return sockfd;
}

static void wait_and_handle_a_request(int sockfd)
{
  char buf[8192];  //current response can not be larger than 8192
  struct response *rsp = (struct response*) buf;
  struct command cmd; 
  struct sockaddr_un sun;
  socklen_t unaddr_len = sizeof(sun);
  int dfd = accept(sockfd, (struct sockaddr *)&sun, &unaddr_len);
  assert(dfd >= 0);
  if(recv(dfd, (void*) &cmd, sizeof(struct command), MSG_WAITALL) < sizeof(struct command)){
       perror("recv");
       close(dfd);
       return;
  }
  memset(buf, 0, 8192);
  handle_command(&cmd, rsp);
  if(send(dfd, (const void *)rsp, sizeof(struct response) + rsp->size, 0) < 0)
      perror("send");
  close(dfd);
  return;
}

int main()
{
   int sockfd;
   create_tmpfs_file_handle("/tmp/somefile");
   sockfd = bind_unix_domain(); 
   while(true){
        wait_and_handle_a_request(sockfd);
   }   
   return 0;
}
