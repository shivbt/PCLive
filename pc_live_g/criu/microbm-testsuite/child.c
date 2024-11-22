#include"common.h"

static int open_one_file(struct process *p)
{
  char filename[16]; 
  struct file *nf = find_unused_file(p);
  if(!nf)
         return -1;
  sprintf(filename, "bmfile-%d%d.txt", p->pos, nf->pos);
  nf->fd = open(filename, O_RDWR|O_CREAT, 0666);
  if(nf->fd < 0){
     return -1;     
  }
  nf->status = STATUS_USED;
  return nf->fd;
}

static int close_file(struct process *p, int fd)
{
    struct file *nf = find_file_by_fd(p, fd);
    if(!nf || nf->fd < 0)
        return -1;
    close(nf->fd);
    bzero(nf, sizeof(struct file));
    return fd;
}
static long do_file_seek(struct process *p, volatile struct internal_command *cmd)
{
    struct file *nf = find_file_by_fd(p, cmd->id);
    if(!nf || nf->fd < 0)
        return -1;
    return lseek(nf->fd, cmd->pages << PAGE_SHIFT, SEEK_SET);
} 

static long do_file_rw(struct process *p, volatile struct internal_command *cmd)
{
    char buf[PAGE_SIZE];
    long retval = 0;
    bool is_write = (cmd->cmd == IC_WRITE_FILE); 
    struct file *nf = find_file_by_fd(p, cmd->id);
    if(!nf || nf->fd < 0)
        return -1;
    for(int i=0; i<cmd->pages; ++i){
       if(is_write){
            memset(buf, 'a' + rand()% 26, PAGE_SIZE);
            retval += write(nf->fd, buf, PAGE_SIZE);
       }else{
            retval += read(nf->fd, buf, PAGE_SIZE);
       }
    }      
    return retval;          
}

static int do_mmap(struct process *p, int pages)
{
   struct memory *m = find_unused_memory(p);
   if(!m)
        return -1;
   m->mid = m->pos + 1;
   m->size = pages << PAGE_SHIFT;
   m->start = mmap(NULL, m->size, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);   
   if(m->start == MAP_FAILED)
         return -1;
   m->status = STATUS_USED;
   return m->mid;
}

static int do_unmap(struct process *p, int id)
{
   struct memory *m = find_mem_by_id(p, id);
   if(!m)
        return -1;
   munmap(m->start, m->size);
   bzero(m, sizeof(struct memory));
   return id;
}

static long do_mem_rw(struct process *p, volatile struct internal_command *cmd)
{
    char *ptr;
    long size = cmd->pages << PAGE_SHIFT;
    char buf[PAGE_SIZE];
    bool is_write = (cmd->cmd == IC_WRITE_MEM); 
    struct memory *m = find_mem_by_id(p, cmd->id);
    if(!m || m->size < size)
        return -1;
    ptr = m->start;
    for(int i=0; i<cmd->pages; ++i){
       if(is_write){
            memset(buf, 'a' + rand()% 26, PAGE_SIZE);
            memcpy(ptr, buf, PAGE_SIZE);
       }else{
            memcpy(buf, ptr, PAGE_SIZE);
       }
       ptr += PAGE_SIZE;
    }      
    return size;          
}

static void *thfunc_dummy(void *arg)
{
  while(1){
         usleep(CHILD_SLEEP_USEC);
  }
  return NULL;
}
static long do_create_thread(struct process *p)
{
   struct thread *th = find_unused_thread(p);
   if(!th)
          return -1;
   th->parent_pid = getpid();
   if(pthread_create(&th->tid, NULL, thfunc_dummy, NULL)){
       return -1;
   }
   th->status = STATUS_USED;
   return th->tid;  
}
static int do_kill_thread(struct process *p, long tid)
{
  struct thread *th = find_thread_by_tid(p, tid);
  if(!th)
       return -1;
  pthread_cancel(th->tid);
  usleep(100);
  bzero(th, sizeof(struct thread));
  return 1;  
}
long handle_process_command(struct process *p)
{
   long retval;
   volatile struct internal_command *command = &p->todo;
   switch(command->cmd){
   case IC_OPEN_FILE:
                        retval = open_one_file(p);
                        break;
   case IC_CLOSE_FILE:
                        retval = close_file(p, command->id);
                        break;   
   case IC_READ_FILE:
   case IC_WRITE_FILE:
                        retval = do_file_rw(p, command);
                        break;
   case IC_SEEK_FILE:
                        retval = do_file_seek(p, command);
                        break;
   case IC_MMAP_MEM:
                        retval = do_mmap(p, command->pages);
                        break; 
   case IC_UNMAP_MEM:
                        retval = do_unmap(p, command->id);
                        break;
   case IC_READ_MEM:
   case IC_WRITE_MEM:
                        retval = do_mem_rw(p, command);
                        break; 
   case IC_CREATE_THREAD:
                        retval = do_create_thread(p);
                        break;
   case IC_DELETE_THREAD:
                        retval = do_kill_thread(p, command->id);
                        break;
   case IC_EXIT:
                        bzero(p, sizeof(struct process));
                        command->response = getpid();
                        msync(p, sizeof(struct process), MS_SYNC);
                        exit(0);
                        break;
                        
   default:
                       retval = IC_RESPONSE_ERR;
                       break;     
   }
   
   return retval;
}

void child_main(struct process *plist)
{
    struct process *p = find_unused_process(plist);
    p->status = STATUS_USED;
    p->pid = getpid();
    p->ppid = getppid();
    msync(p, sizeof(struct process), MS_SYNC);
    while(1){
         if(p->todo.cmd){
              p->todo.response = handle_process_command(p); 
              p->todo.cmd = 0;  // We don't want to process the same command twice
              msync(p, sizeof(struct process), MS_SYNC);
         }else{
              usleep(CHILD_SLEEP_USEC);
         }
    }
}
