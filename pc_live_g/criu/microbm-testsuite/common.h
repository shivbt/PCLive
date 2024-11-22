#ifndef __COMMON_H_
#define __COMMON_H_

#include<stdio.h>
#include<stdlib.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<unistd.h>
#include<wait.h>
#include<assert.h>
#include<fcntl.h>
#include<sys/mman.h>
#include<sys/un.h>
#include<pthread.h>
#include<string.h>

#define PAGE_SIZE 4096
#define PAGE_SHIFT 12

#define UNIX_SOCK_PATH "/tmp/bm.sock"
#define CHILD_SLEEP_USEC 10000


#define STATUS_FREE 0
#define STATUS_USED 1

#define MAX_PROCESS 16
#define MAX_THREADS_PROCESS 16
#define MAX_FILES_PROCESS 16
#define MAX_MEM_PROCESS 16

#ifndef true
    #define true 1
#endif

#ifndef false
    #define false 0
#endif

#ifndef bool
   typedef unsigned char bool;
#endif

enum{
        CMD_INFO_PROCESS=1,   // none, for others id_1 is the pid
        CMD_INFO_THREADS,   
        CMD_INFO_FILES,      
        CMD_INFO_MEM,
        CMD_CREATE_PROCESS,
        CMD_KILL_PROCESS,       
        CMD_OPEN_FILE,         
        CMD_CLOSE_FILE,
        CMD_OP_FILE,
        CMD_MALLOC,
        CMD_MFREE,
        CMD_MOP,
        CMD_THREAD_CREATE,
        CMD_THREAD_DESTROY,
        CMD_MAX
};
enum{
       OP_READ=1,
       OP_WRITE,
       OP_SEEK
};
struct command{
                 short command;
                 short operation;
                 int pages;
                 long id_1;
                 long id_2;
};

#define CMD_SUCCESS 0
#define CMD_ERR -1
struct response{
                 int status;
                 int size;
                 long rsp_id;
                 char args[0];
};

struct thread{
                 int status;
                 pthread_t tid;  
                 int pos;
                 int parent_pid;
};

struct file{
                int status;
                int fd;
                int pos;
};

struct memory{
                int status;
                int mid;
                int pos;
                void* start;
                unsigned long size; 
};

enum{
         IC_CREATE_THREAD=1,
         IC_DELETE_THREAD,
         IC_OPEN_FILE,
         IC_CLOSE_FILE,
         IC_READ_FILE,
         IC_WRITE_FILE,
         IC_SEEK_FILE,
         IC_MMAP_MEM,
         IC_UNMAP_MEM,
         IC_READ_MEM,
         IC_WRITE_MEM,
         IC_EXIT,
         IC_MAX
};

#define IC_RESPONSE_ERR -1

struct internal_command{
                        long cmd;
                        long id;  
                        long pages;
                        long response;
};

struct process{
                 int status;   
                 int pid;
                 int ppid;
                 int pos;
                 struct thread threads[MAX_THREADS_PROCESS];
                 struct file files[MAX_FILES_PROCESS];
                 struct memory mem_areas[MAX_MEM_PROCESS];
                 volatile struct internal_command todo; 
};

static void kill_all_child(struct process *p)
{
   for(int i=1; i<MAX_PROCESS; ++i){
          if((p+i)->status == STATUS_USED){
                  kill((p+i)->pid, SIGKILL); 
          }
  }
}
static struct process* find_process_by_id(struct process *p, int pid)
{
   for(int i=0; i<MAX_PROCESS; ++i)
        if((p+i)->pid == pid)
              return p+i;
   return NULL; 
}

static struct process* find_unused_process(struct process *p)
{
   for(int i=0; i<MAX_PROCESS; ++i)
        if((p+i)->status == STATUS_FREE){
              (p+i)->pos = i;
              return p+i;
        } 
   return NULL; 
}

static struct thread* find_thread_by_tid(struct process *p, unsigned long tid)
{
   for(int i=0; i<MAX_THREADS_PROCESS; ++i)
        if(p->threads[i].tid == tid){
              return &p->threads[i];
        }
   return NULL; 
}

static struct thread* find_unused_thread(struct process *p)
{
   for(int i=0; i<MAX_THREADS_PROCESS; ++i)
        if(p->threads[i].status == STATUS_FREE){
              p->threads[i].pos = i;
              return &p->threads[i];
         }
   return NULL; 
}

static struct file* find_file_by_fd(struct process *p, int fd)
{
   for(int i=0; i<MAX_FILES_PROCESS; ++i)
        if(p->files[i].fd == fd)
              return &p->files[i];
   return NULL; 
}

static struct file* find_unused_file(struct process *p)
{
   for(int i=0; i<MAX_FILES_PROCESS; ++i)
        if(p->files[i].status == STATUS_FREE){
              p->files[i].pos = i;
              return &p->files[i];
        }
   return NULL; 
}

static struct memory* find_mem_by_id(struct process *p, int id)
{
   for(int i=0; i<MAX_MEM_PROCESS; ++i)
        if(p->mem_areas[i].mid == id)
              return &p->mem_areas[i];
   return NULL; 
}

static struct memory* find_unused_memory(struct process *p)
{
   for(int i=0; i<MAX_MEM_PROCESS; ++i)
        if(p->mem_areas[i].status == STATUS_FREE){
              p->mem_areas[i].pos = i;
              return &p->mem_areas[i];
        }
   return NULL; 
}

extern void child_main(struct process *plist);
extern long handle_process_command(struct process *p);
#endif
