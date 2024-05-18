#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <list.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/synch.h"

struct file_descriptor
{
    int fd;                        /*file id*/
    struct file *file;             /*actual file*/
    struct list_elem elem;      /*list elem to add fd_element in fd_list*/
};

struct lock sys_lock;

void syscall_init (void);



//wrapper functions
void wrapper_halt(void);
void wrapper_exit (struct intr_frame *f);
tid_t wrapper_exec (struct intr_frame *f);
tid_t wrapper_wait (struct intr_frame *f);
bool wrapper_create (struct intr_frame *f);
bool wrapper_remove (struct intr_frame *f);
int wrapper_open (struct intr_frame *f);
int wrapper_filesize (struct intr_frame *f);
int wrapper_read (struct intr_frame *f);
int wrapper_write (struct intr_frame *f);
void wrapper_seek (struct intr_frame *f);
unsigned wrapper_tell (struct intr_frame *f);
void wrapper_close (struct intr_frame *f);

//actual functions
void halt(void);
void exit (int status);
tid_t exec (const char *cmd_line);
tid_t wait (int pid);
bool create (const char *file, unsigned initial_size);
bool rmv (const char *file);
int open (const char *file);
int filesize (int fd);
int read (int fd, void *buffer, unsigned size);
int write (int fd, const void *buffer, unsigned size);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);


#endif /* userprog/syscall.h */
