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
static struct lock file_lock_sync;

struct file_descriptor* get_file_descriptor(int fd);
void syscall_init (void);

//actual called function of system call
void exit (int status);
bool create_file (const char *file_name, unsigned initial_size);
bool remove_file (const char *file_name);
int open_file (const char *file_name);
int get_filesize (int fd);
int read_file (int fd, void *buffer, unsigned size);
int write_file (int fd, const void *buffer, unsigned size);
void set_file_position (int fd, unsigned position);
unsigned get_file_position (int fd);
void close_file (int fd);

int read_int_from_stack (int esp, int offset);
char* read_char_ptr_from_stack(int * esp, int offset);
static void syscall_handler (struct intr_frame *);
void* read_void_ptr_from_stack(int * esp, int offset);
void dispatch_syscall(int sys_code);
void validate_user_ptr(const void* pt);
void terminate_child_processes(struct thread* t);
void close_opened_files(struct thread* t);
void remove_from_parent_list(struct thread* t);




#endif /* userprog/syscall.h */