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




//actual functions
void system_halt(void);
void exit (int status);
tid_t execute_command (const char *command_line);
tid_t wait_for_process (int pid);
bool create_file (const char *file_name, unsigned initial_size);
bool remove_file (const char *file_name);
int open_file (const char *file_name);
int get_filesize (int fd);
int read_file (int fd, void *buffer, unsigned size);
int write_file (int fd, const void *buffer, unsigned size);
void set_file_position (int fd, unsigned position);
unsigned get_file_position (int fd);
void close_file (int fd);


#endif /* userprog/syscall.h */