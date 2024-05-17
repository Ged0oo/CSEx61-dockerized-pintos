#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <list.h>
#include "threads/synch.h"
struct file_descriptor
{
    int fd;                        /*file id*/
    struct file *file;             /*actual file*/
    struct list_elem elem;      /*list elem to add fd_element in fd_list*/
};

struct lock sys_lock;

void syscall_init (void);

#endif /* userprog/syscall.h */
