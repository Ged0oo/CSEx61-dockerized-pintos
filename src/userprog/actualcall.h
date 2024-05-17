#ifndef USERPROG_ACTUALCALL_H
#define USERPROG_ACTUALCALL_H

#include <list.h>
#include "userprog/actualcall.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "lib/syscall-nr.h"
#include "userprog/syscall.h"

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

#endif /* userprog/actualcall.h */
