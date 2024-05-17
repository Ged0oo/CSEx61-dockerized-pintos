#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "user/syscall.h"
#include "lib/syscall-nr.h"
#include "actualcall.h"


static void syscall_handler (struct intr_frame *);
static struct lock files_sync_lock;
int get_int (int **esp, int i);
void switch_call(int sys_code);
char* get_char_ptr(char*** esp, int i);
void* get_void_ptr(void*** esp, int i);
void validate_void_ptr(const void* pt);

void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&sys_lock);
}

int get_int (int** esp, int i){
  int sys_code = *((int*)esp + i);
  return sys_code;
}


char* get_char_ptr(char*** esp, int i){
	char* sys_code_char= (char*)(*((int*)esp + i));
	return sys_code_char;
}

void* get_void_ptr(void*** esp, int i){
	void* sys_code_void = (void*)(*((int*)esp + i));
	return sys_code_void;
}

static void
syscall_handler (struct intr_frame *f UNUSED)
{
  void **esp=f->esp;
  validate_void_ptr(esp);
  int sys_code  = get_int ((int**)esp, 0);

  switch (sys_code){

  	case SYS_HALT:
	{
		halt();
	break;
	}

	case SYS_EXIT:
	{
		wrapper_exit (f);
	break;
	}

	case SYS_EXEC:
	{
		f->eax = wrapper_exec (f);
	break;
	}

	case SYS_WAIT:
	{
		f->eax = wrapper_wait (f);
	break;
	}

	case SYS_CREATE:
	{
		f->eax = wrapper_create (f);
	break;
	}

	case SYS_REMOVE:
	{
		f->eax = wrapper_remove (f);
	break;
	}

	case SYS_OPEN:
	{
		f->eax = wrapper_open (f);
	break;
	}

	case SYS_FILESIZE:
	{
		f->eax = wrapper_filesize (f);
	break;
	}

	case SYS_READ:
	{
		f->eax = wrapper_read(f);
	break;
	}

	case SYS_WRITE:
	{
		f->eax = wrapper_write (f);
	break;
	}

	case SYS_SEEK:
	{
		wrapper_seek (f);
	break;
	}

	case SYS_TELL:
	{
		f->eax = wrapper_tell (f);
	break;
	}

	case SYS_CLOSE:
	{
		wrapper_close(f);
	break;
	}
  }
}

void validate_void_ptr(const void* pt){
	if (!(is_user_vaddr (pt))){
			exit (-1);
	}
}
