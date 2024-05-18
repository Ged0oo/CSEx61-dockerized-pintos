
#include "userprog/syscall.h"
#include <stdio.h>
#include <stdlib.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "user/syscall.h"
#include "lib/syscall-nr.h"


static void syscall_handler (struct intr_frame *);
static struct lock files_sync_lock;
int get_int (int esp, int i);
void switch_call(int sys_code);
char* get_char_ptr(char*** esp, int i);
void* get_void_ptr(void*** esp, int i);
void validate_void_ptr(const void* pt);

void release_children(struct thread* t);
void close_files(struct thread* t);
void remove_parent_list(struct thread* t);
struct file_descriptor* get_file_d(int fd);

void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&sys_lock);
}

int get_int (int esp, int i){
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
  void **esp = f->esp;
  validate_void_ptr(esp);
  int sys_code  = get_int ((int)esp, 0);

  switch (sys_code){

    case SYS_HALT:
  {
    //halt();

    shutdown_power_off();
    break;
  }

  case SYS_EXIT:
  {
    //wrapper_exit (f);

    int status = get_int((int**)f->esp, 1);
    validate_void_ptr((const void*)status);
    exit (status);
    break;
  }

  case SYS_EXEC:
  {
    //f->eax = wrapper_exec (f);
    
    char* cmd_line = get_char_ptr((char***)(f->esp), 1);
    validate_void_ptr((const void*)cmd_line);
    f->eax = exec (cmd_line);
    
    break;
  }

  case SYS_WAIT:
  {
    //f->eax = wrapper_wait (f);
    
    int pid = get_int((int**)(f->esp), 1);
    validate_void_ptr((const void*)pid);
    f->eax = wait (pid);

    break;
  }

  case SYS_CREATE:
  {
    //f->eax = wrapper_create (f);
    
    char* file = get_char_ptr((char***)(f->esp), 1);
    validate_void_ptr((const void*)file);

    int initial_size = get_int((int**)(f->esp), 2);
    validate_void_ptr((const void*)initial_size);

    f->eax = create (file, initial_size);

    break;
  }

  case SYS_REMOVE:
  {
    //f->eax = wrapper_remove (f);
    
    char* file = get_char_ptr((char***)(f->esp), 1);
    validate_void_ptr((const void*)file);

    f->eax = rmv (file);
    
    break;
  }

  case SYS_OPEN:
  {
    //f->eax = wrapper_open (f);
    
    char* file = get_char_ptr((char***)(f->esp), 1);
    validate_void_ptr((const void*)file);

    f->eax = open (file);
    
    break;
  }

  case SYS_FILESIZE:
  {
    //f->eax = wrapper_filesize (f);
    
    int fd = get_int((int**)(f->esp), 1);
    validate_void_ptr((const void*)fd);

    f->eax = filesize (fd);
    
    break;
  }

  case SYS_READ:
  {
    //f->eax = wrapper_read(f);
    
    int fd = get_int((int**)(f->esp), 1);
    validate_void_ptr((const void*)fd);

    void *buffer = get_void_ptr((void***)(f->esp), 2);
    validate_void_ptr((const void*)buffer );

    unsigned size = get_int((int**)(f->esp), 3);
    validate_void_ptr((const void*)size);

    f->eax = read (fd, buffer, size);
    
    break;
  }

  case SYS_WRITE:
  {
    //f->eax = wrapper_write (f);
    
    int fd = get_int((int**)(f->esp), 1);
    validate_void_ptr((const void*)fd);

    void *buffer = get_void_ptr((void***)(f->esp), 2);
    validate_void_ptr((const void*)buffer );


    unsigned size = get_int((int**)(f->esp), 3);
    validate_void_ptr((const void*)size);

    f->eax = write ( fd, buffer, size);
    
    break;
  }

  case SYS_SEEK:
  {
    //wrapper_seek (f);
    
    int fd = get_int((int**)(f->esp), 1);
    validate_void_ptr((const void*)fd);

    unsigned position = get_int((int**)(f->esp), 2);
    validate_void_ptr((const void*)position);

    seek ( fd, position);
    
    break;
  }

  
case SYS_TELL:
  {
    //f->eax = wrapper_tell (f);
    
    int fd = get_int((int**)(f->esp), 1);
    validate_void_ptr((const void*)fd);

    f->eax = tell (fd);
    
    break;
  }

  case SYS_CLOSE:
  {
    //wrapper_close(f);
    
    int fd = get_int((int**)(f->esp), 1);
    validate_void_ptr((const void*)fd);

    close (fd);
    
    break;
  }
  }
}

void validate_void_ptr(const void* pt){
  if (!(is_user_vaddr (pt))){
      exit (-1);
  }
}


void exit(int status){
    struct thread * t = thread_current();
    printf("%s: exit(%d)\n", t->name, status);
     if(!list_empty(&t->files));
        close_files(t);
     if(t->fd_exec != NULL)
        file_allow_write (t->fd_exec);
     if(t->parent_thread->waiting_on == t->tid){
        t->parent_thread->child_status = status;
        t->parent_thread->waiting_on = -1;
        sema_up(&t->parent_thread->parent_child_sync);
    }
    else
        remove_parent_list(t);
    if(!list_empty(&t->child_list))
        release_children(t);
    thread_exit();
}

tid_t exec (const char *cmd_line){
    return process_execute(cmd_line);
}

tid_t wait (int pid){
    return process_wait(pid);
}

bool create (const char *file, unsigned initial_size){
    if(file==NULL)
  exit(-1);
    lock_acquire(&sys_lock);
    bool created = filesys_create(file, initial_size);
    lock_release(&sys_lock);
    return created;

}

bool rmv (const char *file)
{
    lock_acquire(&sys_lock);
    bool removed = filesys_remove(file);
    lock_release(&sys_lock);
    return removed;
}

int open (const char *file){
    if(file==NULL)
  return -1;
    lock_acquire(&sys_lock);
    struct file* trial = filesys_open(file);
    if(trial == NULL)
        return -1;
    struct file_descriptor *new_file = malloc(sizeof(struct file_descriptor));
    new_file->fd = thread_current()->fd_last++;
    lock_release(&sys_lock);
    new_file->file = trial;
    list_push_back(&thread_current()->files, &new_file->elem);
    return new_file->fd;
}

int filesize (int fd){
    struct file_descriptor* file_d = get_file_d(fd);
    if(file_d == NULL ||  file_d->file == NULL)
        return -1;
    lock_acquire(&sys_lock);
    int size = file_length(file_d ->file);
    lock_release(&sys_lock);
    return size;
}

int read (int fd, void *buffer, unsigned size){
    if(fd == 0)
        return input_getc();
    struct file_descriptor* file_d = get_file_d(fd);
    if(file_d == NULL || file_d->file == NULL || buffer == NULL)
        return -1;
    lock_acquire(&sys_lock);
    unsigned bytes_read = file_read (file_d ->file, buffer,size);
    lock_release(&sys_lock);
    return bytes_read;
}

int write (int fd, const void *buffer, unsigned size){
    if(fd == 1){
       putbuf((char*)buffer, size);
       return size;
    }
    struct file_descriptor* file_d = get_file_d(fd);
    if(file_d == NULL || file_d->file == NULL || buffer == NULL)
        return -1;
    lock_acquire(&sys_lock);
    unsigned bytes_written = file_write(file_d ->file, buffer, size);
    lock_release(&sys_lock);
    return bytes_written;
}

void seek (int fd, unsigned position){
    struct file_descriptor* file_d = get_file_d(fd);
    if(file_d == NULL || file_d->file == NULL)
        return;
    unsigned curr_pos = tell(fd);
    lock_acquire(&sys_lock);
    file_seek(file_d->file, position);
    lock_release(&sys_lock);
}

unsigned tell (int fd){
    struct file_descriptor* file_d = get_file_d(fd);
    if(file_d == NULL || file_d->file == NULL)
        return -1;
    lock_acquire(&sys_lock);
    unsigned val = file_tell(file_d ->file);
    lock_release(&sys_lock);
    return val;
}

void close (int fd){
    struct file_descriptor *file_d = get_file_d(fd);
    if(file_d== NULL)
        return;
    lock_acquire(&sys_lock);
    file_close(file_d->file);
    list_remove(&file_d->elem);
    lock_release(&sys_lock);
    free(file_d);

}

  
void close_files(struct thread *t){
    struct list_elem *e;
    while(!list_empty(&t->files)){
        e = list_pop_front(&t->files);
        struct file_descriptor *file_d = list_entry (e, struct file_descriptor, elem);
       file_close(file_d->file);
       list_remove(&file_d->elem);
       free(file_d);
    }
}

void release_children(struct thread *t){
    struct list_elem* e;
    while(!list_empty(&t->child_list)){
        e = list_pop_front(&t->child_list);
        struct child_process *child = list_entry (e, struct child_process, elem);
        list_remove(&child->elem);
        sema_up(&child->t->parent_child_sync);
        free(child);
    }
}

void remove_parent_list(struct thread* t){
    struct list_elem* e;
    for (e = list_begin (&t->parent_thread->child_list); e != list_end (&t->parent_thread->child_list); e = list_next (e)){
        struct child_process *child = list_entry (e, struct child_process, elem);
        if(child ->pid == t->tid){
            list_remove(&child->elem);
            free(child);
            break;
            }
    }
}

struct file_descriptor* get_file_d(int fd){
    struct thread *t = thread_current();
    struct file_descriptor *file_d = NULL;
    struct list_elem* e;
    lock_acquire(&sys_lock);
        if(!list_empty(&t->files)){
            for (e = list_begin (&t->files); e != list_end (&t->files); e = list_next (e)){
                struct file_descriptor *temp = list_entry (e, struct file_descriptor, elem);
                if(temp->fd == fd){
                    file_d = temp;
                    break;
                }
            }
        }
    lock_release(&sys_lock);
    return file_d;
}