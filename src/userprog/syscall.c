
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
static struct lock file_lock_sync;

int read_int_from_stack (int esp, int offset);
void dispatch_syscall(int sys_code);
char* read_char_ptr_from_stack(char*** esp, int offset);
void* read_void_ptr_from_stack(void*** esp, int offset);
void validate_user_ptr(const void* pt);

void terminate_child_processes(struct thread* t);
void close_all_files(struct thread* t);
void remove_from_parent_list(struct thread* t);
struct file_descriptor* get_file_descriptor(int fd);

void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&sys_lock);
}

int read_int_from_stack (int esp, int offset){
  // Calculate the address on the stack using the offset and read the integer value at that address.
  int value = *((int*)esp + offset);
  return value;
}

// Reads a character pointer from the stack at the given offset.
char* read_char_ptr_from_stack(char*** esp, int offset){
  char* char_ptr = (char*)(*((int*)esp + offset));
  return char_ptr;
}

// Reads a void pointer from the stack at the given offset.
void* read_void_ptr_from_stack(void*** esp, int offset){
  void* void_ptr  = (void*)(*((int*)esp + offset));
  return void_ptr;
}

static void
syscall_handler (struct intr_frame *f UNUSED)
{
  void **esp = f->esp;
  validate_user_ptr(esp);
  int sys_code  = read_int_from_stack ((int)esp, 0);

  if (sys_code == SYS_HALT) {

    // If the system call code is SYS_HALT, halt the system.
    system_halt();

  } else if (sys_code == SYS_EXIT) {

    // If the system call code is SYS_EXIT, exit the process with the given status.
    int status = read_int_from_stack((int **)f->esp, 1);
    validate_user_ptr((const void *)status); // Validate the status pointer.
    exit(status);

  } else if (sys_code == SYS_EXEC) {

    // If the system call code is SYS_EXEC, execute a new process.
    char *cmd_line = read_char_ptr_from_stack((char ***)(f->esp), 1);
    validate_user_ptr((const void *)cmd_line); // Validate the command line pointer.
    f->eax = execute_command(cmd_line); // Store the result in eax.

  } else if (sys_code == SYS_WAIT) {

    // If the system call code is SYS_WAIT, wait for a child process to terminate.
    int pid = read_int_from_stack((int **)(f->esp), 1);
    validate_user_ptr((const void *)pid); // Validate the PID pointer.
    f->eax = wait_for_process(pid); // Store the result in eax.

  } else if (sys_code == SYS_CREATE) {

    // If the system call code is SYS_CREATE, create a new file.
    char *file = read_char_ptr_from_stack((char ***)(f->esp), 1);
    validate_user_ptr((const void *)file); // Validate the file name pointer.
    int initial_size = read_int_from_stack((int **)(f->esp), 2);
    validate_user_ptr((const void *)initial_size); // Validate the initial size pointer.
    f->eax = create_file(file, initial_size); // Store the result in eax.

  } else if (sys_code == SYS_REMOVE) {

    // If the system call code is SYS_REMOVE, remove a file.
    char *file = read_char_ptr_from_stack((char ***)(f->esp), 1);
    validate_user_ptr((const void *)file); // Validate the file name pointer.
    f->eax = remove_file(file); // Store the result in eax.

  } else if (sys_code == SYS_OPEN) {

    // If the system call code is SYS_OPEN, open a file.
    char *file = read_char_ptr_from_stack((char ***)(f->esp), 1);
    validate_user_ptr((const void *)file); // Validate the file name pointer.
    f->eax = open_file(file); // Store the result in eax.

  } else if (sys_code == SYS_FILESIZE) {

    // If the system call code is SYS_FILESIZE, get the size of a file.
    int fd = read_int_from_stack((int **)(f->esp), 1);
    validate_user_ptr((const void *)fd); // Validate the file descriptor pointer.
    f->eax = get_filesize(fd); // Store the result in eax.

  } else if (sys_code == SYS_READ) {

    // If the system call code is SYS_READ, read from a file.
    int fd = read_int_from_stack((int **)(f->esp), 1);

    validate_user_ptr((const void *)fd); // Validate the file descriptor pointer.
    void *buffer = read_void_ptr_from_stack((void ***)(f->esp), 2);

    validate_user_ptr((const void *)buffer); // Validate the buffer pointer.
    unsigned size = read_int_from_stack((int **)(f->esp), 3);

    validate_user_ptr((const void *)size); // Validate the size pointer.
    f->eax = read_file(fd, buffer, size); // Store the result in eax.

  } else if (sys_code == SYS_WRITE) {

    // If the system call code is SYS_WRITE, write to a file.
    int fd = read_int_from_stack((int **)(f->esp), 1);

    validate_user_ptr((const void *)fd); // Validate the file descriptor pointer.
    void *buffer = read_void_ptr_from_stack((void ***)(f->esp), 2);

    validate_user_ptr((const void *)buffer); // Validate the buffer pointer.
    unsigned size = read_int_from_stack((int **)(f->esp), 3);

    validate_user_ptr((const void *)size); // Validate the size pointer.
    f->eax = write_file(fd, buffer, size); // Store the result in eax.

  } else if (sys_code == SYS_SEEK) {

    // If the system call code is SYS_SEEK, seek within a file.
    int fd = read_int_from_stack((int **)(f->esp), 1);
    validate_user_ptr((const void *)fd); // Validate the file descriptor pointer.
    unsigned position = read_int_from_stack((int **)(f->esp), 2);

    validate_user_ptr((const void *)position); // Validate the position pointer.
    set_file_position(fd, position);

  } else if (sys_code == SYS_TELL) {

    // If the system call code is SYS_TELL, get the current position within a file.
    int fd = read_int_from_stack((int **)(f->esp), 1);

    validate_user_ptr((const void *)fd); // Validate the file descriptor pointer.
    f->eax = get_file_position(fd); // Store the result in eax.

  } else if (sys_code == SYS_CLOSE) {

    // If the system call code is SYS_CLOSE, close a file.
    int fd = read_int_from_stack((int **)(f->esp), 1);
    validate_user_ptr((const void *)fd); // Validate the file descriptor pointer.
    close_file(fd);

  }
}

void validate_user_ptr(const void* ptr){
  // Check if the provided pointer is a valid user address.
  if (!(is_user_vaddr (ptr))){
    // If the pointer is not a valid user address, exit the process with status -1.
    exit (-1);
  }
}

void system_halt (void) {
  // Halt the system by powering off the machine.
  shutdown_power_off();
}


void exit(int status) {
  struct thread *current_thread = thread_current();
  // Print the thread name and exit status.
  printf("%s: exit(%d)\n", current_thread->name, status);

  // Close all open files if the thread has any.
  if (!list_empty(&current_thread->files)) {
    close_all_files(current_thread);
  }

  // Allow writing to the executable file if it is open.
  if (current_thread->fd_exec != NULL) {
      file_allow_write(current_thread->fd_exec);
   }

    // If the parent thread is waiting on this thread, update the parent's status and release the semaphore.
    if (current_thread->parent_thread->waiting_on == current_thread->tid) {
        current_thread->parent_thread->child_status = status;
        current_thread->parent_thread->waiting_on = -1;
        sema_up(&current_thread->parent_thread->parent_child_sync);
    } else {
        // Remove this thread from the parent's child list if the parent is not waiting on it.
        remove_from_parent_list(current_thread);
    }

    // Terminate all child processes if any exist.
    if (!list_empty(&current_thread->child_list)) {
        terminate_child_processes(current_thread);
    }

    // Exit the thread.
    thread_exit();
}

// Execute a new process given the command line.
tid_t execute_command (const char *command_line){
    return process_execute(command_line);
}

// Wait for a child process with the given process ID to terminate.
tid_t wait_for_process (int process_id){
    return process_wait(process_id);
}

// Create a new file with the specified file name and initial size.
bool create_file (const char *file_name, unsigned initial_size){
  // Ensure the file name is not NULL.
  if(file_name == NULL) 
    // If the file name is NULL, exit the process with status -1.
    exit(-1);

    // Acquire the system lock to perform file creation safely.
    lock_acquire(&sys_lock);
    // Attempt to create the file with the provided name and initial size.
    bool created = filesys_create(file_name, initial_size);
    // Release the system lock after file creation.
    lock_release(&sys_lock);
    // Return true if the file was successfully created, false otherwise.
    return created;

}

// Remove the file with the given name from the file system.
bool remove_file(const char *file_name) {
    // Acquire the system lock to perform file removal safely.
    lock_acquire(&sys_lock);
    // Attempt to remove the file with the provided name.
    bool removed = filesys_remove(file_name);
    // Release the system lock after file removal.
    lock_release(&sys_lock);
    // Return true if the file was successfully removed, false otherwise.
    return removed;
}

// Open the file with the given name.
int open_file(const char *file_name) {
    // Return -1 if the file name is NULL.
    if (file_name == NULL) {
        return -1;
    }
    // Acquire the system lock to perform file opening safely.
    lock_acquire(&sys_lock);
    // Attempt to open the file with the provided name.
    struct file *opened_file = filesys_open(file_name);
    // If the file could not be opened, return -1.
    if (opened_file == NULL) {
        lock_release(&sys_lock);
        return -1;
    }
    // Create a new file descriptor for the opened file.
    struct file_descriptor *new_file_descriptor = malloc(sizeof(struct file_descriptor));
    new_file_descriptor->fd = thread_current()->fd_last++;
    // Release the system lock after obtaining the file descriptor.
    lock_release(&sys_lock);
    // Set the opened file and add the file descriptor to the current thread's list of open files.
    new_file_descriptor->file = opened_file;
    list_push_back(&thread_current()->files, &new_file_descriptor->elem);
    // Return the file descriptor associated with the opened file.
    return new_file_descriptor->fd;
}

// Retrieve the size of the file associated with the given file descriptor.
int get_filesize(int fd) {
    // Obtain the file descriptor associated with the given file descriptor.
    struct file_descriptor *file_d = get_file_descriptor(fd);
    // If the file descriptor is invalid or the associated file is NULL, return -1.
    if (file_d == NULL || file_d->file == NULL) {
        return -1;
    }
    // Acquire the system lock to perform file size retrieval safely.
    lock_acquire(&sys_lock);
    // Get the size of the associated file.
    int size = file_length(file_d->file);
    // Release the system lock after obtaining the file size.
    lock_release(&sys_lock);
    // Return the size of the file.
    return size;
}

// Read data from the file associated with the given file descriptor into the buffer.
int read_file(int fd, void *buffer, unsigned size) {
    // If the file descriptor corresponds to stdin, read from the input.
    if (fd == 0) {
        return input_getc();
    }
    // Obtain the file descriptor associated with the given file descriptor.
    struct file_descriptor *file_d = get_file_descriptor(fd);
    // If the file descriptor is invalid, the associated file is NULL, or the buffer is NULL, return -1.
    if (file_d == NULL || file_d->file == NULL || buffer == NULL) {
        return -1;
    }
    // Acquire the system lock to perform file reading safely.
    lock_acquire(&sys_lock);
    // Read data from the associated file into the buffer.
    unsigned bytes_read = file_read(file_d->file, buffer, size);
    // Release the system lock after reading data from the file.
    lock_release(&sys_lock);
    // Return the number of bytes read from the file.
    return bytes_read;
}

// Write data from the buffer to the file associated with the given file descriptor.
int write_file(int fd, const void *buffer, unsigned size) {
    // If the file descriptor corresponds to stdout, write to the console.
    if (fd == 1) {
        putbuf((char *)buffer, size);
        return size;
    }
    // Obtain the file descriptor associated with the given file descriptor.
    struct file_descriptor *file_d = get_file_descriptor(fd);
    // If the file descriptor is invalid, the associated file is NULL, or the buffer is NULL, return -1.
    if (file_d == NULL || file_d->file == NULL || buffer == NULL) {
        return -1;
    }
    // Acquire the system lock to perform file writing safely.
    lock_acquire(&sys_lock);
    // Write data from the buffer to the associated file.
    unsigned bytes_written = file_write(file_d->file, buffer, size);
    // Release the system lock after writing data to the file.
    lock_release(&sys_lock);
    // Return the number of bytes written to the file.
    return bytes_written;
}

// Change the current position of the file pointer associated with the given file descriptor to the specified position.
void set_file_position(int fd, unsigned position){
    // Obtain the file descriptor associated with the given file descriptor.
    struct file_descriptor* file_d = get_file_descriptor(fd);
    // If the file descriptor is invalid or the associated file is NULL, return without performing any action.
    if(file_d == NULL || file_d->file == NULL)
        return;
    // Obtain the current position of the file pointer.
    unsigned curr_pos = get_file_position(fd);
    // Acquire the system lock to perform file seeking safely.
    lock_acquire(&sys_lock);
    // Set the position of the file pointer to the specified position.
    file_seek(file_d->file, position);
    // Release the system lock after performing the seek operation.
    lock_release(&sys_lock);
}

// Retrieve the current position of the file pointer associated with the given file descriptor.
unsigned get_file_position(int fd){
    // Obtain the file descriptor associated with the given file descriptor.
    struct file_descriptor* file_d = get_file_descriptor(fd);
    // If the file descriptor is invalid or the associated file is NULL, return -1.
    if(file_d == NULL || file_d->file == NULL)
        return -1;
    // Acquire the system lock to perform file seeking safely.
    lock_acquire(&sys_lock);
    // Get the current position of the file pointer.
    unsigned position = file_tell(file_d ->file);
    // Release the system lock after obtaining the file position.
    lock_release(&sys_lock);
    // Return the current position of the file pointer.
    return position;
}

// Close the file associated with the given file descriptor.
void close_file(int fd){
    // Obtain the file descriptor associated with the given file descriptor.
    struct file_descriptor *file_d = get_file_descriptor(fd);
    // If the file descriptor is NULL, return without performing any action.
    if(file_d == NULL)
        return;
    // Acquire the system lock to perform file closing safely.
    lock_acquire(&sys_lock);
    // Close the file associated with the file descriptor.
    file_close(file_d->file);
    // Remove the file descriptor from the list of open files in the current thread.
    list_remove(&file_d->elem);
    // Release the system lock after closing the file.
    lock_release(&sys_lock);
    // Free the memory allocated for the file descriptor.
    free(file_d);
}

  
// Close all files associated with the given thread.
void close_all_files(struct thread *t){
    // Declare a list element to iterate through the list of open files.
    struct list_elem *e;
    // Iterate through the list of open files until it becomes empty.
    while(!list_empty(&t->files)){
        // Pop the front element from the list of open files.
        e = list_pop_front(&t->files);
        // Obtain the file descriptor corresponding to the popped element.
        struct file_descriptor *file_d = list_entry (e, struct file_descriptor, elem);
        // Close the file associated with the file descriptor.
        file_close(file_d->file);
        // Remove the file descriptor from the list of open files.
        list_remove(&file_d->elem);
        // Free the memory allocated for the file descriptor.
        free(file_d);
    }
}

// Terminate all child processes associated with the given thread.
void terminate_child_processes(struct thread *t){
    // Declare a list element to iterate through the list of child processes.
    struct list_elem* e;
    // Iterate through the list of child processes until it becomes empty.
    while(!list_empty(&t->child_list)){
        // Pop the front element from the list of child processes.
        e = list_pop_front(&t->child_list);
        // Obtain the child process corresponding to the popped element.
        struct child_process *child = list_entry (e, struct child_process, elem);
        // Remove the child process from the list of child processes.
        list_remove(&child->elem);
        // Unblock the parent thread waiting on the child process.
        sema_up(&child->t->parent_child_sync);
        // Free the memory allocated for the child process.
        free(child);
    }
}

// Remove the given thread from the list of child processes in its parent thread.
void remove_from_parent_list(struct thread* t){
    // Declare a list element to iterate through the list of child processes in the parent thread.
    struct list_elem* e;
    // Iterate through the list of child processes in the parent thread.
    for (e = list_begin (&t->parent_thread->child_list); e != list_end (&t->parent_thread->child_list); e = list_next (e)){
        // Obtain the child process corresponding to the current list element.
        struct child_process *child = list_entry (e, struct child_process, elem);
        // If the child process has the same PID as the given thread, remove it from the list.
        if(child ->pid == t->tid){
            list_remove(&child->elem);
            // Free the memory allocated for the child process.
            free(child);
            break;
        }
    }
}

// Retrieve the file descriptor associated with the given file descriptor from the current thread's list of open files.
struct file_descriptor* get_file_descriptor(int fd){
    // Obtain the current thread.
    struct thread *t = thread_current();
    // Declare a pointer to store the file descriptor.
    struct file_descriptor *file_d = NULL;
    // Declare a list element to iterate through the list of open files.
    struct list_elem* e;
    // Acquire the system lock to ensure thread safety while accessing the list of open files.
    lock_acquire(&sys_lock);
    // Check if the list of open files in the current thread is not empty.
    if(!list_empty(&t->files)){
        // Iterate through the list of open files.
        for (e = list_begin (&t->files); e != list_end (&t->files); e = list_next (e)){
            // Get the file descriptor corresponding to the current list element.
            struct file_descriptor *temp = list_entry (e, struct file_descriptor, elem);
            // If the file descriptor's file descriptor matches the given file descriptor, store it and break the loop.
            if(temp->fd == fd){
                file_d = temp;
                break;
            }
        }
    }
    // Release the system lock after accessing the list of open files.
    lock_release(&sys_lock);
    // Return the file descriptor associated with the given file descriptor.
    return file_d;
}