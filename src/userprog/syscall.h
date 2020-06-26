#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "userprog/process.h"

void syscall_init (void);
void close_fd (struct file_descriptor *);

#endif /* userprog/syscall.h */
