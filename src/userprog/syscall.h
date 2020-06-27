#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "userprog/process.h"

void syscall_init (void);
void s_exit (int);
void close_f (struct file *);

#endif /* userprog/syscall.h */
