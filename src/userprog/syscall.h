#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "userprog/process.h"

void syscall_init (void);
void s_exit (int);
void close_f (struct file *);

//#ifdef VM
mapid_t s_mmap(mapid_t, void *);
void s_munmap(mapid_t);
//#endif

#endif /* userprog/syscall.h */
