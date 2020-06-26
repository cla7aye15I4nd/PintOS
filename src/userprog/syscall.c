#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"

static void syscall_handler (struct intr_frame *);
static void syscall_exit (int);
static int  syscall_write (int, const void *, unsigned);

static void
check_address (const void * addr) 
{
  if (!((addr) && is_user_vaddr (addr) && pagedir_get_page (thread_current ()->pagedir, addr))) {
    printf ("putain a la %x!\n", addr);
    syscall_exit (-1);
    return;
  }
}

static uint32_t
get_argument (const void * addr, int num) {
  for (int i = 0; i < 4; ++i)
    check_address (addr + i + (num << 2));
  return *((uint32_t *)(addr) + num);
}

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  printf ("system call! %x\n", f->esp);
  // get call type enum
  check_address (f->esp);
  int type = *((int *)(f->esp));
  switch (type)
  {
    case SYS_EXIT:
      syscall_exit (get_argument (f->esp, 1));
      break;
    case SYS_WRITE:
      f->eax = syscall_write (get_argument (f->esp, 1), get_argument (f->esp, 2), get_argument (f->esp, 3));
      break;
  }
}

static void
syscall_exit (int status) {
  thread_current ()->exit_status = status;
  printf("%s: exit(%d)\n", thread_current()->name, status);
  thread_exit ();
}

static int
syscall_write (int fd, const void *buf, unsigned size) {
  printf ("system write %d %d %s\n", fd, size, (char *) buf);
  if (fd == 1)
  {
    putbuf ((const char *)buf, size);
    return size;
  }
  return 1;
}
