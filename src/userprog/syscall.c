#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "devices/shutdown.h"
#include "threads/synch.h"
#include "userprog/process.h"
#include "lib/user/syscall.h"
#include "filesys/filesys.h"
#include "filesys/file.h"

static void syscall_handler (struct intr_frame *);
static void s_exit (int);

static struct lock filesys_lock;

static void
check_address (const void * addr) 
{
  // printf ("checking address %x\n", addr);
  if (!((addr) && is_user_vaddr (addr) && pagedir_get_page (thread_current ()->pagedir, addr))) {
    // printf ("putain a la %x!\n", addr);
    s_exit (-1);
    return;
  }
}

static uint32_t
get_argument (const void * addr, int num) {
  for (int i = 0; i < 4; ++i)
    check_address (addr + i + (num << 2));
  return *((uint32_t *)(addr) + num);
}

static void
check_string (const char * str)
{
  for (char * p = str; p == str || *(p - 1); ++p)
    check_address (p);
}

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init (&filesys_lock);
}

static void 
s_halt (void) 
{
  shutdown_power_off();
}

static void
s_exit (int status) 
{
  thread_current ()->exit_status = status;
  printf ("%s: exit(%d)\n", thread_current()->name, status);
  thread_exit ();
  printf ("****************** exit done!\n");
}

static pid_t 
s_exec (const char *cmd_line) 
{
  check_string (cmd_line);
  lock_acquire (&filesys_lock);
  int status = process_execute (cmd_line);
  lock_release (&filesys_lock);
  // printf ("************* exec returned %d\n", status);
  return status;
}

static int 
s_wait (pid_t pid)
{
  return process_wait (pid);
}

static bool 
s_create (const char *file, unsigned initial_size) 
{
  check_string (file);
  lock_acquire (&filesys_lock);
  bool status = filesys_create (file, initial_size);
  lock_release (&filesys_lock);
  return status;
}

static bool 
s_remove (const char *file)
{
  check_string (file);
  lock_acquire (&filesys_lock);
  bool status = filesys_remove (file);
  lock_release (&filesys_lock);
  return status;
}

static struct file_descriptor *
create_fd (struct file *f)
{
  struct file_descriptor *fd = malloc (sizeof (struct file_descriptor));
  fd->fdn = (thread_current()->current_fdn++);
  fd->file = f;
  list_push_back (&thread_current()->files, &fd->fd_elem);
  return fd;
}

static struct file_descriptor *
find_fd (int fdn)
{
  struct list *files = &thread_current()->files;
  for (struct list_elem *e = list_begin(files); e != list_end(files); e = list_next(e))
  {
    struct file_descriptor * fd = list_entry(e, struct file_descriptor, fd_elem);
    if (fd->fdn == fdn)
      return fd;
  }
  return NULL;
}

void
close_fd (struct file_descriptor *fd)
{
  lock_acquire (&filesys_lock);
  file_close (fd->file);
  lock_release (&filesys_lock);
}

static int 
s_open (const char *file)
{
  check_string (file);

  lock_acquire (&filesys_lock);
  struct file *f = filesys_open (file);
  lock_release (&filesys_lock);

  if (f == NULL)
    return -1;
  else
    return (create_fd (f))->fdn;
}

static int
s_filesize (int fdn)
{
  struct file_descriptor * fd = find_fd (fdn);
  if (fd == NULL)
    return -1;

  lock_acquire (&filesys_lock);
  int result = file_length (fd->file);
  lock_release (&filesys_lock);

  return result;
}

static int
s_read (int fdn, void *buf, unsigned size)
{
  for (int i = 0; i < size; i++)
    check_address (buf + i);
  if (fdn == 0) {
    for (int i = 0; i < size; i++)
      *((char *)buf + i) = input_getc();
    return size;
  }

  struct file_descriptor * fd = find_fd (fdn);
  if (fd == NULL)
    return -1;
  
  lock_acquire (&filesys_lock);
  int status = file_read (fd->file, buf, size);
  lock_release (&filesys_lock);

  return status;
}

static int
s_write (int fdn, const void *buf, unsigned size) {
  // printf ("system write %d %d %s\n", fd, size, (char *) buf);
  for (int i = 0; i < size; i++)
    check_address (buf + i);

  if (fdn == 1)
  {
    putbuf ((const char *)buf, size);
    return size;
  }
  struct file_descriptor * fd = find_fd (fdn);
  if (fd == NULL)
    return -1;
  
  lock_acquire (&filesys_lock);
  int status = file_write (fd->file, buf, size);
  lock_release (&filesys_lock);
  
  return status;
}

static void 
s_seek (int fdn, unsigned position)
{
  struct file_descriptor * fd = find_fd (fdn);
  if (fd == NULL)
    return -1;

  lock_acquire (&filesys_lock);
  file_seek (fd->file, position);
  lock_release (&filesys_lock);
}

static unsigned 
s_tell (int fdn)
{
  struct file_descriptor * fd = find_fd (fdn);
  if (fd == NULL)
    return;

  lock_acquire (&filesys_lock);
  unsigned result = file_tell (fd->file);
  lock_release (&filesys_lock);

  return result;
}

static void
s_close (int fdn)
{
  struct file_descriptor * fd = find_fd (fdn);
  if (fd == NULL)
    s_exit (-1);

  close_fd (fd);
  list_remove (&fd->fd_elem);
  free (fd);
}


static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  // printf ("system call! %x\n", f->esp);
  // get call type enum
  int type = get_argument (f->esp, 0);
  switch (type)
  {
    case SYS_HALT:
      s_halt ();
      break;
    case SYS_EXIT:
      s_exit (get_argument (f->esp, 1));
      break;
    case SYS_EXEC:
      f->eax = s_exec (get_argument (f->esp, 1));
      break;
    case SYS_WAIT:
      f->eax = s_wait (get_argument (f->esp, 1));
      break;
    case SYS_CREATE:
      f->eax = s_create (get_argument (f->esp, 1), get_argument (f->esp, 2));
      break;
    case SYS_REMOVE:
      f->eax = s_remove (get_argument (f->esp, 1));
      break;
    case SYS_OPEN:
      f->eax = s_open (get_argument (f->esp, 1));
      break;
    case SYS_FILESIZE:
      f->eax = s_filesize (get_argument (f->esp, 1));
      break;
    case SYS_READ:
      f->eax = s_read (get_argument (f->esp, 1), get_argument (f->esp, 2), get_argument (f->esp, 3));
      break;
    case SYS_WRITE:
      f->eax = s_write (get_argument (f->esp, 1), get_argument (f->esp, 2), get_argument (f->esp, 3));
      break;
    case SYS_SEEK:
      s_seek (get_argument (f->esp, 1), get_argument (f->esp, 2));
      break;
    case SYS_TELL:
      f->eax = s_tell (get_argument (f->esp, 1));
      break;
    case SYS_CLOSE:
      s_close (get_argument (f->esp, 1));
      break;
  }
}
