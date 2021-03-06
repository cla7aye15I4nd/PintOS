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
#include "filesys/inode.h"
#include "filesys/directory.h"
#ifdef VM
#include "../vm/page.h"
#endif

static void syscall_handler(struct intr_frame *);

void s_exit(int);

struct lock filesys_lock;

static int get_user (const uint8_t *uaddr) {
    if (uaddr >= PHYS_BASE) {
        return -1;
    }
    int result;
    asm ("movl $1f, %0; movzbl %1, %0; 1:"
    : "=&a" (result) : "m" (*uaddr));
    return result;
}

static bool put_user (uint8_t *udst, uint8_t byte) {
    if (udst >= PHYS_BASE) {
        return false;
    }
    int error_code;
    asm ("movl $1f, %0; movb %b2, %1; 1:"
    : "=&a" (error_code), "=m" (*udst) : "q" (byte));
    return error_code != -1;
}

static void
check_address(const void *addr) {
    struct thread *cur_thread = thread_current();
#ifdef VM
    if (!((addr) && is_user_vaddr(addr) &&
          (sup_page_table_find_locked(cur_thread->sup_page_table, pg_round_down(addr)) ||
           (sup_page_table_on_stack(cur_thread->esp, addr) && page_fault_handler(cur_thread->sup_page_table, cur_thread->pagedir, addr, true, cur_thread->esp))))) {
#else
    if (!((addr) && is_user_vaddr(addr) && pagedir_get_page (thread_current()->pagedir, addr))) {
#endif
        s_exit(-1);
        return;
    }

//        if (get_user(addr) == -1) {
//        s_exit(-1);
//        return;
//    }
}

static uint32_t
arg(const void *addr, int num) {
    for (int i = 0; i < 4; ++i)
        check_address(addr + i + (num << 2));
    return *((uint32_t * )(addr) + num);

//    uint32_t ret;
//    for (int i = 0; i < 4; ++i) {
//        int value = get_user(addr + i + (num << 2));
////        printf("arg: %d\n", value);
//        if (value == -1) {
//            s_exit(-1);
//            return;
//        }
//        *((char*)(&ret) + i) = value & 0xff;
//    }
////    printf("%d\n",ret);
//    return ret;
}

static void
check_string(const char *str) {
    for (char *p = str; p == str || *(p - 1); ++p)
        check_address(p);
//    if (get_user(str) == -1) {
//        s_exit(-1);
//        return;
//    }
}

void
syscall_init(void) {
    intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
    lock_init(&filesys_lock);
//    printf("filesys lock %p\n", &filesys_lock);
}

static void
s_halt(void) {
    shutdown_power_off();
}

void
s_exit(int status) {
    thread_current()->exit_status = status;
    printf("%s: exit(%d)\n", thread_current()->name, status);
    //Correct???
    if (lock_held_by_current_thread(&filesys_lock))
        lock_release(&filesys_lock);
    thread_exit();
    printf("****************** exit done!\n");
}

static pid_t
s_exec(const char *cmd_line) {
    check_string(cmd_line);
    lock_acquire(&filesys_lock);
    int status = process_execute(cmd_line);
    lock_release(&filesys_lock);
    // printf ("************* exec returned %d\n", status);
    return status;
}

static int
s_wait(pid_t pid) {
    return process_wait(pid);
}

static bool 
s_create (const char *file, unsigned initial_size) 
{
  check_string (file);
  lock_acquire (&filesys_lock);
  bool status = filesys_create (file, initial_size, false);
  lock_release (&filesys_lock);
  return status;
}

static bool
s_remove(const char *file) {
    check_string(file);
    lock_acquire(&filesys_lock);
    bool status = filesys_remove(file);
    lock_release(&filesys_lock);
    return status;
}

static struct file_descriptor *
create_fd(struct file *f) {
    struct file_descriptor *fd = malloc(sizeof(struct file_descriptor));
    fd->fdn = (thread_current()->current_fdn++);
    fd->file = f;
    
    struct inode* inode = file_get_inode(f);
    if (inode != NULL && inode_is_dir (inode))
        fd->dir = dir_open (inode_reopen (inode));
    else
        fd->dir = NULL;
    

    list_push_back(&thread_current()->files, &fd->fd_elem);
    return fd;
}

static struct file_descriptor *
find_fd(int fdn) {
    struct list *files = &thread_current()->files;
    for (struct list_elem *e = list_begin(files); e != list_end(files); e = list_next(e)) {
        struct file_descriptor *fd = list_entry(e, struct file_descriptor, fd_elem);
        if (fd->fdn == fdn)
            return fd;
    }
    return NULL;
}

void
close_f(struct file *f) {
    lock_acquire(&filesys_lock);
    file_close(f);
    lock_release(&filesys_lock);
}

static int
s_open(const char *file) {
    check_string(file);

    lock_acquire(&filesys_lock);
    struct file *f = filesys_open(file);

    if (f == NULL) {
        lock_release(&filesys_lock);
        return -1;
    }
    
    struct file_descriptor *fd = create_fd(f);

    lock_release(&filesys_lock);
    return fd->fdn;
}

static int
s_filesize(int fdn) {
    struct file_descriptor *fd = find_fd(fdn);
    if (fd == NULL)
        return -1;

    lock_acquire(&filesys_lock);
    int result = file_length(fd->file);
    lock_release(&filesys_lock);

    return result;
}

static int
s_read(int fdn, void *buf, unsigned size) {
//    printf("read %p %p\n", buf, pg_ofs(buf));
    for (int i = -pg_ofs(buf); i < pg_ofs(buf) + size; i += PGSIZE)
        check_address(buf + i);
//    printf("read\n");

    if (fdn == 0) {
        for (int i = 0; i < size; i++) {
//            put_user(buf + i, input_getc());
            *((char *) buf + i) = input_getc();
        }
        return size;
    }

    struct file_descriptor *fd = find_fd(fdn);
    if (fd == NULL)
        return -1;

    lock_acquire(&filesys_lock);
    int status = file_read(fd->file, buf, size);
    lock_release(&filesys_lock);
    return status;
}

static int
s_write(int fdn, const void *buf, unsigned size) {
//     printf ("system write %d %s\n", size, (char *) buf);
    for (int i = -pg_ofs(buf); i < pg_ofs(buf) + size; i += PGSIZE)
        check_address(buf + i);

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
  
  // printf("************** syscall write complete size %d status %d\n", size, status);

  return status;
}

static void
s_seek(int fdn, unsigned position) {
    struct file_descriptor *fd = find_fd(fdn);
    if (fd == NULL)
        return -1;

    lock_acquire(&filesys_lock);
    file_seek(fd->file, position);
    lock_release(&filesys_lock);
}

static unsigned
s_tell(int fdn) {
    struct file_descriptor *fd = find_fd(fdn);
    if (fd == NULL)
        return;

    lock_acquire(&filesys_lock);
    unsigned result = file_tell(fd->file);
    lock_release(&filesys_lock);

    return result;
}

static void
s_close(int fdn) {
    struct file_descriptor *fd = find_fd(fdn);
    if (fd == NULL)
        s_exit(-1);

    close_f (fd->file);
    if (fd->dir)
        dir_close (fd->dir);
    list_remove (&fd->fd_elem);
    free (fd);
}

static bool
s_chdir (const char *dir)
{
    if (dir[0] == '\0')
        return false;

    bool retval;
    lock_acquire (&filesys_lock); 
    retval = filesys_chdir (dir);
    lock_release (&filesys_lock);

    return retval;
}

static bool
s_mkdir (const char *dir)
{
    if (dir[0] == '\0')
        return false;

    bool retval;
    lock_acquire (&filesys_lock); 
    retval = filesys_create (dir, 0, true);
    lock_release (&filesys_lock);

    return retval;
}

static bool
s_readdir (int fdn, char name[READDIR_MAX_LEN + 1]) 
{
    bool retval = false;

    lock_acquire (&filesys_lock);
  
    struct inode *inode;
    struct file_descriptor *fd = find_fd (fdn);

    if (fd != NULL && fd->dir != NULL) {
        retval = dir_readdir (fd->dir, name);
    }

    lock_release (&filesys_lock);
    return retval;
}

static bool
s_isdir (int fdn) 
{
  lock_acquire (&filesys_lock);

  struct file_descriptor *fd = find_fd (fdn);
  bool retval = inode_is_dir (file_get_inode(fd->file));

  lock_release (&filesys_lock);
  return retval;
}

static int
s_inumber (int fdn) 
{
  lock_acquire (&filesys_lock);

  struct file_descriptor *fd = find_fd (fdn);
  int retval = inode_get_sector (file_get_inode(fd->file));

  lock_release (&filesys_lock);
  return retval;
}

static void
syscall_handler(struct intr_frame *f UNUSED) {
#ifdef VM
    //Save esp
    thread_current()->esp = f->esp;
#endif

    // get call type enum
    int type = arg(f->esp, 0);
//    printf("system call! %x %d\n", f->esp, type);

    switch (type) {
        case SYS_HALT:              s_halt    ();                                                   break;
        case SYS_EXIT:              s_exit    (arg (f->esp, 1));                                    break;
        case SYS_EXEC:    f->eax =  s_exec    (arg (f->esp, 1));                                    break;
        case SYS_WAIT:    f->eax =  s_wait    (arg (f->esp, 1));                                    break;
        case SYS_CREATE:  f->eax =  s_create  (arg (f->esp, 1), arg (f->esp, 2));                   break;
        case SYS_REMOVE:  f->eax =  s_remove  (arg (f->esp, 1));                                    break;
        case SYS_OPEN:    f->eax =  s_open    (arg (f->esp, 1));                                    break;
        case SYS_FILESIZE:f->eax =  s_filesize(arg (f->esp, 1));                                    break;
        case SYS_READ:    f->eax =  s_read    (arg (f->esp, 1), arg (f->esp, 2), arg (f->esp, 3));  break;
        case SYS_WRITE:   f->eax =  s_write   (arg (f->esp, 1), arg (f->esp, 2), arg (f->esp, 3));  break;
        case SYS_SEEK:              s_seek    (arg (f->esp, 1), arg (f->esp, 2));                   break;
        case SYS_TELL:    f->eax =  s_tell    (arg (f->esp, 1));                                    break;
        case SYS_CLOSE:             s_close   (arg (f->esp, 1));                                    break;
#ifdef VM
        case SYS_MMAP:    f->eax =  s_mmap(arg(f->esp, 1), arg(f->esp, 2));                         break;
        case SYS_MUNMAP:            s_munmap(arg(f->esp, 1));                                       break;
#endif
        case SYS_CHDIR:   f->eax =  s_chdir   (arg (f->esp, 1));                                    break;
        case SYS_MKDIR:   f->eax =  s_mkdir   (arg (f->esp, 1));                                    break;
        case SYS_READDIR: f->eax =  s_readdir (arg (f->esp, 1), arg (f->esp, 2));                   break;                                    break;
        case SYS_ISDIR:   f->eax =  s_isdir   (arg (f->esp, 1));                                    break;
        case SYS_INUMBER: f->eax =  s_inumber (arg (f->esp, 1));                                    break;
    }
}

#ifdef VM
static struct file_descriptor *get_file_descriptor(int fd) {
    for (struct list_elem *e = list_begin(&thread_current()->files);
         e != list_end(&thread_current()->files); e = list_next(e)) {
        struct file_descriptor *ret = list_entry(e, struct file_descriptor, fd_elem);
        if (ret->fdn == fd) return ret;
    }
    return NULL;
}

static struct mmap *get_mmap(mapid_t id) {
    for (struct list_elem *e = list_begin(&thread_current()->mmap_list);
         e != list_end(&thread_current()->mmap_list); e = list_next(e)) {
        struct mmap *ret = list_entry(e, struct mmap, mmap_elem);
        if (ret->id == id) return ret;
    }
    return NULL;
}

mapid_t s_mmap(int fd, void *addr) {
//    printf("Mmap %d %p", fd, addr);

    struct file_descriptor *file_descriptor = get_file_descriptor(fd);
    if (fd <= 1 || file_descriptor == NULL) return -1;
    if (addr == 0 || pg_ofs(addr) != 0) return -1;

    lock_acquire(&filesys_lock);

    struct file *file = file_reopen(file_descriptor->file);
    size_t size = file_length(file);
    if (file == NULL || size == 0) {
        lock_release(&filesys_lock);
        return -1;
    }

    struct thread *cur_thread = thread_current();

    //Check before map
    for (size_t offset = 0; offset < size; offset += PGSIZE) {
        if (sup_page_table_find(cur_thread->sup_page_table, addr + offset)) {
            lock_release(&filesys_lock);
            return -1;
        }
    }

    //Map every page
    for (size_t offset = 0; offset < size; offset += PGSIZE) {
        uint32_t read_bytes = offset + PGSIZE < size ? PGSIZE : (size - offset);
        uint32_t zero_bytes = PGSIZE - read_bytes;
        sup_page_table_set_file(cur_thread->sup_page_table, addr + offset, file, offset, read_bytes, zero_bytes, true);
    }

    struct mmap *cur_mmap = (struct mmap *) malloc(sizeof(struct mmap));
    cur_mmap->id = 1;
    if (!list_empty(&cur_thread->mmap_list)) {
        cur_mmap->id = (list_entry(list_back(&cur_thread->mmap_list), struct mmap, mmap_elem))->id + 1;
    }

    cur_mmap->vPage = addr;
    cur_mmap->file = file;
//    printf("MMAP Id: %d, Size: %d\n", cur_mmap->id, size);
    cur_mmap->size = size;
    list_push_back(&cur_thread->mmap_list, &cur_mmap->mmap_elem);

    lock_release(&filesys_lock);
    return cur_mmap->id;
}

void s_munmap(mapid_t mapid) {
    lock_acquire(&filesys_lock);

    struct mmap *cur_mmap = get_mmap(mapid);
    struct thread *cur_thread = thread_current();
    if (cur_mmap == NULL) return;

//    printf("In s_munmap %d %p %d\n", mapid, cur_mmap, cur_mmap->size);

    for (size_t offset = 0; offset < cur_mmap->size; offset += PGSIZE) {
        uint32_t read_bytes = offset + PGSIZE < cur_mmap->size ? PGSIZE : (cur_mmap->size - offset);
        sup_page_table_unmap(cur_thread->sup_page_table, cur_mmap->vPage + offset, cur_thread->pagedir,
                             cur_mmap->file, offset, read_bytes);
    }
    file_close(cur_mmap->file);
    list_remove(&cur_mmap->mmap_elem);
    free(cur_mmap);

    lock_release(&filesys_lock);
    return;
}
#endif