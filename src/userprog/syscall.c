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

#ifdef VM
#include "../vm/page.h"
#endif

static void syscall_handler(struct intr_frame *);
void s_exit(int);

#ifdef VM
static mapid_t s_mmap(mapid_t, void *);
void s_munmap(mapid_t);
#endif

static struct lock filesys_lock;

static void
check_address(const void *addr) {
	// printf ("checking address %x\n", addr);
	if (!((addr) && is_user_vaddr(addr) && pagedir_get_page(thread_current()->pagedir, addr))) {
		// printf ("putain a la %x!\n", addr);
		s_exit(-1);
		return;
	}
}

static uint32_t
arg(const void *addr, int num) {
	for (int i = 0; i < 4; ++i)
		check_address(addr + i + (num << 2));
	return *((uint32_t * )(addr) + num);
}

static void
check_string(const char *str) {
	for (char *p = str; p == str || *(p - 1); ++p)
		check_address(p);
}

void
syscall_init(void) {
	intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
	lock_init(&filesys_lock);
}

static void
s_halt(void) {
	shutdown_power_off();
}

void
s_exit(int status) {
	thread_current()->exit_status = status;
	printf("%s: exit(%d)\n", thread_current()->name, status);
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
s_create(const char *file, unsigned initial_size) {
	check_string(file);
	lock_acquire(&filesys_lock);
	bool status = filesys_create(file, initial_size);
	lock_release(&filesys_lock);
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
	list_push_back(&thread_current()->files, &fd->fd_elem);
	return fd;
}

static struct file_descriptor *
find_fd(int fdn) {
	struct list *files = &thread_current()->files;
	for (struct list_elem *e = list_begin(files); e != list_end(files); e = list_next(e)) {
		struct file_descriptor *fd = list_entry(e,
		struct file_descriptor, fd_elem);
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
	lock_release(&filesys_lock);

	if (f == NULL)
		return -1;
	else
		return (create_fd(f))->fdn;
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
	for (int i = 0; i < size; i++)
		check_address(buf + i);
	if (fdn == 0) {
		for (int i = 0; i < size; i++)
			*((char *) buf + i) = input_getc();
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
	// printf ("system write %d %d %s\n", fd, size, (char *) buf);
	for (int i = 0; i < size; i++)
		check_address(buf + i);

	if (fdn == 1) {
		putbuf((const char *) buf, size);
		return size;
	}
	struct file_descriptor *fd = find_fd(fdn);
	if (fd == NULL)
		return -1;

	lock_acquire(&filesys_lock);
	int status = file_write(fd->file, buf, size);
	lock_release(&filesys_lock);

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

	close_f(fd->file);
	list_remove(&fd->fd_elem);
	free(fd);
}


static void
syscall_handler(struct intr_frame *f UNUSED) {
	// printf ("system call! %x\n", f->esp);
	// get call type enum
	int type = arg(f->esp, 0);
	switch (type) {
		case SYS_HALT:
			s_halt();
			break;
		case SYS_EXIT:
			s_exit(arg(f->esp, 1));
			break;
		case SYS_EXEC:
			f->eax = s_exec(arg(f->esp, 1));
			break;
		case SYS_WAIT:
			f->eax = s_wait(arg(f->esp, 1));
			break;
		case SYS_CREATE:
			f->eax = s_create(arg(f->esp, 1), arg(f->esp, 2));
			break;
		case SYS_REMOVE:
			f->eax = s_remove(arg(f->esp, 1));
			break;
		case SYS_OPEN:
			f->eax = s_open(arg(f->esp, 1));
			break;
		case SYS_FILESIZE:
			f->eax = s_filesize(arg(f->esp, 1));
			break;
		case SYS_READ:
			f->eax = s_read(arg(f->esp, 1), arg(f->esp, 2), arg(f->esp, 3));
			break;
		case SYS_WRITE:
			f->eax = s_write(arg(f->esp, 1), arg(f->esp, 2), arg(f->esp, 3));
			break;
		case SYS_SEEK:
			s_seek(arg(f->esp, 1), arg(f->esp, 2));
			break;
		case SYS_TELL:
			f->eax = s_tell(arg(f->esp, 1));
			break;
		case SYS_CLOSE:
			s_close(arg(f->esp, 1));
			break;
		case SYS_MMAP:
			f->eax = s_mmap(arg(f->esp, 1), arg(f->esp, 2));
			break;
		case SYS_MUNMAP:
			s_munmap(arg(f->esp, 1));
			break;
	}
}

#ifdef VM
static file_descriptor *get_file_descriptor(int fd) {
	for (struct list_elem *e = list_begin(&thread_current()->file_descriptors);
		 e != list_end(&thread_current()->file_descriptors); e = list_next(e)) {
		struct file_descriptor *ret = list_entry(e, struct file_descriptor, elem);
		if (ret->fdn == fd) return ret;
	}
	return NULL;
}

static mmap *get_mmap(mapid_t id) {
	for (struct list_elem *e = list_begin(&thread_current()->mmap_list);
		 e != list_end(&thread_current()->file_descriptors); e = list_next(e)) {
		struct mmap *ret = list_entry(e, struct mmap, mmap_elem);
		if (ret->id == id) return ret;
	}
	return NULL;
}

static mapid_t s_mmap(int fd, void *addr) {
	struct file_descriptor *file_descriptor = get_file_descriptor(fd);
	if (fd <= 1 || file_descriptor == NULL) return -1;
	if (pg_ofs(upage) != 0) return -1;

	lock_acquire(&filesys_lock);

	struct file *file = file_reopen(file_descriptor->file);
	size_t size = file_length(file);
	if (file == NULL || size == 0) {
		lock_release(&filesys_lock);
		return -1;
	}

	struct thread *cur_thread = thread_current();

	//Map every page
	for (size_t offset = 0; offset < size; offset += PGSIZE) {
		uint32_t read_bytes = offset + PGSIZE < size ? PGSIZE : (size - offset);
		uint32_t zero_bytes = PGSIZE - read_bytes;
		sup_page_table_set_file(cur_thread->sup_page_table, addr + offset, file, offset, read_bytes, zero_bytes);
	}

	struct mmap *cur_mmap = (struct mmap *) malloc(sizeof(struct mmap));
	if (!list_empty(&cur_thread->mmap_list)) {
		cur_mmap->id = (list_entry(list_back(&cur_thread->mmap_list), struct mmap, mmap_elem))->id + 1;
	} else {
		cur_mmap->id = 1;
	}
	cur_mmap->vPage = addr;
	cur_mmap->file = file;
	cur_mmap->size = size;
	list_push_back(&cur_thread->mmap_list, cur_mmap);

	lock_release(&filesys_lock);
	return cur_mmap->id;
}

void s_munmap(mapid_t mapid) {
	struct mmap *cur_mmap = get_mmap(mapid);
	struct thread *cur_thread = thread_current();
	if (cur_mmap == NULL) return;

	lock_acquire(&filesys_lock);

	for (size_t offset = 0; offset < cur_mmap->size; offset += PGSIZE) {
		uint32_t read_bytes = offset + PGSIZE < cur_mmap->size ? PGSIZE : (cur_mmap->size - offset);
		sup_page_table_unmap(cur_thread->sup_page_table, cur_mmap->vPage + offset, cur_thread->pagedir,
					   cur_mmap->file, offset, read_bytes);
	}
	file_close(cur_mmap->file);
	list_remove(cur_mmap);
	free(cur_mmap);

	lock_release(&filesys_lock);
	return;
}
#endif