//
// Created by gabriel on 6/26/20.
//

#include "../vm/page.h"
#include "../threads/malloc.h"
#include "../threads/thread.h"
#include "../threads/vaddr.h"
#include "../threads/palloc.h"
#include "../userprog/pagedir.h"
#include "../vm/frame.h"
#include "../vm/swap.h"
#include "../userprog/process.h"

static struct lock page_lock;

unsigned sup_page_table_entry_hash(const struct hash_elem *e, void *aux) {
    struct sup_page_table_entry *entry = hash_entry(e, struct sup_page_table_entry, hashElem);
    unsigned ret = hash_int((int) entry->vPage);
//    printf("Hashing %p %p %d\n", entry, entry->vPage, ret);
    return ret;
}

bool sup_page_table_entry_less(const struct hash_elem *a, const struct hash_elem *b, void *aux) {
    struct sup_page_table_entry *entryA = hash_entry(a, struct sup_page_table_entry, hashElem);
    struct sup_page_table_entry *entryB = hash_entry(b, struct sup_page_table_entry, hashElem);
    return entryA->vPage < entryB->vPage;
}

void sup_page_table_entry_destroy(struct hash_elem *e, void *aux) {
    struct sup_page_table_entry *entry = hash_entry(e, struct sup_page_table_entry, hashElem);
    if (entry->status == FRAME) {
        frame_remove_entry(entry->phyPage);
    } else if (entry->status == SWAP) {
        swap_free(entry->swap_index);
    }
    free(entry);
}

struct sup_page_table *sup_page_table_create() {
    struct sup_page_table *ret = (struct sup_page_table *) malloc(sizeof(struct sup_page_table));
    hash_init(&ret->hashTable, sup_page_table_entry_hash, sup_page_table_entry_less, NULL);
    lock_init(&page_lock);
//    printf("page lock %p\n", &page_lock);
    return ret;
}

void sup_page_table_destroy(struct sup_page_table *sup_page_table) {
//    lock_acquire(&page_lock);
    hash_destroy(&sup_page_table->hashTable, sup_page_table_entry_destroy);
    free(sup_page_table);
//    lock_release(&page_lock);
}

struct sup_page_table_entry *sup_page_table_find(struct sup_page_table *sup_page_table, void *vPage) {
    //lock_acquire(&page_lock);
    struct sup_page_table_entry tmp;
    tmp.vPage = vPage;
    struct hash_elem *ret = hash_find(&sup_page_table->hashTable, &tmp.hashElem);

    if (ret != NULL) {
        //lock_release(&page_lock);
        return hash_entry(ret, struct sup_page_table_entry, hashElem);
    } else {
        //lock_release(&page_lock);
        return NULL;
    }
}

bool sup_page_table_set_frame(struct sup_page_table *sup_page_table, void *vPage, void *phyPage, bool writable) {
//    printf("Set frame %p %p\n", vPage, &sup_page_table->hashTable);

    if (sup_page_table_find(sup_page_table, vPage) != NULL) return false;

    struct sup_page_table_entry *newEntry = (struct sup_page_table_entry *) malloc(
            sizeof(struct sup_page_table_entry));

    //lock_acquire(&page_lock);
    newEntry->vPage = vPage;
    newEntry->phyPage = phyPage;
    newEntry->status = FRAME;
    newEntry->writable = writable;
    newEntry->dirty = false;
    hash_insert(&sup_page_table->hashTable, &newEntry->hashElem);

    //lock_release(&page_lock);
    return true;
}

bool sup_page_table_set_swap(struct sup_page_table *sup_page_table, void *vPage, uint32_t swap_index) {
//    printf("Set swap %p %p %d\n", vPage, &sup_page_table->hashTable, swap_index);
    struct sup_page_table_entry *cur = sup_page_table_find(sup_page_table, vPage);
    if (cur == NULL) {
        return false;
    }

    //lock_acquire(&page_lock);
    cur->status = SWAP;
    cur->phyPage = NULL;
    cur->swap_index = swap_index;

    //lock_release(&page_lock);
    return true;
}

bool sup_page_table_set_file(struct sup_page_table *sup_page_table, void *vPage, struct file *file, off_t offset,
                             uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
//    printf("Set file %p %p %d\n", vPage, &sup_page_table->hashTable, read_bytes);
    if (sup_page_table_find(sup_page_table, vPage) != NULL) return false;
//    printf("load file: %p%p\n",file, vPage);
    struct sup_page_table_entry *newEntry = (struct sup_page_table_entry *) malloc(
            sizeof(struct sup_page_table_entry));
    //lock_acquire(&page_lock);

    newEntry->vPage = vPage;
    newEntry->phyPage = NULL;
    newEntry->status = FILE;
    newEntry->dirty = false;
    newEntry->offset = offset;
    newEntry->file = file;
    newEntry->read_bytes = read_bytes;
    newEntry->zero_bytes = zero_bytes;
    newEntry->writable = writable;

    hash_insert(&sup_page_table->hashTable, &newEntry->hashElem);
    //lock_release(&page_lock);

    return true;
}

bool sup_page_table_unmap(struct sup_page_table *sup_page_table, void *vPage, uint32_t *page_dir, struct file *file,
                          off_t offset, size_t bytes) {
    struct sup_page_table_entry *entry = sup_page_table_find(sup_page_table, vPage);
    if (entry == NULL) PANIC("Can't unmap an non-existent page");

    //lock_acquire(&page_lock);
    //Pin if necessary
    if (entry->status == FRAME) {
        frame_pin(entry->phyPage);
    }

    bool dirty;
    switch (entry->status) {
        case FRAME:
            dirty = entry->dirty;
            dirty |= pagedir_is_dirty(page_dir, entry->vPage);
            dirty |= pagedir_is_dirty(page_dir, entry->phyPage);
//            printf("Dirty %d %d %d\n",entry->dirty, pagedir_is_dirty(page_dir, entry->vPage),pagedir_is_dirty(page_dir, entry->phyPage));
//            printf("Dirty %p\n", entry->phyPage);
            lock_acquire(&filesys_lock);

            if (dirty) {
                file_write_at(file, entry->vPage, bytes, offset);
            }
            frame_free(entry->phyPage);
            pagedir_clear_page(page_dir, entry->vPage);

            lock_release(&filesys_lock);
            break;
        case SWAP:
            dirty = entry->dirty;
            dirty |= pagedir_is_dirty(page_dir, entry->vPage);
            lock_acquire(&filesys_lock);

            if (dirty) {
                void *tmp = palloc_get_page(0);
                swap_in(entry->swap_index, tmp);
                file_write_at(file, tmp, PGSIZE, offset);
                palloc_free_page(tmp);
            }
            swap_free(entry->swap_index);

            lock_release(&filesys_lock);
            break;
        case FILE:
            break;
    }

    hash_delete(&sup_page_table->hashTable, &entry->hashElem);
    //lock_release(&page_lock);

    return true;
}

bool load_from_swap(struct sup_page_table_entry *entry, void *frame) {
    swap_in(entry->swap_index, frame);
    return true;
}

bool load_from_file(struct sup_page_table_entry *entry, void *frame) {
    lock_acquire(&filesys_lock);

    int read = file_read_at(entry->file, frame, entry->read_bytes, entry->offset);
    memset(frame + read, 0, entry->zero_bytes);

    lock_release(&filesys_lock);
    return true;
}

bool sup_page_table_load(struct sup_page_table *sup_page_table, uint32_t *page_dir, void *page) {
    struct sup_page_table_entry *entry = sup_page_table_find(sup_page_table, page);
//    printf("HELLO %p\n", entry);
    if (entry == NULL) return false;
    if (entry->status == FRAME && entry->phyPage != NULL) return true;

    //Obtain a frame
    void *frame = frame_get(PAL_USER, page);
    if (frame == NULL) return false;

    //Load into the frame
    bool success = true;
    switch (entry->status) {
        case SWAP:
            success = load_from_swap(entry, frame);
            break;
        case FILE:
            success = load_from_file(entry, frame);
            break;
        case FRAME:
            //Initializing the stack
            memset(frame, 0, PGSIZE);
            break;
        default:
            break;
    }
    bool writable = entry->writable;

    //Add entry to page directory
    if ((!success) || !pagedir_set_page(page_dir, page, frame, writable)) {
        frame_free(frame);
        return false;
    }

    //lock_acquire(&page_lock);
    //Add entry to sup page table
    entry->status = FRAME;
    entry->phyPage = frame;
    pagedir_set_dirty(page_dir, frame, false);
    //lock_release(&page_lock);

    frame_release_pinned(frame);
    return true;
}

bool sup_page_table_on_stack(void *esp, void *addr) {
//    printf("%p %p\n", esp, addr);
    return (addr >= esp - 32) && (addr >= PHYS_BASE - STACK_MAX) && (addr < PHYS_BASE);
}

static void sup_page_table_init_stack_page(struct sup_page_table *sup_page_table, void *vPage) {
    struct sup_page_table_entry *newEntry = (struct sup_page_table_entry *) malloc(
            sizeof(struct sup_page_table_entry));
    //lock_acquire(&page_lock);
    newEntry->vPage = vPage;
    newEntry->phyPage = NULL;
    newEntry->status = FRAME;
    newEntry->writable = true;
    hash_insert(&sup_page_table->hashTable, &newEntry->hashElem);
    //lock_release(&page_lock);
}

bool page_fault_handler(struct sup_page_table *sup_page_table, uint32_t *page_dir, void *fault_addr, bool isWrite,
                        void *esp) {
    //Invalid Access
    if (!is_user_vaddr(fault_addr)) return false;

    void *fault_page = pg_round_down(fault_addr);
    if (sup_page_table_on_stack(esp, fault_addr)) {
//        printf("YEAH STACK %p %p\n", fault_addr, fault_page);
        sup_page_table_init_stack_page(sup_page_table, fault_page);
    }
//    printf("PAGE FAULT HANDLER: %p %p\n", page_dir, fault_page);
    bool ret = sup_page_table_load(sup_page_table, page_dir, fault_page);
//    printf(ret ? "PAGE FAULT HANDLED\n" : "PAGE FAULT REMAINS\n");
    return ret;
}

void sup_page_set_dirty(struct sup_page_table *sup_page_table, void *vPage, bool dirty) {
    struct sup_page_table_entry *entry = sup_page_table_find(sup_page_table, vPage);
    if (entry == NULL) PANIC("Page doesn't exist");

    //lock_acquire(&page_lock);
    entry->dirty |= dirty;
    //lock_release(&page_lock);
}