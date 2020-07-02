//
// Created by sheepp on 2020/6/26.
//



#include "frame.h"
#include "swap.h"
#include "../lib/kernel/hash.h"
#include "../lib/kernel/list.h"
#include "../lib/debug.h"
#include "../threads/synch.h"
#include "../threads/palloc.h"
#include "../threads/thread.h"
#include "../threads/malloc.h"
#include "../userprog/pagedir.h"

static struct hash frame_table;
static struct list frame_list;
static struct lock global_lock;
static struct list_elem *cur_frame;

void frame_free_op(void *frame, bool real);

static unsigned frame_hash_hash_func(const struct hash_elem *element, void *aux UNUSED) {
    struct frame_entry *frame = hash_entry(element, struct frame_entry, hash_elem);
    return hash_bytes(&frame->frame, sizeof(frame->frame));
}

static bool frame_hash_less_func(const struct hash_elem *lhs, const struct hash_elem *rhs, void *aux UNUSED) {
    struct frame_entry *lhs_frame = hash_entry(lhs, struct frame_entry, hash_elem);
    struct frame_entry *rhs_frame = hash_entry(rhs, struct frame_entry, hash_elem);
    return lhs_frame->frame < rhs_frame->frame;
}

void frame_init() {
    hash_init(&frame_table, frame_hash_hash_func, frame_hash_less_func, NULL);
    list_init(&frame_list);
    lock_init(&global_lock);
//    printf("frame lock %p\n", &global_lock);
    cur_frame = NULL;
}

void *frame_query(void *frame) {
    struct frame_entry entry;
    entry.frame = frame;
    struct hash_elem *hash = hash_find(&frame_table, &(entry.hash_elem));
    return hash == NULL ? NULL : hash_entry(hash, struct frame_entry, hash_elem);
}

struct frame_entry *next_frame() {
    if (list_empty(&frame_list))
        PANIC("empty frame table");

    if (cur_frame == NULL || cur_frame == list_end(&frame_list)) {
        cur_frame = list_begin(&frame_list);
    } else {
        cur_frame = list_next(cur_frame);
    }

    struct frame_entry *entry = list_entry(cur_frame, struct frame_entry, list_elem);
    return entry;
}

struct frame_entry *next_evicted_frame(void *pagedir) {
    size_t size = hash_size(&frame_table);
    if (size == 0) {
        PANIC("Empty frame table!");
    }
    size_t it = 0;
    for (it = 0; it <= 2 * size; ++it) {
        struct frame_entry *entry = next_frame();
        if (entry->pinned) continue;
        if (pagedir_is_accessed(pagedir, entry->upage)) {
            pagedir_set_accessed(pagedir, entry->upage, false);
            continue;
        }

        return entry;
    }

    PANIC("Fail to evict any frame.");
}

void *frame_get(enum palloc_flags flag, void *upage) {
    lock_acquire(&global_lock);

    void *page = palloc_get_page(flag | PAL_USER);
    if (page == NULL) {
#ifndef VM
        lock_release(&global_lock);
        return NULL;
#endif
        struct frame_entry *evicted_frame = next_evicted_frame(thread_current()->pagedir);
        void *pd = evicted_frame->thread->pagedir;
        pagedir_clear_page(pd, evicted_frame->upage);

        bool dirty = pagedir_is_dirty(pd, evicted_frame->upage) || pagedir_is_dirty(pd, evicted_frame->frame);
        uint32_t swap_index = swap_out(evicted_frame->frame);

        sup_page_table_set_swap(evicted_frame->thread->sup_page_table, evicted_frame->upage, swap_index);
        sup_page_set_dirty(evicted_frame->thread->sup_page_table, evicted_frame->upage, dirty);
        frame_free_op(evicted_frame->frame, true);

        page = palloc_get_page(flag | PAL_USER);
    }

    ASSERT(page != NULL);
    struct frame_entry *entry = malloc(sizeof(struct frame_entry));
    ASSERT(entry != NULL);
    entry->frame = page;
    entry->upage = upage;
    entry->thread = thread_current();
    entry->pinned = true;

    hash_insert(&frame_table, &entry->hash_elem);
    list_push_back(&frame_list, &entry->list_elem);

    lock_release(&global_lock);
    return page;
}

void frame_free(void *frame) {
    lock_acquire(&global_lock);
    frame_free_op(frame, true);
    lock_release(&global_lock);
}

void frame_remove_entry(void *frame) {
    lock_acquire(&global_lock);
    frame_free_op(frame, false);
    lock_release(&global_lock);
}

void frame_free_op(void *frame, bool real) {
    struct frame_entry tmp;
    tmp.frame = frame;
    struct hash_elem *hash = hash_find(&frame_table, &tmp.hash_elem);
    if (hash == NULL) {
        PANIC("Free a frame not in the frame table");
    }

    struct frame_entry *entry = hash_entry(hash, struct frame_entry, hash_elem);
    hash_delete(&frame_table, &entry->hash_elem);
    list_remove(&entry->list_elem);

    if (real) palloc_free_page(frame);
    free(entry);
}

bool frame_if_pinned(void *frame) {
    struct frame_entry *entry = frame_query(frame);
    if (entry == NULL) {
        PANIC("try_to_check_frame_that_does_not_exist");
    }
    return entry -> pinned;
}

static void frame_set_pinned(void *frame, bool value) {
    struct frame_entry *entry = frame_query(frame);
    if (entry == NULL && value) {
        if (value) PANIC("Try to pin frame that does not exist");
//        else PANIC("Try to unpin frame that does not exist");
    }

    if (entry != NULL) entry->pinned = value;
//    if (entry->pinned) {
//        list_push_back(&frame_list, &entry->list_elem);
//        if (list_size(frame_list) == 1)
//            cur_frame = entry;
//    }
}

void frame_pin(void *frame) {
    lock_acquire(&global_lock);
    frame_set_pinned(frame, true);
    lock_release(&global_lock);
}

void frame_release_pinned(void *frame) {
    lock_acquire(&global_lock);
    frame_set_pinned(frame, false);
    lock_release(&global_lock);
}