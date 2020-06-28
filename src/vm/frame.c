//
// Created by sheepp on 2020/6/26.
//

#include "frame.h"
#include "../lib/kernel/hash.h"
#include "../lib/debug.h"
#include "../threads/synch.h"

static struct hash frame_table;
static struct list frame_list;
static struct lock global_lock;
struct frame_item *cur_frame;

static unsigned frame_hash_hash_func(const struct hash_elem *element, void *aux UNUSED) {
    struct frame_entry *frame = hash_entry(element, frame_entry, hash_elem);
    return hash_bytes(&frame->frame, sizeof(frame->frame));
}

static bool frame_hash_less_func(const struct hash_elem *lhs, const struct hash_elem *rhs, void *aux UNUSED) {
    struct frame_entry *lhs_frame = hash_entry(lhs, frame_entry, hash_elem);
    struct frame_entry *rhs_frame = hash_entry(rhs, frame_entry, hash_elem);
    return lhs_frame->frame < rhs_frame->frame;
}

void frame_init() {
    hash_init(&frame_table, frame_hash_hash_func, frame_hash_less_func, NULL);
    list_init(&frame_list);
    lock_init(&global_lock);
    cur_frame = NULL;
}

void *frame_query(void *frame) {
    struct frame_entry entry;
    entry.frame = frame;
    struct hash_elem *hash = hash_find(&frame_table, &entry.hash_elem);
    return hash == NULL ? NULL : hash_entry(hash, struct frame_entry, hash_elem);
}

void *frame_get() {
    lock_acquire(&global_lock);
    struct frame_entry *
}

void *frame_free() {

}

bool frame_if_pinned(void *frame) {
    struct frame_entry *entry = frame_query(frame);
    if (entry == NULL) {
        PANIC("try_to_pin_frame_that_does_not_exist");
    }
    return entry -> pinnned;
}

bool frame_release_pinned(void *frame) {
    lock_acquire(&global_clock);

    struct frame_entry *entry = frame_query(frame);
    if (entry == NULL) {
        lock_release(&global_clock);
        returan false;
    }
    if (entry->pinned) {
        entry->pinned = false;
        list_push_back(&frame_list, &entry->list_elem);
        if (list_size(frame_list) == 1)
            cur_frame = entry;
    }
    lock_release(&global_lock);
    return true;
}