#include <debug.h>
#include "threads/synch.h"
#include "filesys/cache.h"
#include "filesys/filesys.h"

#define CACHE_SIZE 64

static struct lock cache_lock;
static struct cache_entry cache[CACHE_SIZE];

void 
cache_init (void) 
{
    lock_init (&cache_lock);
    memset(cache, 0, sizeof(cache));
}

void
cache_close (void)
{
    lock_acquire (&cache_lock);

    for (size_t i = 0; i < CACHE_SIZE; ++i) 
        if (cache[i].valid) cache_entry_flush(cache + i);

    lock_release (&cache_lock);
}

void 
cache_entry_flush (struct cache_entry *entry) 
{
    ASSERT (lock_held_by_current_thread (&cache_lock));
    ASSERT (entry != NULL && entry->valid);

    if (entry->dirty) {
        block_write (fs_device, entry->sector, entry->data);
        entry->dirty = false;
    }
}

struct cache_entry*
cache_lookup (block_sector_t sector)
{
    for (size_t i = 0; i < CACHE_SIZE; ++i) 
        if (cache[i].valid && cache[i].sector == sector)
            return cache + i;
    return NULL;
}

struct cache_entry*
cache_fetch (void) 
{
    ASSERT (lock_held_by_current_thread(&cache_lock));

    static size_t clock = 0;
    while (true) {
        if (!cache[clock].valid)
            break;

        if (cache[clock].reference)
            cache[clock].reference = false;
        else {
            cache_entry_flush (cache + clock);
            break;
        }

        clock = (clock + 1) & (CACHE_SIZE - 1);
    }
    
    struct cache_entry* entry = cache + clock;

    entry->valid = true;
    entry->dirty = false;

    return entry;
}

void
cache_read (block_sector_t sector, void *buffer) 
{
    lock_acquire (&cache_lock);

    struct cache_entry *entry = cache_lookup (sector);

    if (entry == NULL) {
        entry = cache_fetch();
        entry->sector = sector;
        block_read (fs_device, sector, entry->data);
    }

    entry->reference = true;
    memcpy (buffer, entry->data, BLOCK_SECTOR_SIZE);

    lock_release (&cache_lock);
}

void 
cache_write (block_sector_t sector, const void *source)
{
    lock_acquire (&cache_lock);

    struct cache_entry *entry = cache_lookup (sector);

    if (entry == NULL) {
        entry = cache_fetch();
        entry->sector = sector;
    }

    entry->reference = true;
    entry->dirty = true;
    memcpy (entry->data, source, BLOCK_SECTOR_SIZE);

    lock_release (&cache_lock);
}