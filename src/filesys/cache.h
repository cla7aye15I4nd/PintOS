#ifndef FILESYS_CACHE_H
#define FILESYS_CACHE_H

#include "devices/block.h"

struct cache_entry {
    block_sector_t sector;
    uint8_t data[BLOCK_SECTOR_SIZE];
    
    bool valid, dirty, reference;
};

void cache_init (void);
void cache_close (void);

struct cache_entry* cache_lookup (block_sector_t);
struct cache_entry* cache_fetch (void);

void cache_read (block_sector_t, void*);
void cache_write (block_sector_t, const void*);

void cache_entry_flush (struct cache_entry*);

#endif