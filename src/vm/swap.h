//
// Created by zhang on 2020/6/27.
//

#ifndef PINTOS_SWAP_H
#define PINTOS_SWAP_H

#include "../devices/block.h"
#include "../lib/kernel/bitmap.h"
#include "../threads/vaddr.h"
#include "../threads/synch.h"

void swap_table_init();

//In and Out is relative to memory
void swap_in(uint32_t swap_index, void *page);
uint32_t swap_out(void *page);
void swap_free(uint32_t swap_index);

#endif //PINTOS_SWAP_H
