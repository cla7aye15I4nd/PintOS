//
// Created by gabriel on 6/25/20.
//

#ifndef PINTOS_PAGE_H
#define PINTOS_PAGE_H

#include "../lib/kernel/hash.h"

enum page_status {
	FRAME, SWAP, FILE
};

struct sup_page_table_entry {
	struct hash_elem hashElem; //Must contain, see "lib/kernel/hash"

	void *vPage, *phyPage;
	enum page_status status;
	bool writeable;
	uint32_t swap_index;
};

struct sup_page_table {
	struct hash hashTable;
};

//Helper Methods
unsigned sup_page_table_entry_hash(const struct hash_elem *e, void *aux);
bool sup_page_table_entry_less(const struct hash_elem *a, const struct hash_elem *b, void *aux);
void sup_page_table_entry_destroy(struct hash_elem *e, void *aux);

//Instantiation and Destruction
struct sup_page_table *sup_page_table_create();
void sup_page_table_destroy(struct sup_page_table *sup_page_table);

//Basic methods of a table
struct sup_page_table_entry *sup_page_table_find(struct sup_page_table *sup_page_table, void *vPage);
bool sup_page_table_set_page(struct sup_page_table *sup_page_table, void *vPage, void *phyPage, bool writeable,
							 enum page_status type);

//File Mapping
bool sup_page_table_unmap(struct sup_page_table *sup_page_table, void *vPage);

//Page Fault Handler
bool page_fault_handler(struct sup_page_table *sup_page_table, uint32_t *page_dir, void *fault_addr, bool isWrite);

#endif //PINTOS_PAGE_H
