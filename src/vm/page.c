//
// Created by gabriel on 6/26/20.
//

#include "page.h"
#include "../threads/malloc.h"
#include "../threads/thread.h"
#include "../threads/vaddr.h"

unsigned sup_page_table_entry_hash(const struct hash_elem *e, void *aux) {
	struct sup_page_table_entry *entry = hash_entry(e, struct sup_page_table, hashElem);
	return hash_bytes(entry->vPage, sizeof(entry->vPage));
}

bool sup_page_table_entry_less(const struct hash_elem *a, const struct hash_elem *b, void *aux) {
	struct sup_page_table_entry *entryA = hash_entry(a, struct sup_page_table, hashElem);
	struct sup_page_table_entry *entryB = hash_entry(b, struct sup_page_table, hashElem);
	return entryA->vPage < entryB->vPage;
}

void sup_page_table_entry_destroy(struct hash_elem *e, void *aux) {
	struct sup_page_table_entry *entry = hash_entry(e, struct sup_page_table, hashElem);
	if (entry->status == FRAME) {
		//TODO: Call Corresponding free function
	} else if (entry->status == SWAP) {
		//TODO: Call Corresponding free function
	}
	free(entry);
}

struct sup_page_table *sup_page_table_create() {
	struct sup_page_table *ret = (struct sup_page_table *) malloc(sizeof(struct sup_page_table));
	hash_init(&ret->hashTable, sup_page_table_entry_hash, sup_page_table_entry_less, NULL);
	return ret;
}

void sup_page_table_destroy(struct sup_page_table *sup_page_table) {
	hash_destroy(&sup_page_table->hashTable, sup_page_table_entry_destroy);
	free(sup_page_table);
}

struct sup_page_table_entry *sup_page_table_find(struct sup_page_table *sup_page_table, void *vPage) {
	struct sup_page_table_entry *tmp = hash_entry(a, struct sup_page_table, hashElem);
	tmp->vPage = vPage;
	struct hash_elem *ret = hash_find(&sup_page_table->hashTable, &tmp->hashElem);
	if (ret != NULL) {
		return hash_entry(ret, struct sup_page_table, hashElem);
	} else {
		return NULL;
	}
}

bool sup_page_table_set_frame(struct sup_page_table *sup_page_table, void *vPage, void *phyPage, bool writeable) {
	if (findPage(sup_page_table, vPage) == NULL) {
		struct sup_page_table_entry *newEntry = (struct sup_page_table_entry *) malloc(
				sizeof(struct sup_page_table_entry));
		newEntry->vPage = vPage;
		newEntry->phyPage = phyPage;
		newEntry->status = FRAME;
		newEntry->writeable = writeable;
		hash_insert(&sup_page_table->hashTable, &newEntry->hashElem);
		return true;
	} else {
		return false;
	}
}

bool sup_page_table_set_page(struct sup_page_table *sup_page_table, void *vPage, void *phyPage, bool writeable,
							 enum page_status type) {
	//TODO: Needs lock?
	if (type == FRAME) {
		return sup_page_table_set_frame(sup_page_table, vPage, phyPage, writeable);
	} else if (type == SWAP) {
		//TODO
	} else {

	}
}

bool unMap(struct sup_page_table *sup_page_table, void *vPage) {
	//TODO
}

bool sup_page_table_load(struct sup_page_table *sup_page_table, uint32_t *page_dir, void *vPage) {
	struct sup_page_table_entry *entry = sup_page_table_find(sup_page_table, fault_page);
	if (entry == NULL) return false;
	if (entry->status == FRAME) return true;

	//
}

bool page_fault_handler(struct sup_page_table *sup_page_table, uint32_t *page_dir, void *fault_addr, bool isWrite,
						void *esp) {
	//Invalid Access
	if (!is_user_vaddr(fault_addr)) return false;

	void *fault_page = pg_round_down(fault_addr);
	if (on_stack(esp, fault_addr)) {
		//TODO: Stack Growth
	}
	return sup_page_table_load(sup_page_table, page_dir, fault_page);
}
