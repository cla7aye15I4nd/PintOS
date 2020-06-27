//
// Created by gabriel on 6/26/20.
//

#include "page.h"
#include "../threads/malloc.h"

unsigned pageTableEntryHashFunc(const struct hash_elem *e, void *aux) {
	struct pageTableEntry *entry = hash_entry(e, struct pageTable, hashElem);
	return hash_bytes(entry->vPage, sizeof(entry->vPage));
}

bool pageTableEntryLessFunc(const struct hash_elem *a, const struct hash_elem *b, void *aux) {
	struct pageTableEntry *entryA = hash_entry(a, struct pageTable, hashElem);
	struct pageTableEntry *entryB = hash_entry(b, struct pageTable, hashElem);
	return entryA->vPage < entryB->vPage;
}

void pageTableEntryDestroyFunc(struct hash_elem *e, void *aux) {
	struct pageTableEntry *entry = hash_entry(e, struct pageTable, hashElem);
	if (entry->status == FRAME) {
		//TODO: Call Corresponding free function
	} else if (entry->status == SWAP) {
		//TODO: Call Corresponding free function
	}
	free(entry);
}

struct pageTable *createPageTable() {
	struct pageTable *ret = (struct pageTable *) malloc(sizeof(struct pageTable));
	hash_init(&ret->hashTable, pageTableEntryHashFunc, pageTableEntryLessFunc, NULL);
	return ret;
}

void destroyPageTable(struct pageTable *pageTable) {
	hash_destroy(&pageTable->hashTable, pageTableEntryDestroyFunc);
	free(pageTable);
}

pageTableEntry *findPage(struct pageTable *pageTable, void *vPage) {
	struct pageTableEntry *tmp = hash_entry(a, struct pageTable, hashElem);
	tmp->vPage = vPage;
	struct hash_elem *ret = hash_find(&pageTable->hashTable, &tmp->hashElem);
	if (ret != NULL) {
		return hash_entry(ret, struct pageTable, hashElem);
	} else {
		return NULL;
	}
}

bool setFrame(struct pageTable *pageTable, void *vPage, void *phyPage, bool writeable) {
	if (findPage(pageTable, vPage) == NULL) {
		struct pageTableEntry *newEntry = (struct pageTableEntry *) malloc(sizeof(struct pageTableEntry));
		newEntry->vPage = vPage;
		newEntry->phyPage = phyPage;
		newEntry->status = FRAME;
		newEntry->writeable = writeable;
		hash_insert(&pageTable->hashTable, &newEntry->hashElem);
		return true;
	} else {
		return false;
	}
}

bool setPage(struct pageTable *pageTable, void *vPage, void *phyPage, bool writeable, enum pageStatus type) {
	//TODO: Needs lock?
	if (type == FRAME) {
		return setFrame(pageTable, vPage, phyPage, writeable);
	} else if (type == SWAP) {

	} else {

	}
}

bool unMap(struct pageTable *pageTable, void *vPage) {

}
