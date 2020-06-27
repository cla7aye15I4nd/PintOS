//
// Created by gabriel on 6/25/20.
//

#ifndef PINTOS_PAGE_H
#define PINTOS_PAGE_H

#include "../lib/kernel/hash.h"

enum pageStatus {
	FRAME, SWAP, FILE
};

struct pageTableEntry {
	struct hash_elem hashElem; //Must contain, see "lib/kernel/hash"

	void *vPage, *phyPage;
	enum pageStatus status;
	bool writeable;
};

struct pageTable {
	struct hash hashTable;
};

//Helper Methods
unsigned pageTableEntryHashFunc(const struct hash_elem *e, void *aux);
bool pageTableEntryLessFunc(const struct hash_elem *a, const struct hash_elem *b, void *aux);
void pageTableEntryDestroyFunc(struct hash_elem *e, void *aux);

//Instantiation and Destruction
struct pageTable *createPageTable();
void destroyPageTable(struct pageTable *pageTable);

//Basic methods of a table
pageTableEntry *findPage(struct pageTable *pageTable, void *vPage);
bool setPage(struct pageTable *pageTable, void *vPage, void *phyPage, bool writeable, enum pageStatus type);

//File Mapping
bool unMap(struct pageTable *pageTable, void *vPage);

//Page Fault Handler


#endif //PINTOS_PAGE_H
