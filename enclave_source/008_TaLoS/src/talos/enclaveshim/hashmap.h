// from http://www2.informatik.hu-berlin.de/~weber/slipOff/hashmap_h.html

#ifndef HASHMAP_H_INCLUDED
#define HASHMAP_H_INCLUDED

/** Hashmap structure (forward declaration) */
struct s_hashmap;
typedef struct s_hashmap hashmap;

/** Creates a new hashmap near the given size. */
extern hashmap* hashmapCreate(int startsize);

/** Inserts a new element into the hashmap. */
extern void hashmapInsert(hashmap*, const void* data, unsigned long key);

/** Removes the storage for the element of the key and returns the element. */
extern void* hashmapRemove(hashmap*, unsigned long key);

/** Returns the element for the key. */
extern void* hashmapGet(hashmap*, unsigned long key);

/** Returns the number of saved elements. */
extern long hashmapCount(hashmap*);

/** Removes the hashmap structure. */
extern void hashmapDelete(hashmap*);

#endif

