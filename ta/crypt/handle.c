// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014, Linaro Limited
 */

#include <tee_internal_api.h>
#include "handle.h"

/*
 * Define the initial capacity of the database. It should be a low number
 * multiple of 2 since some databases a likely to only use a few handles.
 * Since the algorithm doubles up when growing it shouldn't cause a
 * noticeable overhead on large databases.
 */
#define HANDLE_DB_INITIAL_MAX_PTRS	4

void handle_db_destroy(struct handle_db *db)
{
	if (db) {
		TEE_Free(db->ptrs);
		db->ptrs = NULL;
		db->max_ptrs = 0;
	}
}

int handle_get(struct handle_db *db, void *ptr)
{
	size_t n;
	void *p;
	size_t new_max_ptrs;

	if (!db || !ptr)
		return -1;

	/* Try to find an empty location */
	for (n = 0; n < db->max_ptrs; n++) {
		if (!db->ptrs[n]) {
			db->ptrs[n] = ptr;
			return n;
		}
	}

	/* No location available, grow the ptrs array */
	if (db->max_ptrs)
		new_max_ptrs = db->max_ptrs * 2;
	else
		new_max_ptrs = HANDLE_DB_INITIAL_MAX_PTRS;
	p = TEE_Realloc(db->ptrs, new_max_ptrs * sizeof(void *));
	if (!p)
		return -1;
	db->ptrs = p;
	TEE_MemFill(db->ptrs + db->max_ptrs, 0,
		    (new_max_ptrs - db->max_ptrs) * sizeof(void *));
	db->max_ptrs = new_max_ptrs;

	/* Since n stopped at db->max_ptrs there is an empty location there */
	db->ptrs[n] = ptr;
	return n;
}

void *handle_put(struct handle_db *db, int handle)
{
	void *p;

	if (!db || handle < 0 || (size_t)handle >= db->max_ptrs)
		return NULL;

	p = db->ptrs[handle];
	db->ptrs[handle] = NULL;
	return p;
}

void *handle_lookup(struct handle_db *db, int handle)
{
	if (!db || handle < 0 || (size_t)handle >= db->max_ptrs)
		return NULL;

	return db->ptrs[handle];
}
