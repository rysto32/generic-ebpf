/*-
 * SPDX-License-Identifier: Apache License 2.0
 *
 * Copyright 2017-2018 Yutaro Hayakawa
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "ebpf_map.h"
#include "ebpf_internal.h"
#include <sys/ebpf_vm.h>
#include <sys/lock.h>
#include <sys/mutex.h>

struct ebpf_map_array {
	void *array;
};

struct ebpf_map_arrayqueue {
	struct ebpf_map_array array;

	struct mtx lock;
	int pidx; /* Producer Index */
	int cidx; /* Consumer Index */
};

#define ARRAY_MAP(_map) ((struct ebpf_map_array *)(_map->data))

static void
array_map_deinit(struct ebpf_map *map, void *arg)
{
	struct ebpf_map_array *array_map = map->data;

	ebpf_epoch_wait();

	ebpf_free(array_map->array);
	ebpf_free(array_map);
}

static void
array_map_deinit_percpu(struct ebpf_map *map, void *arg)
{
	struct ebpf_map_array *array_map = map->data;

	ebpf_epoch_wait();

	for (uint16_t i = 0; i < ebpf_ncpus(); i++) {
		ebpf_free(array_map[i].array);
	}

	ebpf_free(array_map);
}

static int
array_map_init_common(struct ebpf_map_array *array_map, struct ebpf_map_attr *attr)
{
	if (attr->key_size != sizeof(uint32_t)) {
		return (EINVAL);
	}

	array_map->array = ebpf_calloc(attr->max_entries, attr->value_size);
	if (array_map->array == NULL) {
		return ENOMEM;
	}

	return 0;
}

static int
array_map_init(struct ebpf_map *map, struct ebpf_map_attr *attr)
{
	int error;

	struct ebpf_map_array *array_map =
	    ebpf_calloc(1, sizeof(*array_map));
	if (array_map == NULL) {
		return ENOMEM;
	}

	error = array_map_init_common(array_map, attr);
	if (error != 0) {
		ebpf_free(array_map);
		return error;
	}

	map->data = array_map;
	map->percpu = false;

	return 0;
}

static int
array_map_init_percpu(struct ebpf_map *map, struct ebpf_map_attr *attr)
{
	int error;
	uint16_t ncpus = ebpf_ncpus();

	struct ebpf_map_array *array_map =
	    ebpf_calloc(ncpus, sizeof(*array_map));
	if (array_map == NULL) {
		return ENOMEM;
	}

	uint16_t i;
	for (i = 0; i < ncpus; i++) {
		error = array_map_init_common(array_map + i, attr);
		if (error != 0) {
			goto err0;
		}
	}

	map->data = array_map;
	map->percpu = true;

	return 0;

err0:
	for (uint16_t j = i; j > 0; j--) {
		ebpf_free(array_map[i].array);
	}

	ebpf_free(array_map);

	return error;
}

static void *
array_map_lookup_elem(struct ebpf_map *map, int cpu, void *key)
{
	uint32_t k = *(uint32_t *)key;

	if (k >= map->max_entries) {
		return NULL;
	}

	return (uint8_t *)(ARRAY_MAP(map)->array) + (map->value_size * k);
}

static int
array_map_lookup_elem_from_user(struct ebpf_map *map, int cpu, void *key, void *value)
{
	uint32_t k = *(uint32_t *)key;

	if (k >= map->max_entries) {
		return EINVAL;
	}

	uint8_t *elem =
	    (uint8_t *)(ARRAY_MAP(map)->array) + (map->value_size * k);
	memcpy((uint8_t *)value, elem, map->value_size);

	return 0;
}

static void *
array_map_lookup_elem_percpu(struct ebpf_map *map, int cpu, void *key)
{
	uint32_t k = *(uint32_t *)key;

	if (k >= map->max_entries) {
		return NULL;
	}

	return (uint8_t *)((ARRAY_MAP(map) + cpu)->array) +
	       (map->value_size * k);
}

static int
array_map_lookup_elem_percpu_from_user(struct ebpf_map *map, int cpu, void *key,
				       void *value)
{
	uint32_t k = *(uint32_t *)key;

	if (k >= map->max_entries) {
		return EINVAL;
	}

	uint8_t *elem;
	for (uint32_t i = 0; i < ebpf_ncpus(); i++) {
		elem = (uint8_t *)((ARRAY_MAP(map) + i)->array) +
		       (map->value_size * k);
		memcpy((uint8_t *)value + map->value_size * i, elem,
		       map->value_size);
	}

	return 0;
}

static int
array_map_update_elem_common(struct ebpf_map *map,
			     struct ebpf_map_array *array_map, uint32_t key,
			     void *value, uint64_t flags)
{
	uint8_t *elem = (uint8_t *)array_map->array + (map->value_size * key);

	memcpy(elem, value, map->value_size);

	return 0;
}

static inline int
array_map_update_check_attr(struct ebpf_map *map, void *key, void *value,
			    uint64_t flags)
{
	if (flags & EBPF_NOEXIST) {
		return EEXIST;
	}

	if (*(uint32_t *)key >= map->max_entries) {
		return EINVAL;
	}

	return 0;
}

static int
array_map_update_elem(struct ebpf_map *map, int cpu, void *key, void *value,
		      uint64_t flags)
{
	int error;
	struct ebpf_map_array *array_map = map->data;

	error = array_map_update_check_attr(map, key, value, flags);
	if (error != 0) {
		return error;
	}

	return array_map_update_elem_common(map, array_map, *(uint32_t *)key,
					    value, flags);
}

static int
array_map_update_elem_percpu(struct ebpf_map *map, int cpu, void *key, void *value,
			     uint64_t flags)
{
	int error;
	struct ebpf_map_array *array_map = map->data;

	error = array_map_update_check_attr(map, key, value, flags);
	if (error != 0) {
		return error;
	}

	return array_map_update_elem_common(map, array_map + cpu,
					    *(uint32_t *)key, value, flags);
}

static int
array_map_update_elem_percpu_from_user(struct ebpf_map *map, int cpu, void *key,
				       void *value, uint64_t flags)
{
	int error;
	struct ebpf_map_array *array_map = map->data;

	error = array_map_update_check_attr(map, key, value, flags);
	if (error != 0) {
		return error;
	}

	for (uint16_t i = 0; i < ebpf_ncpus(); i++) {
		array_map_update_elem_common(map, array_map + i,
					     *(uint32_t *)key, value, flags);
	}

	return 0;
}

static int
array_map_delete_elem(struct ebpf_map *map, int cpu, void *key)
{
	return EINVAL;
}

static int
array_map_get_next_key(struct ebpf_map *map, int cpu, void *key, void *next_key)
{
	uint32_t k = key ? *(uint32_t *)key : UINT32_MAX;
	uint32_t *nk = (uint32_t *)next_key;

	if (k >= map->max_entries) {
		*nk = 0;
		return 0;
	}

	if (k == map->max_entries - 1) {
		return ENOENT;
	}

	*nk = k + 1;
	return 0;
}

static int
progarray_map_init(struct ebpf_map *map, struct ebpf_map_attr *attr)
{

	if (attr->value_size != sizeof(int)) {
		return (EINVAL);
	}

	return (array_map_init(map, attr));
}

static int
progarray_map_update_elem(struct ebpf_map *map, int cpu, void *key,
    void *value, uint64_t flags)
{
	int error, fd;
	ebpf_file *fp;
	struct ebpf_map_array *array_map;
	ebpf_thread *td;

	array_map = map->data;
	error = array_map_update_check_attr(map, key, value, flags);
	if (error != 0) {
		return error;
	}

	td = ebpf_curthread();
	fd = *(int*)value;
	fp = NULL;

	/* Test that the FD currently points to a program.*/
	error = ebpf_fd_to_program(td, fd, &fp, NULL);
	if (error != 0) {
		goto out;
	}

	error = array_map_update_elem_common(map, array_map, *(uint32_t *)key,
	    value, flags);
out:
	if (fp != NULL) {
		ebpf_fdrop(fp, td);
	}

	return (error);
}

static int
arrayqueue_init(struct ebpf_map *map, struct ebpf_map_attr *attr)
{
	struct ebpf_map_arrayqueue *queue;
	int error;

	queue = ebpf_calloc(1, sizeof(*queue));
	if (queue == NULL) {
		return (ENOMEM);
	}

	error = array_map_init_common(&queue->array, attr);
	if (error != 0) {
		ebpf_free(queue);
		return error;
	}

	mtx_init(&queue->lock, "ebpf_arrayqueue", NULL, MTX_DEF);
	queue->pidx = 0;
	queue->cidx = 0;

	map->data = queue;
	map->percpu = false;

	return 0;
}

static void
arrayqueue_deinit(struct ebpf_map *map, void *arg)
{
	struct ebpf_map_arrayqueue *queue;

	queue = map->data;

	ebpf_epoch_wait();

	mtx_destroy(&queue->lock);
	ebpf_free(queue->array.array);
	ebpf_free(queue);
}

static __inline int
arrayqueue_isfull(struct ebpf_map *map, struct ebpf_map_arrayqueue *queue)
{
	if (queue->pidx == map->max_entries - 1) {
		return queue->cidx == 0;
	} else {
		return (queue->pidx == (queue->cidx - 1));
	}
}

static __inline int
arrayqueue_isempty(struct ebpf_map *map, struct ebpf_map_arrayqueue *queue)
{

	return queue->cidx == queue->pidx;
}

static __inline void
arrayqueue_idx_incr(struct ebpf_map *map, int *idx)
{
	int i;

	i = *idx + 1;
	if (i != map->max_entries) {
		*idx = i;
	} else {
		*idx = 0;
	}
}

static int
arrayqueue_enqueue(struct ebpf_map *map, int cpu, void *value)
{
	struct ebpf_map_arrayqueue *queue;
	int pidx, error;

	queue = map->data;

	mtx_lock(&queue->lock);
	if (!arrayqueue_isfull(map, queue)) {
		pidx = queue->pidx;
		array_map_update_elem_common(map, &queue->array, pidx, value, 0);
		arrayqueue_idx_incr(map, &queue->pidx);
		wakeup_one(queue);
		error = 0;
	} else {
		error = ENOSPC;
	}
	mtx_unlock(&queue->lock);

	return (error);
}

static int
arrayqueue_dequeue(struct ebpf_map *map, int cpu, void *buf)
{
	struct ebpf_map_arrayqueue *queue;
	struct ebpf_map_array *array;
	uint8_t *elem;
	int cidx, error;

	queue = map->data;

	mtx_lock(&queue->lock);
	if (!arrayqueue_isempty(map, queue)) {
		cidx = queue->cidx;
		array = &queue->array;
		elem = (uint8_t *)(array->array) + (map->value_size * cidx);
		memcpy(buf, elem, map->value_size);

		arrayqueue_idx_incr(map, &queue->cidx);
		error = 0;
	} else {
		error = EWOULDBLOCK;
	}
	mtx_unlock(&queue->lock);

	return (error);
}

struct ebpf_map_type array_map_type = {
	.name = "array",
	.ops = {
		.init = array_map_init,
		.update_elem = array_map_update_elem,
		.lookup_elem = array_map_lookup_elem,
		.delete_elem = array_map_delete_elem,
		.update_elem_from_user = array_map_update_elem,
		.lookup_elem_from_user = array_map_lookup_elem_from_user,
		.delete_elem_from_user = array_map_delete_elem,
		.get_next_key_from_user = array_map_get_next_key,
		.deinit = array_map_deinit
	}
};

struct ebpf_map_type percpu_array_map_type = {
	.name = "percpu_array",
	.ops = {
		.init = array_map_init_percpu,
		.update_elem = array_map_update_elem_percpu,
		.lookup_elem = array_map_lookup_elem_percpu,
		.delete_elem = array_map_delete_elem, // delete is anyway invalid
		.update_elem_from_user = array_map_update_elem_percpu_from_user,
		.lookup_elem_from_user = array_map_lookup_elem_percpu_from_user,
		.delete_elem_from_user = array_map_delete_elem, // delete is anyway invalid
		.get_next_key_from_user = array_map_get_next_key,
		.deinit = array_map_deinit_percpu
	}
};

struct ebpf_map_type progarray_map_type = {
	.name = "progarray",
	.ops = {
		.init = progarray_map_init,
		.update_elem = progarray_map_update_elem,
		.lookup_elem = array_map_lookup_elem,
		.delete_elem = array_map_delete_elem,
		.update_elem_from_user = progarray_map_update_elem,
		.lookup_elem_from_user = array_map_lookup_elem_from_user,
		.delete_elem_from_user = array_map_delete_elem,
		.get_next_key_from_user = array_map_get_next_key,
		.deinit = array_map_deinit
	}
};

struct ebpf_map_type arrayqueue_type = {
	.name = "arrayqueue",
	.ops = {
		.init = arrayqueue_init,
		.update_elem = array_map_update_elem,
		.lookup_elem = array_map_lookup_elem,
		.delete_elem = array_map_delete_elem,
		.update_elem_from_user = array_map_update_elem,
		.lookup_elem_from_user = array_map_lookup_elem_from_user,
		.delete_elem_from_user = array_map_delete_elem,
		.get_next_key_from_user = array_map_get_next_key,
		.enqueue = arrayqueue_enqueue,
		.dequeue = arrayqueue_dequeue,
		.deinit = arrayqueue_deinit
	}
};
