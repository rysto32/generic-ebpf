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

#include "ebpf_obj.h"

void *
ebpf_obj_container_of(struct ebpf_obj *obj)
{
	if (obj == NULL) {
		return NULL;
	}

	switch (obj->type) {
	case EBPF_OBJ_TYPE_PROG:
		return (uint8_t *)obj -
		       __builtin_offsetof(struct ebpf_obj_prog, obj);
	case EBPF_OBJ_TYPE_MAP:
		return (uint8_t *)obj -
		       __builtin_offsetof(struct ebpf_obj_map, obj);
	default:
		return NULL;
	}
}

void *
ebpf_objfile_get_container(ebpf_file *fp)
{
	if (fp == NULL) {
		return NULL;
	}

	if (!is_ebpf_objfile(fp)) {
		return NULL;
	}

	struct ebpf_obj *obj = EBPF_OBJ(fp);
	if (obj == NULL) {
		return NULL;
	}

	return ebpf_obj_container_of(obj);
}

void
ebpf_obj_delete(struct ebpf_obj *obj, ebpf_thread *td)
{
	if (obj == NULL) {
		return;
	}

	if (obj->type == EBPF_OBJ_TYPE_PROG) {
		struct ebpf_obj_prog *prog;
		prog = (struct ebpf_obj_prog *)ebpf_obj_container_of(obj);
		if (prog == NULL) {
			return;
		}

		ebpf_prog_deinit(&prog->prog, NULL);
		for (int i = 0; i < EBPF_PROG_MAX_ATTACHED_MAPS; i++) {
			if (prog->attached_maps[i] != NULL) {
				ebpf_fdrop(prog->attached_maps[i]->obj.f, td);
			}
		}

		ebpf_free(prog);
	} else if (obj->type == EBPF_OBJ_TYPE_MAP) {
		struct ebpf_map *map;
		map = (struct ebpf_map *)ebpf_obj_container_of(obj);
		if (map == NULL) {
			return;
		}
		ebpf_map_deinit_default(map, NULL);
		ebpf_free(map);
	}
}
