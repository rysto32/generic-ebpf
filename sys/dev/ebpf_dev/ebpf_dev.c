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

#include "ebpf_dev_platform.h"
#include <dev/ebpf/ebpf_internal.h>
#include <dev/ebpf/ebpf_map.h>
#include <dev/ebpf/ebpf_prog_test.h>

#include <sys/ebpf.h>
#include <sys/ebpf_vm.h>
#include <sys/ebpf_dev.h>
#include <sys/ebpf_probe.h>

static int
has_null_term(const char * str, int max)
{
	int i;

	for (i = 0; i < max; ++i) {
		if (str[i] == '\0')
			return (1);
	}

	return (0);
}

static void
ebpf_dev_prog_deinit(struct ebpf_prog *self, void *arg)
{
// 	struct ebpf_obj_prog *prog = (struct ebpf_obj_prog *)self;
// 	ebpf_thread *td = (ebpf_thread *)arg;
// 	ebpf_obj_delete(&prog->obj, td);
// 	ebpf_fdrop(prog->obj.f, td);
}

static void
ebpf_dev_map_deinit(struct ebpf_map *self, void *arg)
{
// 	struct ebpf_obj_map *map = (struct ebpf_obj_map *)self;
// 	ebpf_thread *td = (ebpf_thread *)arg;
// 	ebpf_obj_delete(&map->obj, td);
// 	ebpf_fdrop(map->obj.f, td);
}

static int
ebpf_prog_mapfd_to_addr(struct ebpf_obj_prog *prog_obj, ebpf_thread *td)
{
	int error;
	struct ebpf_inst *prog = prog_obj->prog.prog, *cur;
	uint16_t num_insts = prog_obj->prog.prog_len / sizeof(struct ebpf_inst);
	ebpf_file *f;
	struct ebpf_obj_map *map;

	for (uint32_t i = 0; i < num_insts; i++) {
		cur = prog + i;

		if (cur->opcode != EBPF_OP_LDDW) {
			continue;
		}

		if (i == num_insts - 1 || cur[1].opcode != 0 ||
		    cur[1].dst != 0 || cur[1].src != 0 || cur[1].offset != 0) {
			error = EINVAL;
			goto err0;
		}

		// Normal lddw
		if (cur->src == 0) {
			continue;
		}

		if (cur->src != EBPF_PSEUDO_MAP_DESC) {
			error = EINVAL;
			goto err0;
		}

		error = ebpf_fget(td, cur->imm, &f);
		if (error != 0) {
			goto err0;
		}

		map = ebpf_objfile_get_container(f);
		if (map == NULL) {
			error = EINVAL;
			goto err1;
		}

		if (prog_obj->nattached_maps == EBPF_PROG_MAX_ATTACHED_MAPS) {
			error = E2BIG;
			goto err1;
		}

		cur[0].imm = (uint32_t)map;
		cur[1].imm = ((uint64_t)map) >> 32;

		for (int j = 0; j < EBPF_PROG_MAX_ATTACHED_MAPS; j++) {
			if (prog_obj->attached_maps[j] != NULL) {
				if (prog_obj->attached_maps[j] == map) {
					ebpf_fdrop(f, td);
					break;
				}
			} else {
				prog_obj->attached_maps[j] = map;
				prog_obj->nattached_maps++;
				break;
			}
		}

		i++;
	}

	return 0;

err1:
	ebpf_fdrop(f, td);
err0:
	for (int i = 0; i < EBPF_PROG_MAX_ATTACHED_MAPS; i++) {
		if (prog_obj->attached_maps[i] != NULL) {
			ebpf_fdrop(f, td);
			prog_obj->attached_maps[i] = NULL;
		} else {
			break;
		}
	}

	return error;
}

static int
ebpf_ioc_load_prog(union ebpf_req *req, ebpf_thread *td)
{
	int error;
	struct ebpf_obj_prog *prog;
	struct ebpf_inst *insts;

	if (req == NULL || req->prog_fdp == NULL ||
			req->prog_type >= EBPF_PROG_TYPE_MAX ||
	    req->prog == NULL || req->prog_len == 0 ||
	    td == NULL) {
		return EINVAL;
	}

	insts = ebpf_malloc(req->prog_len);
	if (insts == NULL) {
		return ENOMEM;
	}

	error = ebpf_copyin(req->prog, insts, req->prog_len);
	if (error != 0) {
		ebpf_free(insts);
		return error;
	}

	prog = ebpf_calloc(sizeof(*prog), 1);
	if (prog == NULL) {
		ebpf_free(insts);
		return ENOMEM;
	}

	struct ebpf_prog_attr attr = {
		.type = req->prog_type,
		.prog = insts,
		.prog_len = req->prog_len
	};

	error = ebpf_prog_init(&prog->prog, &attr);
	if (error != 0) {
		ebpf_free(insts);
		ebpf_free(prog);
		return error;
	}

	error = ebpf_prog_mapfd_to_addr(prog, td);
	if (error != 0) {
		ebpf_prog_deinit(&prog->prog, td);
		ebpf_free(insts);
		ebpf_free(prog);
		return error;
	}

	int fd;
	ebpf_file *f;

	error = ebpf_fopen(td, &f, &fd, &prog->obj);
	if (error != 0) {
		ebpf_prog_deinit(&prog->prog, td);
		ebpf_free(insts);
		ebpf_free(prog);
		return error;
	}

	prog->obj.f = f;
	prog->obj.type = EBPF_OBJ_TYPE_PROG;

	// set destructor after object bounded to file
// 	prog->prog.deinit = ebpf_dev_prog_deinit;

	error = ebpf_copyout(&fd, req->prog_fdp, sizeof(int));
	if (error != 0) {
		ebpf_prog_deinit(&prog->prog, td);
		ebpf_free(insts);
		return error;
	}

	ebpf_free(insts);

	return 0;
}

static int
ebpf_ioc_map_create(union ebpf_req *req, ebpf_thread *td)
{
	int error;
	struct ebpf_obj_map *map;

	if (req == NULL || req->map_fdp == NULL || td == NULL) {
		return EINVAL;
	}

	map = ebpf_malloc(sizeof(*map));
	if (map == NULL) {
		return ENOMEM;
	}

	struct ebpf_map_attr attr = {
		.type = req->map_type,
		.key_size = req->key_size,
		.value_size = req->value_size,
		.max_entries = req->max_entries,
		.flags = req->map_flags
	};

	error = ebpf_map_init(&map->map, &attr);
	if (error != 0) {
		ebpf_free(map);
		return error;
	}

	int fd;
	ebpf_file *f;

	error = ebpf_fopen(td, &f, &fd, &map->obj);
	if (error != 0) {
		ebpf_map_deinit(&map->map, td);
		ebpf_free(map);
		return error;
	}

	map->obj.f = f;
	map->obj.type = EBPF_OBJ_TYPE_MAP;

	// set destructor after object bounded to file
// 	map->map.deinit = ebpf_dev_map_deinit;

	error = ebpf_copyout(&fd, req->map_fdp, sizeof(int));
	if (error != 0) {
		ebpf_map_deinit(&map->map, td);
		return error;
	}

	return 0;
}

static int
ebpf_ioc_map_lookup_elem(union ebpf_req *req, ebpf_thread *td)
{
	int error;
	ebpf_file *f;

	if (req == NULL || td == NULL || (void *)req->key == NULL ||
			(void *)req->value == NULL) {
		return EINVAL;
	}

	error = ebpf_fget(td, req->map_fd, &f);
	if (error != 0) {
		return error;
	}

	void *k, *v;
	struct ebpf_obj_map *map = ebpf_objfile_get_container(f);
	if (map == NULL) {
		return EINVAL;
	}

	k = ebpf_malloc(map->map.key_size);
	if (k == NULL) {
		error = ENOMEM;
		goto err0;
	}

	error = ebpf_copyin((void *)req->key, k, map->map.key_size);
	if (error != 0) {
		goto err1;
	}

	uint32_t ncpus = ebpf_ncpus();
	if (map->map.percpu) {
		v = ebpf_calloc(ncpus, map->map.value_size);
		if (v == NULL) {
			error = ENOMEM;
			goto err1;
		}
	} else {
		v = ebpf_calloc(1, map->map.value_size);
		if (v == NULL) {
			error = ENOMEM;
			goto err1;
		}
	}

	error = ebpf_map_lookup_elem_from_user(&map->map, k, v);
	if (error != 0) {
		goto err2;
	}

	if (map->map.percpu) {
		error = ebpf_copyout(v, (void *)req->value,
				     map->map.value_size * ncpus);
	} else {
		error =
		    ebpf_copyout(v, (void *)req->value, map->map.value_size);
	}

err2:
	ebpf_free(v);
err1:
	ebpf_free(k);
err0:
	ebpf_fdrop(f, td);
	return error;
}

static int
ebpf_ioc_map_update_elem(union ebpf_req *req, ebpf_thread *td)
{
	int error;
	ebpf_file *f;

	if (req == NULL || td == NULL || (void *)req->key == NULL ||
			(void *)req->value == NULL) {
		return EINVAL;
	}

	error = ebpf_fget(td, req->map_fd, &f);
	if (error != 0) {
		return error;
	}

	void *k, *v;
	struct ebpf_obj_map *map = ebpf_objfile_get_container(f);
	if (map == NULL) {
		return EINVAL;
	}

	k = ebpf_malloc(map->map.key_size);
	if (k == NULL) {
		error = ENOMEM;
		goto err0;
	}

	error = ebpf_copyin((void *)req->key, k, map->map.key_size);
	if (error != 0) {
		goto err1;
	}

	v = ebpf_malloc(map->map.value_size);
	if (v == NULL) {
		error = ENOMEM;
		goto err1;
	}

	error = ebpf_copyin((void *)req->value, v, map->map.value_size);
	if (error != 0) {
		goto err2;
	}

	error = ebpf_map_update_elem_from_user(&map->map, k, v, req->flags);
	if (error != 0) {
		goto err2;
	}

	ebpf_free(k);
	ebpf_free(v);
	ebpf_fdrop(f, td);

	return 0;

err2:
	ebpf_free(v);
err1:
	ebpf_free(k);
err0:
	ebpf_fdrop(f, td);
	return error;
}

static int
ebpf_ioc_map_delete_elem(union ebpf_req *req, ebpf_thread *td)
{
	int error;
	ebpf_file *f;

	if (req == NULL || td == NULL || (void *)req->key == NULL) {
		return EINVAL;
	}

	error = ebpf_fget(td, req->map_fd, &f);
	if (error != 0) {
		return error;
	}

	void *k;
	struct ebpf_obj_map *map = ebpf_objfile_get_container(f);
	if (map == NULL) {
		return EINVAL;
	}

	k = ebpf_malloc(map->map.key_size);
	if (k == NULL) {
		error = ENOMEM;
		goto err0;
	}

	error = ebpf_copyin((void *)req->key, k, map->map.key_size);
	if (error != 0) {
		goto err1;
	}

	error = ebpf_map_delete_elem_from_user(&map->map, k);

err1:
	ebpf_free(k);
err0:
	ebpf_fdrop(f, td);
	return error;
}

static int
ebpf_ioc_map_get_next_key(union ebpf_req *req, ebpf_thread *td)
{
	int error;
	ebpf_file *f;

	/*
	 * key == NULL is valid, because it means "give me a first key"
	 */
	if (req == NULL || td == NULL ||
			(void *)req->next_key == NULL) {
		return EINVAL;
	}

	error = ebpf_fget(td, req->map_fd, &f);
	if (error != 0) {
		return error;
	}

	void *k = NULL, *nk;
	struct ebpf_obj_map *map = ebpf_objfile_get_container(f);
	if (map == NULL) {
		return EINVAL;
	}

	if (req->key != NULL) {
		k = ebpf_malloc(map->map.key_size);
		if (k == NULL) {
			error = ENOMEM;
			goto err0;
		}

		error = ebpf_copyin((void *)req->key, k, map->map.key_size);
		if (error != 0) {
			goto err1;
		}
	}

	nk = ebpf_malloc(map->map.key_size);
	if (nk == NULL) {
		error = ENOMEM;
		goto err1;
	}

	error = ebpf_map_get_next_key_from_user(&map->map, k, nk);
	if (error != 0) {
		goto err2;
	}

	error = ebpf_copyout(nk, (void *)req->next_key, map->map.key_size);

err2:
	ebpf_free(nk);
err1:
	if (k) {
		ebpf_free(k);
	}
err0:
	ebpf_fdrop(f, td);
	return error;
}

static int
ebpf_ioc_run_test(union ebpf_req *req, ebpf_thread *td)
{
	int error;

	ebpf_file *f;
	error = ebpf_fget(td, req->prog_fd, &f);
	if (error != 0) {
		return error;
	}

	struct ebpf_obj_prog *prog_obj = ebpf_objfile_get_container(f);
	if (prog_obj == NULL) {
		error = EINVAL;
		goto err0;
	}

	void *ctx = ebpf_calloc(req->ctx_len, 1);
	if (ctx == NULL) {
		error = ENOMEM;
		goto err0;
	}

	error = ebpf_copyin(req->ctx, ctx, req->ctx_len);
	if (error != 0) {
		goto err1;
	}

	uint64_t result;
	error = ebpf_run_test(prog_obj->prog.prog, prog_obj->prog.prog_len,
			ctx, req->ctx_len, req->jit, &result);
	if (error != 0) {
		goto err1;
	}

	error = ebpf_copyout(&result, req->test_result, sizeof(uint64_t));

err1:
	ebpf_free(ctx);
err0:
	ebpf_fdrop(f, td);
	return error;
}

static int
ebpf_ioc_get_map_type_info(union ebpf_req *req)
{
	int error;
	if (req->mt_id >= EBPF_MAP_TYPE_MAX) {
		return EINVAL;
	}

	struct ebpf_map_type_info *info = ebpf_malloc(sizeof(*info));
	if (info == NULL) {
		return ENOMEM;
	}

	const struct ebpf_map_type *type = ebpf_get_map_type(req->mt_id);
	if (type == NULL) {
		error = ENOENT;
		goto err0;
	}

	memcpy(info->name, type->name, EBPF_NAME_MAX);

	error = ebpf_copyout(info, req->mt_info, sizeof(*info));

err0:
	ebpf_free(info);
	return error;
}

static int
ebpf_ioc_get_prog_type_info(union ebpf_req *req)
{
	int error;
	if (req->pt_id >= EBPF_PROG_TYPE_MAX) {
		return EINVAL;
	}

	struct ebpf_prog_type_info *info = ebpf_malloc(sizeof(*info));
	if (info == NULL) {
		return ENOMEM;
	}

	const struct ebpf_prog_type *type = ebpf_get_prog_type(req->pt_id);
	if (type == NULL) {
		error = ENOENT;
		goto err0;
	}

	memcpy(info->name, type->name, EBPF_NAME_MAX);

	error = ebpf_copyout(info, req->pt_info, sizeof(*info));
	if (error != 0) {
		goto err0;
	}

err0:
	ebpf_free(info);
	return error;
}

static int
ebpf_attach(union ebpf_req *req, ebpf_thread *td)
{
	struct ebpf_req_attach *attach;
	struct ebpf_probe * probe;
	ebpf_file *f;
	struct ebpf_obj_prog *prog_obj;
	int error;

	attach = &req->attach;

	if (!has_null_term(attach->probe_name, sizeof(attach->probe_name))) {
		return (EINVAL);
	}

	probe = ebpf_find_probe(attach->probe_name);
	if (probe == NULL) {
		return (ENOENT);
	}

	error = ebpf_fget(td, attach->prog_fd, &f);
	if (error != 0) {
		return error;
	}

	prog_obj = ebpf_objfile_get_container(f);
	if (prog_obj == NULL) {
		error = EINVAL;
		goto err0;
	}

	ebpf_probe_attach(probe, &prog_obj->prog, attach->jit);
	error = 0;

err0:
	ebpf_fdrop(f, td);
	return (error);
}

int
ebpf_ioctl(uint32_t cmd, void *data, ebpf_thread *td)
{
	int error;
	union ebpf_req *req = (union ebpf_req *)data;

	if (data == NULL || td == NULL) {
		return EINVAL;
	}

	switch (cmd) {
	case EBPFIOC_LOAD_PROG:
		error = ebpf_ioc_load_prog(req, td);
		break;
	case EBPFIOC_MAP_CREATE:
		error = ebpf_ioc_map_create(req, td);
		break;
	case EBPFIOC_MAP_LOOKUP_ELEM:
		error = ebpf_ioc_map_lookup_elem(req, td);
		break;
	case EBPFIOC_MAP_UPDATE_ELEM:
		error = ebpf_ioc_map_update_elem(req, td);
		break;
	case EBPFIOC_MAP_DELETE_ELEM:
		error = ebpf_ioc_map_delete_elem(req, td);
		break;
	case EBPFIOC_MAP_GET_NEXT_KEY:
		error = ebpf_ioc_map_get_next_key(req, td);
		break;
	case EBPFIOC_RUN_TEST:
		error = ebpf_ioc_run_test(req, td);
		break;
	case EBPFIOC_GET_MAP_TYPE_INFO:
		error = ebpf_ioc_get_map_type_info(req);
		break;
	case EBPFIOC_GET_PROG_TYPE_INFO:
		error = ebpf_ioc_get_prog_type_info(req);
		break;
	case EBPFIOC_ATTACH_PROBE:
		error = ebpf_attach(req, td);
		break;
	default:
		error = EINVAL;
		break;
	}

	return error;
}
