/*-
 * SPDX-License-Identifier: Apache License 2.0
 *
 * Copyright 2019 Yutaro Hayakawa
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

#include "ebpf_platform.h"
#include <sys/ebpf.h>

struct ebpf_env {
	uint32_t ref;
	struct ebpf_config *ec;
};

void ebpf_env_acquire(struct ebpf_env *ee);
void ebpf_env_release(struct ebpf_env *ee);
struct ebpf_prog_type *ebpf_env_get_prog_type(struct ebpf_env *ee, uint32_t type);
struct ebpf_map_type *ebpf_env_get_map_type(struct ebpf_env *ee, uint32_t type);
struct ebpf_helper_type *ebpf_env_get_helper_type(struct ebpf_env *ee, uint32_t type);
struct ebpf_preprocessor *ebpf_env_get_preprocessor(struct ebpf_env *ee);