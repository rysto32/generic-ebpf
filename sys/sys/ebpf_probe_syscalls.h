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

#pragma once
#include <sys/ebpf_uapi.h>

static EBPF_FUNC(int, copyinstr, const void *uaddr, void *kaddr, size_t len, size_t *done);
static EBPF_FUNC(int, copyout, const void *, void *, size_t);
static EBPF_FUNC(int, dup, int fd);
static EBPF_FUNC(int, openat, int fd, const char * path, int flags, int mode);
static EBPF_FUNC(int, fstat, int fd, struct stat *sb);
static EBPF_FUNC(int, fstatat, int fd, const char *path, struct stat *sb, int flag);
static EBPF_FUNC(int, faccessat, int fd, const char *path, int mode, int flag);
static EBPF_FUNC(int, set_errno, int);
static EBPF_FUNC(int, set_syscall_retval, int, int);
static EBPF_FUNC(pid_t, pdfork, int *, int);
static EBPF_FUNC(int, pdwait4_nohang, int, int*, int, struct rusage *);