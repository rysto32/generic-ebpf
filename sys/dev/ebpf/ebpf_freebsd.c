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

#include <sys/ebpf.h>
#include <dev/ebpf/ebpf_platform.h>
#include <dev/ebpf/ebpf_internal.h>
#include <dev/ebpf/ebpf_map.h>
#include <dev/ebpf/ebpf_prog.h>

#include <sys/ebpf_probe.h>
#include <sys/exec.h>
#include <sys/imgact.h>
#include <sys/proc.h>
#include <sys/syscallsubr.h>
#include <sys/wait.h>
#include <sys/unistd.h>

MALLOC_DECLARE(M_EBPFBUF);
MALLOC_DEFINE(M_EBPFBUF, "ebpf-buffers", "Buffers for ebpf and its subsystems");

static struct ebpf_module ebpf_mod_callbacks = {
	.fire = ebpf_fire,
};

/*
 * Platform dependent function implementations
 */
__inline void *
ebpf_malloc(size_t size)
{
	return malloc(size, M_EBPFBUF, M_NOWAIT);
}

__inline void *
ebpf_calloc(size_t number, size_t size)
{
	return malloc(number * size, M_EBPFBUF, M_NOWAIT | M_ZERO);
}

__inline void *
ebpf_exalloc(size_t size)
{
	return malloc(size, M_EBPFBUF, M_NOWAIT | M_EXEC);
}

__inline void
ebpf_exfree(void *mem, size_t size)
{
	free(mem, M_EBPFBUF);
}

__inline void
ebpf_free(void *mem)
{
	free(mem, M_EBPFBUF);
}

int
ebpf_error(const char *fmt, ...)
{
	int ret;
	__va_list ap;

	va_start(ap, fmt);
	ret = vprintf(fmt, ap);
	va_end(ap);

	return ret;
}

__inline uint16_t
ebpf_ncpus(void)
{
	return mp_maxid + 1;
}

__inline uint16_t
ebpf_curcpu(void)
{
	return curcpu;
}

__inline long
ebpf_getpagesize(void)
{
	return PAGE_SIZE;
}

static epoch_t ebpf_epoch;

__inline void
ebpf_epoch_enter(void)
{
	epoch_enter(ebpf_epoch);
}

__inline void
ebpf_epoch_exit(void)
{
	epoch_exit(ebpf_epoch);
}

__inline void
ebpf_epoch_call(ebpf_epoch_context *ctx,
		void (*callback)(ebpf_epoch_context *))
{
	epoch_call(ebpf_epoch, ctx, callback);
}

__inline void
ebpf_epoch_wait(void)
{
	epoch_wait(ebpf_epoch);
}

__inline void
ebpf_mtx_init(ebpf_mtx *mutex, const char *name)
{
	mtx_init(mutex, name, NULL, MTX_DEF);
}

__inline void
ebpf_mtx_lock(ebpf_mtx *mutex)
{
	mtx_lock(mutex);
}

__inline void
ebpf_mtx_unlock(ebpf_mtx *mutex)
{
	mtx_unlock(mutex);
}

__inline void
ebpf_mtx_destroy(ebpf_mtx *mutex)
{
	mtx_destroy(mutex);
}

__inline void
ebpf_spinmtx_init(ebpf_spinmtx *mutex, const char *name)
{
	mtx_init(mutex, name, NULL, MTX_SPIN);
}

__inline void
ebpf_spinmtx_lock(ebpf_spinmtx *mutex)
{
	mtx_lock_spin(mutex);
}

__inline void
ebpf_spinmtx_unlock(ebpf_spinmtx *mutex)
{
	mtx_unlock_spin(mutex);
}

__inline void
ebpf_spinmtx_destroy(ebpf_spinmtx *mutex)
{
	mtx_destroy(mutex);
}

__inline void
ebpf_refcount_init(uint32_t *count, uint32_t value)
{
	refcount_init(count, value);
}

__inline void
ebpf_refcount_acquire(uint32_t *count)
{
	refcount_acquire(count);
}

__inline int
ebpf_refcount_release(uint32_t *count)
{
	return refcount_release(count);
}

__inline uint32_t
ebpf_jenkins_hash(const void *buf, size_t len, uint32_t hash)
{
	return jenkins_hash(buf, len, hash);
}

int
ebpf_init(void)
{
	ebpf_epoch = epoch_alloc(0);
	ebpf_module_register(&ebpf_mod_callbacks);
	return 0;
}

int
ebpf_deinit(void)
{
	ebpf_module_deregister();
	epoch_free(ebpf_epoch);
	return 0;
}

int
ebpf_fd_to_program(ebpf_thread *td, int fd, ebpf_file **fp_out, struct ebpf_prog **prog_out)
{
	int error;
	ebpf_file *fp;
	struct ebpf_obj_prog *prog;
	struct ebpf_obj *obj;

	error = ebpf_fget(td, fd, &fp);
	if (error != 0) {
		return (error);
	}

	if (!is_ebpf_objfile(fp)) {
		error = EINVAL;
		goto out;
	}

	obj = EBPF_OBJ(fp);
	if (obj->type != EBPF_OBJ_TYPE_PROG) {
		error = EINVAL;
		goto out;
	}

	prog = ebpf_obj_container_of(obj);

	*fp_out = fp;
	if (prog_out) {
		*prog_out = &prog->prog;
	}

	return (0);

out:
	if (fp != NULL) {
		ebpf_fdrop(fp, td);
	}

	return (error);
}

int
ebpf_probe_copyinstr(struct ebpf_vm_state *s, const void *uaddr, void *kaddr, size_t len, size_t *done)
{
	int error;

	error = copyinstr(uaddr, kaddr, len, done);
	curthread->td_errno = error;

	return (error);
}

int
ebpf_probe_copyout(struct ebpf_vm_state *s, const void *kaddr, void *uaddr, size_t len)
{
	int error;

	error = copyout(kaddr, uaddr, len);
	curthread->td_errno = error;

	return (error);
}

int
ebpf_probe_dup(struct ebpf_vm_state *s, int fd)
{
	struct thread *td;
	int error;

	td = curthread;
	error = kern_dup(td, FDDUP_NORMAL, 0, fd, 0);
	td->td_errno = error;

	/* Return the file descriptor. */
	return (td->td_retval[0]);
}

int
ebpf_probe_openat(struct ebpf_vm_state *s, int fd, const char * path, int flags, int mode)
{
	struct thread *td;
	int error;

	td = curthread;
	error = kern_openat(td, fd, path, UIO_SYSSPACE, flags, mode);
	td->td_errno = error;

	/* Return the file descriptor. */
	return (td->td_retval[0]);
}

int
ebpf_probe_fstatat(struct ebpf_vm_state *s, int fd, const char *path, struct stat *sb, int flag)
{
	struct thread *td;
	int error;

	td = curthread;

	error = kern_statat(curthread, flag, fd, path, UIO_SYSSPACE, sb, NULL);
	td->td_errno = error;

	return (error);
}

int
ebpf_probe_fstat(struct ebpf_vm_state *s, int fd, struct stat *sb)
{
	struct thread *td;
	int error;

	td = curthread;

	error = kern_fstat(curthread, fd, sb);
	td->td_errno = error;

	return (error);
}

int
ebpf_probe_faccessat(struct ebpf_vm_state *s, int fd, const char *path, int mode, int flag)
{
	struct thread *td;
	int error;

	td = curthread;
	error = kern_accessat(curthread, fd, path, UIO_SYSSPACE, flag, mode);
	td->td_errno = error;

	return (error);
}

int
ebpf_probe_set_errno(struct ebpf_vm_state *s, int error)
{

	curthread->td_errno = error;
	return (0);
}

int
ebpf_probe_set_syscall_retval(struct ebpf_vm_state *s, int ret0, int ret1)
{
	struct thread *td;

	td = curthread;
	td->td_retval[0] = ret0;
	td->td_retval[1] = ret1;
	return (0);
}


pid_t
ebpf_probe_pdfork(struct ebpf_vm_state *s, int *fd, int flags)
{
	struct thread *td;
	struct fork_req fr;
	int error, pid;

	bzero(&fr, sizeof(fr));
	fr.fr_flags = RFFDG | RFPROC | RFPROCDESC;
	fr.fr_pidp = &pid;
	fr.fr_pd_fd = fd;
	fr.fr_pd_flags = flags;

	td = curthread;
	error = fork1(td, &fr);
	td->td_errno = error;

	if (error == 0) {
		return (pid);
	} else {
		return (-1);
	}
}

static int
ebpf_probe_do_pdwait(int fd, int* status, int options, struct rusage *ru)
{
	int error;
	struct thread *td;

	td = curthread;
	error = kern_pdwait4(td, fd, status, options, ru);
	td->td_errno = error;

	return (error);
}

int
ebpf_probe_pdwait4_nohang(struct ebpf_vm_state *s, int fd, int* status, int options, struct rusage *ru)
{

	/*
	 * We cannot block here as the process that we block on could block on
	 * us holding the ebpf state lock, leading to a deadlock.
	 */
	options |= WNOHANG;

	return (ebpf_probe_do_pdwait(fd, status, options, ru));
}

static void
ebpf_probe_do_deferred_pdwait4(struct ebpf_vm_state *s)
{
	int error, status;

	error = ebpf_probe_do_pdwait(s->scratch.wait4.fd, &status,
	    s->scratch.wait4.options, &s->scratch.wait4.rusage);

	s->next_vm_args[0] = (uintptr_t)s->scratch.wait4.arg;
	s->next_vm_args[1] = error;
	s->next_vm_args[2] = status;
	s->next_vm_args[3] = (uintptr_t)&s->scratch.wait4.rusage;
	s->num_args = 4;
}

int
ebpf_probe_pdwait4_defer(struct ebpf_vm_state *s, int fd, int options, void *arg,
    int *prog_fd)
{
	struct ebpf_prog *prog;
	int error;

	if (prog_fd == NULL) {
		curthread->td_errno = ENOENT;
		return ENOENT;
	}

	error = ebpf_fd_to_program(ebpf_curthread(), *prog_fd, &s->vm_fp, &prog);
	if (error != 0) {
		curthread->td_errno = error;
		return (error);
	}

	s->scratch.wait4.fd = fd;
	s->scratch.wait4.options = options;
	s->scratch.wait4.arg = arg;

	s->next_vm = prog->vm;
	s->deferred_func = ebpf_probe_do_deferred_pdwait4;
	return 0;
}

/*
 * XXX a comment in kern_exec.c claims that kern_execve can call exit1() and
 * fail to return.  If this happens we will leak EBPF locks.
 */
int
ebpf_probe_fexecve(struct ebpf_vm_state *s, int fd, char ** argv,
    char ** envp, char ** argv_prepend)
{
	struct thread *td;
	struct image_args args;
	struct vmspace *oldvmspace;
	int error;

	td = ebpf_curthread();

	error = pre_execve(td, &oldvmspace);
	if (error != 0) {
		td->td_errno = error;
		return (error);
	}

	error = exec_copyin_args_prepend(&args, NULL, UIO_SYSSPACE,
	    argv, envp, argv_prepend);
	if (error != 0) {
		td->td_errno = error;
		return (error);
	}

	args.fd = fd;
	error = kern_execve(td, &args, NULL);
	td->td_errno = error;

	post_execve(td, error, oldvmspace);
	return (error);
}

int
ebpf_probe_readlinkat(struct ebpf_vm_state *s, int fd, const char *path,
    char *buf, size_t bufsize)
{
	struct thread *td;
	int error;

	td = ebpf_curthread();
	error = kern_readlinkat(td, fd, path, UIO_SYSSPACE, buf, UIO_SYSSPACE, bufsize);
	td->td_errno = error;

	return (error);
}

void *
ebpf_probe_memset(struct ebpf_vm_state *s, void *mem , int c, size_t size)
{

	return (memset(mem, c, size));
}

int
ebpf_probe_exec_get_interp(struct ebpf_vm_state *s, int fd, char *buf,
    size_t bufsize, int *type)
{
	struct thread *td;
	int error;

	td = ebpf_curthread();
	error = exec_get_interp(td, fd, buf, bufsize, type);
	td->td_errno = error;

	return (error);
}

int
ebpf_probe_strncmp(struct ebpf_vm_state *s, const char *a, const char *b,
    size_t len)
{

	return (strncmp(a, b, len));
}

/*
 * Kernel module operations
 */
static int
ebpf_loader(__unused struct module *module, int event, __unused void *arg)
{
	int error = 0;

	switch (event) {
	case MOD_LOAD:
		error = ebpf_init();
		break;
	case MOD_UNLOAD:
		error = ebpf_deinit();
		break;
	default:
		error = EOPNOTSUPP;
		break;
	}

	return (error);
}

DEV_MODULE(ebpf, ebpf_loader, NULL);
MODULE_VERSION(ebpf, 1);
