/*
 * FFI glue for the bcrypt spin package: two functions over the vendored
 * public-domain crypt_blowfish (see crypt_blowfish.c for provenance).
 *
 * Buffer contract: each function returns a pointer into a buffer of the
 * calling OS thread's own (_Thread_local), valid until that thread's
 * next call; the FFI :str return copies it into a GC string on the same
 * thread, at the call boundary. One buffer shared by the whole process
 * would let a thread on another Spinel worker (SPINEL_WORKERS > 1: no
 * GVL) overwrite it between the hash and that copy, handing the caller
 * another thread's digest. Do not declare these ffi_funcs
 * `offload: true`: the function would then run on a pool thread, and the
 * pointer would name that thread's buffer. An error returns "" — the
 * Ruby layer turns that into the gem's typed errors
 * (Errors::InvalidSalt / InvalidSecret).
 */

#include <stdio.h>
#include <stdint.h>

#include "crypt_blowfish.h"

/* $2a$NN$ + 22 base64 chars + NUL, rounded up. */
#define SP_BCRYPT_SALT_SIZE 32
/* 60-char bcrypt output + NUL, rounded up. */
#define SP_BCRYPT_OUT_SIZE 64

const char *sp_bcrypt_hash_secret(const char *key, const char *setting)
{
	static _Thread_local char out[SP_BCRYPT_OUT_SIZE];
	char *r = _crypt_blowfish_rn(key, setting, out, sizeof(out));
	return r ? r : "";
}

const char *sp_bcrypt_gensalt(intptr_t cost)
{
	static _Thread_local char salt[SP_BCRYPT_SALT_SIZE];
	char rnd[16];
	FILE *f = fopen("/dev/urandom", "rb");
	if (!f)
		return "";
	if (fread(rnd, 1, sizeof(rnd), f) != sizeof(rnd)) {
		fclose(f);
		return "";
	}
	fclose(f);
	char *r = _crypt_gensalt_blowfish_rn("$2a$", (unsigned long)cost,
					     rnd, sizeof(rnd),
					     salt, sizeof(salt));
	return r ? r : "";
}
