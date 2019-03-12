/* $OpenBSD: ssh-rsa.c,v 1.45 2010/08/31 09:58:37 djm Exp $ */
/*
 * Copyright (c) 2000, 2003 Markus Friedl <markus@openbsd.org>
 * 
 * Copyright 2019 ALE USA Inc.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "includes.h"

#include <sys/types.h>

#include <openssl/evp.h>
#include <openssl/err.h>

#include <stdarg.h>
#include <string.h>

#include "xmalloc.h"
#include "log.h"
#include "buffer.h"
#include "key.h"
#include "compat.h"
#include "misc.h"
#include "ssh.h"

static int openssh_RSA_verify(int, u_char *, u_int, u_char *, u_int, RSA *);

/* RSASSA-PKCS1-v1_5 (PKCS #1 v2.0 signature) with SHA1 */
int
ssh_rsa_sign(const Key *key, u_char **sigp, u_int *lenp,
    const u_char *data, u_int datalen)
{
	const EVP_MD *evp_md;
	EVP_MD_CTX md;
	u_char *sig;
	u_int slen, len;
	int ok, nid;
	Buffer b;
	EVP_PKEY *pkey;

	if (key == NULL || key->rsa == NULL || (key->type != KEY_RSA &&
	    key->type != KEY_RSA_CERT && key->type != KEY_RSA_CERT_V00)) {
		error("ssh_rsa_sign: no RSA key");
		return -1;
	}
	nid = (datafellows & SSH_BUG_RSASIGMD5) ? NID_md5 : NID_sha1;
	if ((evp_md = EVP_get_digestbynid(nid)) == NULL) {
		error("ssh_rsa_sign: EVP_get_digestbynid %d failed", nid);
		return -1;
	}
	pkey = EVP_PKEY_new();
	EVP_PKEY_set1_RSA(pkey, key->rsa);
	slen = EVP_PKEY_size(pkey);
	sig = xmalloc(slen);

	EVP_MD_CTX_init(&md);
	EVP_SignInit_ex(&md, evp_md, NULL);
	EVP_SignUpdate(&md, data, datalen);
	ok = EVP_SignFinal(&md, sig, &len, pkey);
	EVP_MD_CTX_cleanup(&md);
	EVP_PKEY_free(pkey);

	if (ok != 1) {
		int ecode = ERR_get_error();

		error("ssh_rsa_sign: RSA_sign failed: %s",
		    ERR_error_string(ecode, NULL));
		xfree(sig);
		return -1;
	}
	if (len < slen) {
		u_int diff = slen - len;
		debug("slen %u > len %u", slen, len);
		memmove(sig + diff, sig, len);
		memset(sig, 0, diff);
	} else if (len > slen) {
		error("ssh_rsa_sign: slen %u slen2 %u", slen, len);
		xfree(sig);
		return -1;
	}
	/* encode signature */
	buffer_init(&b);
	buffer_put_cstring(&b, "ssh-rsa");
	buffer_put_string(&b, sig, slen);
	len = buffer_len(&b);
	if (lenp != NULL)
		*lenp = len;
	if (sigp != NULL) {
		*sigp = xmalloc(len);
		memcpy(*sigp, buffer_ptr(&b), len);
	}
	buffer_free(&b);
	memset(sig, 's', slen);
	xfree(sig);

	return 0;
}

int
ssh_rsa_verify(const Key *key, const u_char *signature, u_int signaturelen,
    const u_char *data, u_int datalen)
{
	Buffer b;
	const EVP_MD *evp_md;
	EVP_MD_CTX md;
	char *ktype;
	u_char *sigblob;
	u_int len, modlen;
	int rlen, ret, nid;
	EVP_PKEY *pkey;

	if (key == NULL || key->rsa == NULL || (key->type != KEY_RSA &&
	    key->type != KEY_RSA_CERT && key->type != KEY_RSA_CERT_V00)) {
		error("ssh_rsa_verify: no RSA key");
		return -1;
	}
	if (BN_num_bits(key->rsa->n) < SSH_RSA_MINIMUM_MODULUS_SIZE) {
		error("ssh_rsa_verify: RSA modulus too small: %d < minimum %d bits",
		    BN_num_bits(key->rsa->n), SSH_RSA_MINIMUM_MODULUS_SIZE);
		return -1;
	}
	buffer_init(&b);
	buffer_append(&b, signature, signaturelen);
	ktype = buffer_get_cstring(&b, NULL);
	if (strcmp("ssh-rsa", ktype) != 0) {
		error("ssh_rsa_verify: cannot handle type %s", ktype);
		buffer_free(&b);
		xfree(ktype);
		return -1;
	}
	xfree(ktype);
	sigblob = buffer_get_string(&b, &len);
	rlen = buffer_len(&b);
	buffer_free(&b);
	if (rlen != 0) {
		error("ssh_rsa_verify: remaining bytes in signature %d", rlen);
		xfree(sigblob);
		return -1;
	}
	/* RSA_verify expects a signature of RSA_size */
	modlen = RSA_size(key->rsa);
	if (len > modlen) {
		error("ssh_rsa_verify: len %u > modlen %u", len, modlen);
		xfree(sigblob);
		return -1;
	} else if (len < modlen) {
		u_int diff = modlen - len;
		debug("ssh_rsa_verify: add padding: modlen %u > len %u",
		    modlen, len);
		sigblob = xrealloc(sigblob, 1, modlen);
		memmove(sigblob + diff, sigblob, len);
		memset(sigblob, 0, diff);
		len = modlen;
	}
	nid = (datafellows & SSH_BUG_RSASIGMD5) ? NID_md5 : NID_sha1;
	if ((evp_md = EVP_get_digestbynid(nid)) == NULL) {
		error("ssh_rsa_verify: EVP_get_digestbynid %d failed", nid);
		xfree(sigblob);
		return -1;
	}
	pkey = EVP_PKEY_new();
	EVP_PKEY_set1_RSA(pkey, key->rsa);
	EVP_MD_CTX_init(&md);
	EVP_VerifyInit_ex(&md, evp_md, NULL);
	EVP_VerifyUpdate(&md, data, datalen);
	ret = EVP_VerifyFinal(&md, sigblob, len, pkey);
	EVP_MD_CTX_cleanup(&md);
	EVP_PKEY_free(pkey);

	memset(sigblob, 's', len);
	xfree(sigblob);
	debug("ssh_rsa_verify: signature %scorrect", (ret==0) ? "in" : "");
	return ret;
}
