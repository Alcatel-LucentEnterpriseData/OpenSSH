/* $OpenBSD: ssh-dss.c,v 1.27 2010/08/31 09:58:37 djm Exp $ */
/*
 * Copyright (c) 2000 Markus Friedl.  All rights reserved.
 *
 * Copyright 2019 ALE USA Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "includes.h"

#include <sys/types.h>

#include <openssl/bn.h>
#include <openssl/evp.h>

#include <stdarg.h>
#include <string.h>

#include "xmalloc.h"
#include "buffer.h"
#include "compat.h"
#include "log.h"
#include "key.h"

#define INTBLOB_LEN	20
#define SIGBLOB_LEN	(2*INTBLOB_LEN)

int
ssh_dss_sign(const Key *key, u_char **sigp, u_int *lenp,
    const u_char *data, u_int datalen)
{
	DSA_SIG *sig;
	const EVP_MD *evp_md = EVP_dss1();
	EVP_MD_CTX md;
	u_char sigblob[SIGBLOB_LEN];
	u_int rlen, slen, len;
	Buffer b;
	u_char *tsig;
	const u_char *psig;
	EVP_PKEY *pkey;
	int ok;

	if (key == NULL || key->dsa == NULL || (key->type != KEY_DSA &&
	    key->type != KEY_DSA_CERT && key->type != KEY_DSA_CERT_V00)) {
		error("ssh_dss_sign: no DSA key");
		return -1;
	}
	pkey = EVP_PKEY_new();
	EVP_PKEY_set1_DSA(pkey, key->dsa);
	slen = EVP_PKEY_size(pkey);
	tsig = xmalloc(slen);

	EVP_MD_CTX_init(&md);
	EVP_SignInit_ex(&md, evp_md, NULL);
	EVP_SignUpdate(&md, data, datalen);
	ok = EVP_SignFinal(&md, tsig, &len, pkey);
	EVP_MD_CTX_cleanup(&md);
	EVP_PKEY_free(pkey);

	if (ok != 1) {
		xfree(tsig);
		error("ssh_dss_sign: sign failed");
		return -1;
	}

	psig = tsig;

	/* Output of EVP_SignFinal() is encoded, convert to DSA_SIG */
	sig = d2i_DSA_SIG(NULL, &psig, len);
	memset(tsig, 'd', len);
	xfree(tsig);

	if (sig == NULL) {
		error("ssh_dss_sign: DSA parse failed");
		return -1;
	}

	rlen = BN_num_bytes(sig->r);
	slen = BN_num_bytes(sig->s);
	if (rlen > INTBLOB_LEN || slen > INTBLOB_LEN) {
		error("bad sig size %u %u", rlen, slen);
		DSA_SIG_free(sig);
		return -1;
	}
	memset(sigblob, 0, SIGBLOB_LEN);
	BN_bn2bin(sig->r, sigblob+ SIGBLOB_LEN - INTBLOB_LEN - rlen);
	BN_bn2bin(sig->s, sigblob+ SIGBLOB_LEN - slen);
	DSA_SIG_free(sig);

	if (datafellows & SSH_BUG_SIGBLOB) {
		if (lenp != NULL)
			*lenp = SIGBLOB_LEN;
		if (sigp != NULL) {
			*sigp = xmalloc(SIGBLOB_LEN);
			memcpy(*sigp, sigblob, SIGBLOB_LEN);
		}
	} else {
		/* ietf-drafts */
		buffer_init(&b);
		buffer_put_cstring(&b, "ssh-dss");
		buffer_put_string(&b, sigblob, SIGBLOB_LEN);
		len = buffer_len(&b);
		if (lenp != NULL)
			*lenp = len;
		if (sigp != NULL) {
			*sigp = xmalloc(len);
			memcpy(*sigp, buffer_ptr(&b), len);
		}
		buffer_free(&b);
	}
	return 0;
}
int
ssh_dss_verify(const Key *key, const u_char *signature, u_int signaturelen,
    const u_char *data, u_int datalen)
{
	DSA_SIG *sig;
	const EVP_MD *evp_md = EVP_dss1();
	EVP_MD_CTX md;
	u_char *sigblob;
	u_int len;
	int rlen, ret;
	Buffer b;
        u_char *tsig, *psig;
	EVP_PKEY *pkey;

	if (key == NULL || key->dsa == NULL || (key->type != KEY_DSA &&
	    key->type != KEY_DSA_CERT && key->type != KEY_DSA_CERT_V00)) {
		error("ssh_dss_verify: no DSA key");
		return -1;
	}

	/* fetch signature */
	if (datafellows & SSH_BUG_SIGBLOB) {
		sigblob = xmalloc(signaturelen);
		memcpy(sigblob, signature, signaturelen);
		len = signaturelen;
	} else {
		/* ietf-drafts */
		char *ktype;
		buffer_init(&b);
		buffer_append(&b, signature, signaturelen);
		ktype = buffer_get_cstring(&b, NULL);
		if (strcmp("ssh-dss", ktype) != 0) {
			error("ssh_dss_verify: cannot handle type %s", ktype);
			buffer_free(&b);
			xfree(ktype);
			return -1;
		}
		xfree(ktype);
		sigblob = buffer_get_string(&b, &len);
		rlen = buffer_len(&b);
		buffer_free(&b);
		if (rlen != 0) {
			error("ssh_dss_verify: "
			    "remaining bytes in signature %d", rlen);
			xfree(sigblob);
			return -1;
		}
	}

	if (len != SIGBLOB_LEN) {
		fatal("bad sigbloblen %u != SIGBLOB_LEN", len);
	}

	/* parse signature */
	if ((sig = DSA_SIG_new()) == NULL)
		fatal("ssh_dss_verify: DSA_SIG_new failed");
	if ((sig->r = BN_new()) == NULL)
		fatal("ssh_dss_verify: BN_new failed");
	if ((sig->s = BN_new()) == NULL)
		fatal("ssh_dss_verify: BN_new failed");
	if ((BN_bin2bn(sigblob, INTBLOB_LEN, sig->r) == NULL) ||
	    (BN_bin2bn(sigblob+ INTBLOB_LEN, INTBLOB_LEN, sig->s) == NULL))
		fatal("ssh_dss_verify: BN_bin2bn failed");

	/* clean up */
	memset(sigblob, 0, len);
	xfree(sigblob);

        /* Sig is in DSA_SIG structure, convert to encoded buffer */
        len = i2d_DSA_SIG(sig, NULL);
        tsig = xmalloc(len);
        psig = tsig;
        i2d_DSA_SIG(sig, &psig);
        DSA_SIG_free(sig);
  
        pkey = EVP_PKEY_new();
        EVP_PKEY_set1_DSA(pkey, key->dsa);
  
        /* now verify signature */
        EVP_MD_CTX_init(&md);
        EVP_VerifyInit(&md, evp_md);
        EVP_VerifyUpdate(&md, data, datalen);
        ret = EVP_VerifyFinal(&md, tsig, len, pkey);
        EVP_MD_CTX_cleanup(&md);
        EVP_PKEY_free(pkey);
  
        /* Cleanup buffer */
        memset(tsig, 'd', len);
        xfree(tsig);

	debug("ssh_dss_verify: signature %s",
	    ret == 1 ? "correct" : ret == 0 ? "incorrect" : "error");
	return ret;
}
