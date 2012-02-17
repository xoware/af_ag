/* Written by Markus Koetter (nepenthesdev@gmail.com) for the OpenSSL
 * project.
 */
/* ====================================================================
 * Copyright (c) 2011 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include <memory.h>
#include <openssl/aes.h>
#include <openssl/engine.h>
#include <sys/socket.h>
#include <linux/if_alg.h>
#include <unistd.h>
#include <sys/param.h>
#include <ctype.h>
#include <stdbool.h>

#ifndef AF_ALG
#define AF_ALG 38
#endif

#ifndef SOL_ALG
#define SOL_ALG 279
#endif

/* Socket options */
#define ALG_SET_KEY			1
#define ALG_SET_IV			2
#define ALG_SET_OP			3

/* Operations */
#define ALG_OP_DECRYPT			0
#define ALG_OP_ENCRYPT			1

#define AES_KEY_SIZE_128        16
#define AES_KEY_SIZE_192        24
#define AES_KEY_SIZE_256        32

static int af_alg_ciphers (ENGINE *e, const EVP_CIPHER **cipher, const int **nids, int nid);
static int af_alg_aes_ciphers(EVP_CIPHER_CTX *ctx, unsigned char *out_arg, const unsigned char *in_arg, unsigned int nbytes);

static int af_alg_digests(ENGINE *e, const EVP_MD **digest, const int **nids, int nid);

#define DYNAMIC_ENGINE
#define AF_ALG_ENGINE_ID	"af_alg"
#define AF_ALG_ENGINE_NAME	"use AF_ALG for AES crypto"

#define EVP_CIPHER_block_size_CBC	AES_BLOCK_SIZE

static bool nid_in_nids(int nid, int nids[], int num)
{
	int i=0;
	for( i=0;i<num;i++ )
		if( nids[i] == nid )
			return true;
	return false;
}

struct af_alg_cipher_data
{
	int tfmfd;
	int op;
	__u32 type;
};

static int af_alg_cipher_all_nids[] = {
	NID_aes_128_cbc,
	NID_aes_192_cbc,
	NID_aes_256_cbc,
};
static int af_alg_cipher_all_nids_num = (sizeof(af_alg_cipher_all_nids)/sizeof(af_alg_cipher_all_nids[0]));
static int *af_alg_digest_nids = NULL;
static int af_alg_digest_nids_num = 0;

static int af_alg_digest_all_nids[] = {
	NID_sha1,
};
static int af_alg_digest_all_nids_num = sizeof(af_alg_digest_all_nids)/sizeof(af_alg_digest_all_nids[0]);
static int *af_alg_cipher_nids = NULL;
static int af_alg_cipher_nids_num = 0;


int af_alg_init(ENGINE * engine)
{
	int sock;
	if((sock = socket(AF_ALG, SOCK_SEQPACKET, 0)) == -1)
		return 0;
	close(sock);
	return 1;
}

int af_alg_finish(ENGINE * engine)
{
	return 1;
}
/* The definitions for control commands specific to this engine */
#define AF_ALG_CMD_CIPHERS	ENGINE_CMD_BASE
#define AF_ALG_CMD_DIGESTS	(ENGINE_CMD_BASE + 1)

static const ENGINE_CMD_DEFN af_alg_cmd_defns[] = {
	{AF_ALG_CMD_CIPHERS,"CIPHERS","which ciphers to run",ENGINE_CMD_FLAG_STRING},
	{AF_ALG_CMD_DIGESTS,"DIGESTS","which digests to run",ENGINE_CMD_FLAG_STRING},
	{0, NULL, NULL, 0}
};
static int cipher_nid(const EVP_CIPHER *c)
{
	return EVP_CIPHER_nid(c);
}
static int digest_nid(const EVP_MD *d)
{
	return EVP_MD_type(d);
}
static bool names_to_nids(const char *names, const void*(*by_name)(const char *), int (*to_nid)(const void *), int **rnids, int *rnum, int *nids, int num)
{
	char *str, *r;
	char *c = NULL;
	r = str = strdup(names);
	while( (c = strtok_r(r, " ", &r)) != NULL )
	{
		const void *ec = by_name(c);
		if( ec == NULL || nid_in_nids(to_nid(ec), nids, num) == false)
			continue;
		if((*rnids = realloc(*rnids, (*rnum+1)*sizeof(int))) == NULL)
			return false;
		(*rnids)[*rnum]=to_nid(ec);
		*rnum = *rnum+1;
	}
	return true;
}

static int af_alg_ctrl(ENGINE *e, int cmd, long i, void *p, void (*f)())
{
	switch( cmd )
	{
	case AF_ALG_CMD_CIPHERS:
		if( p == NULL )
			return 1;
		names_to_nids(p, (void *)EVP_get_cipherbyname, (void *)cipher_nid, &af_alg_cipher_nids, &af_alg_cipher_nids_num, af_alg_cipher_all_nids, af_alg_cipher_all_nids_num);
		ENGINE_unregister_ciphers(e);
		ENGINE_register_ciphers(e);
		return 1;
	case AF_ALG_CMD_DIGESTS:
		if( p == NULL )
			return 1;
		names_to_nids(p, (void *)EVP_get_digestbyname, (void *)digest_nid, &af_alg_digest_nids, &af_alg_digest_nids_num, af_alg_digest_all_nids, af_alg_digest_all_nids_num);
		ENGINE_unregister_digests(e);
		ENGINE_register_digests(e);
		return 1;
	default:
		break;
	}
	return 0;
}

static int af_alg_bind_helper(ENGINE * e)
{
	if( !ENGINE_set_id(e, AF_ALG_ENGINE_ID) ||
		!ENGINE_set_init_function(e, af_alg_init) ||
		!ENGINE_set_finish_function(e, af_alg_finish) ||
		!ENGINE_set_name(e, AF_ALG_ENGINE_NAME) ||
		!ENGINE_set_ciphers (e, af_alg_ciphers) ||
		!ENGINE_set_digests (e, af_alg_digests) ||
		!ENGINE_set_ctrl_function(e, af_alg_ctrl) ||
		!ENGINE_set_cmd_defns(e, af_alg_cmd_defns))
		return 0;
	return 1;
}

ENGINE *ENGINE_af_alg(void)
{
	ENGINE *eng = ENGINE_new();
	if( !eng )
		return NULL;

	if( !af_alg_bind_helper(eng) )
	{
		ENGINE_free(eng);
		return NULL;
	}
	return eng;
}

static int af_alg_bind_fn(ENGINE *e, const char *id)
{
	if( id && (strcmp(id, AF_ALG_ENGINE_ID) != 0) )
		return 0;

	if( !af_alg_bind_helper(e) )
		return 0;

	return 1;
}

IMPLEMENT_DYNAMIC_CHECK_FN()
IMPLEMENT_DYNAMIC_BIND_FN(af_alg_bind_fn)

static int af_alg_aes_init_key (EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc)
{
	int keylen = EVP_CIPHER_CTX_key_length(ctx);
	struct af_alg_cipher_data *acd = (struct af_alg_cipher_data *)ctx->cipher_data;
	
	struct sockaddr_alg sa = {
		.salg_family = AF_ALG,
		.salg_type = "skcipher",
		.salg_name = "cbc(aes)",
	};

	acd->op = -1;

	if( ctx->encrypt )
		acd->type = ALG_OP_ENCRYPT;
	else
		acd->type = ALG_OP_DECRYPT;

	if((acd->tfmfd = socket(AF_ALG, SOCK_SEQPACKET, 0)) == -1)
		return 0;
	
	if( bind(acd->tfmfd, (struct sockaddr*)&sa, sizeof(sa)) == -1 )
		return 0;

	if (setsockopt(acd->tfmfd, SOL_ALG, ALG_SET_KEY, key, keylen) == -1)
		return 0;

	return 1;
}

int af_alg_aes_cleanup_key(EVP_CIPHER_CTX *ctx)
{
	struct af_alg_cipher_data *acd = (struct af_alg_cipher_data *)ctx->cipher_data;
	if( acd->tfmfd != -1 )
		close(acd->tfmfd);
	if( acd->op != -1 )
		close(acd->op);
	return 1;
}

#define	DECLARE_AES_EVP(ksize,lmode,umode)                  \
static const EVP_CIPHER af_alg_aes_##ksize##_##lmode = {    \
	.nid = NID_aes_##ksize##_##lmode,                       \
	.block_size = EVP_CIPHER_block_size_##umode,            \
	.key_len = AES_KEY_SIZE_##ksize,                        \
	.iv_len = AES_BLOCK_SIZE,                               \
	.flags = 0 | EVP_CIPH_##umode##_MODE,                   \
	.init = af_alg_aes_init_key,                            \
	.do_cipher = af_alg_aes_ciphers,                        \
	.cleanup = af_alg_aes_cleanup_key,                      \
	.ctx_size = sizeof(struct af_alg_cipher_data),          \
	.set_asn1_parameters = EVP_CIPHER_set_asn1_iv,          \
	.get_asn1_parameters = EVP_CIPHER_get_asn1_iv,          \
	.ctrl = NULL,                                           \
	.app_data = NULL                                        \
}

DECLARE_AES_EVP(128,cbc,CBC);
DECLARE_AES_EVP(192,cbc,CBC);
DECLARE_AES_EVP(256,cbc,CBC);

static int af_alg_aes_ciphers(EVP_CIPHER_CTX *ctx, unsigned char *out_arg, const unsigned char *in_arg, unsigned int nbytes)
{
	struct af_alg_cipher_data *acd = (struct af_alg_cipher_data *)ctx->cipher_data;
	struct msghdr msg = {};
	struct cmsghdr *cmsg;
	struct af_alg_iv *ivm;
	struct iovec iov;
	char buf[CMSG_SPACE(sizeof(acd->type)) + CMSG_SPACE(offsetof(struct af_alg_iv, iv) + AES_BLOCK_SIZE)];
	ssize_t len;
	unsigned char save_iv[AES_BLOCK_SIZE];

	memset(buf, 0, sizeof(buf));

	msg.msg_control = buf;
	msg.msg_controllen = 0;
	msg.msg_controllen = sizeof(buf);
	if( acd->op == -1 )
	{
		if((acd->op = accept(acd->tfmfd, NULL, 0)) == -1)
			return 0;
	}
	/* set operation type encrypt|decrypt */
	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_ALG;
	cmsg->cmsg_type = ALG_SET_OP;
	cmsg->cmsg_len = CMSG_LEN(4);
	memcpy(CMSG_DATA(cmsg),&acd->type, 4);

	/* set IV - or update if it was set before */
	if(!ctx->encrypt)
		memcpy(save_iv, in_arg + nbytes - AES_BLOCK_SIZE, AES_BLOCK_SIZE);

	cmsg = CMSG_NXTHDR(&msg, cmsg);
	cmsg->cmsg_level = SOL_ALG;
	cmsg->cmsg_type = ALG_SET_IV;
	cmsg->cmsg_len = CMSG_LEN(offsetof(struct af_alg_iv, iv) + AES_BLOCK_SIZE);
	ivm = (void*)CMSG_DATA(cmsg);
	ivm->ivlen = AES_BLOCK_SIZE;
	memcpy(ivm->iv, ctx->iv, AES_BLOCK_SIZE);

	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	unsigned int todo = nbytes;
	unsigned int done = 0;
	while( todo-done > 0 )
	{
		iov.iov_base = (void *)(in_arg + done);
		iov.iov_len = todo-done;

		if((len = sendmsg(acd->op, &msg, 0)) == -1)
			return 0;

		if (read(acd->op, out_arg+done, len) != len)
			return 0;
		
		/* do not update IV for following chunks */
		msg.msg_controllen = 0;
		done += len;
	}

	/* copy IV for next iteration */
	if(ctx->encrypt)
		memcpy(ctx->iv, out_arg + done - AES_BLOCK_SIZE, AES_BLOCK_SIZE);
	else
		memcpy(ctx->iv, save_iv, AES_BLOCK_SIZE);
	return 1;
}

static int af_alg_ciphers(ENGINE *e, const EVP_CIPHER **cipher, const int **nids, int nid)
{
	if( !cipher )
	{
		*nids = af_alg_cipher_nids;
		return af_alg_cipher_nids_num;
	}

	if( ! nid_in_nids(nid, af_alg_cipher_nids, af_alg_cipher_nids_num) )
		return 0;

	switch( nid )
	{
	case NID_aes_128_cbc:
		*cipher = &af_alg_aes_128_cbc;
		break;
	case NID_aes_192_cbc:
		*cipher = &af_alg_aes_192_cbc;
		break;
	case NID_aes_256_cbc:
		*cipher = &af_alg_aes_256_cbc;
		break;
	default:
		*cipher = NULL;
	}
	return(*cipher != 0);
}

struct af_alg_digest_data
{
	int tfmfd;
	int opfd;
};

#define DIGEST_DATA(ctx) ((struct af_alg_digest_data*)(ctx->md_data))

static int af_alg_sha1_init(EVP_MD_CTX *ctx)
{
	struct af_alg_digest_data *ddata = DIGEST_DATA(ctx);
	struct sockaddr_alg sa = {
		.salg_family = AF_ALG,
		.salg_type = "hash",
		.salg_name = "sha1"
	};

	if( (ddata->tfmfd = socket(AF_ALG, SOCK_SEQPACKET, 0)) == -1 )
		return 0;

	if( bind(ddata->tfmfd, (struct sockaddr *)&sa, sizeof(sa)) != 0 )
		return 0;

	if( (ddata->opfd = accept(ddata->tfmfd,NULL,0)) == -1 )
		return 0;

	return 1;
}

static int af_alg_sha1_update(EVP_MD_CTX *ctx, const void *data, size_t length)
{
	struct af_alg_digest_data *ddata = DIGEST_DATA(ctx);
	ssize_t r;
	r = send(ddata->opfd, data, length, MSG_MORE);
	if( r < 0 || (size_t)r < length )
		return 0;
	return 1;
}

static int af_alg_sha1_final(EVP_MD_CTX *ctx, unsigned char *md)
{
	struct af_alg_digest_data *ddata = DIGEST_DATA(ctx);
	if( read(ddata->opfd, md, SHA_DIGEST_LENGTH) != SHA_DIGEST_LENGTH )
		return 0;

	return 1;
}

static int af_alg_sha1_copy(EVP_MD_CTX *_to,const EVP_MD_CTX *_from)
{
	struct af_alg_digest_data *from = DIGEST_DATA(_from);
	struct af_alg_digest_data *to = DIGEST_DATA(_to);
	if( (to->opfd = accept(from->opfd, NULL, 0)) == -1 )
		return 0;
	to->tfmfd = from->tfmfd; /* FIXME how to verify? */
	return 1;
}

static int af_alg_sha1_cleanup(EVP_MD_CTX *ctx)
{
	struct af_alg_digest_data *ddata = DIGEST_DATA(ctx);
	if( ddata->opfd != -1 )
		close(ddata->opfd);
	if( ddata->tfmfd != -1 )
		close(ddata->tfmfd);
	return 0;
}

#define	DECLARE_MD_SHA(digest) \
static const EVP_MD af_alg_##digest##_md = {    \
	NID_##digest,                               \
	NID_##digest##WithRSAEncryption,            \
	SHA_DIGEST_LENGTH,                          \
	0,                                          \
	af_alg_##digest##_init,                     \
	af_alg_##digest##_update,                   \
	af_alg_##digest##_final,                    \
	af_alg_##digest##_copy,                     \
	af_alg_##digest##_cleanup,                  \
	EVP_PKEY_RSA_method,                        \
	SHA_CBLOCK,                                 \
	sizeof(struct af_alg_digest_data),          \
};

DECLARE_MD_SHA(sha1)

static int af_alg_digests(ENGINE *e, const EVP_MD **digest, const int **nids, int nid)
{
	if( !digest )
	{
		*nids = af_alg_digest_nids;
		return af_alg_digest_nids_num;
	}

	if( nid_in_nids(nid, af_alg_digest_nids, af_alg_digest_nids_num) == false )
		return 0;

	switch( nid )
	{
	case NID_sha1:
		*digest = &af_alg_sha1_md;
		break;
	default:
		*digest = NULL;
	}
	return (*digest != NULL);
}

