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

#define DYNAMIC_ENGINE
#define AF_ALG_ENGINE_ID	"af_alg"
#define AF_ALG_ENGINE_NAME	"use AF_ALG for AES crypto"

#define EVP_CIPHER_block_size_CBC	AES_BLOCK_SIZE

struct af_alg_cipher_data
{
	int tfmfd;
	int op;
	__u32 type;
};

static int af_alg_cipher_nids[] = {
	NID_aes_128_cbc,
	NID_aes_192_cbc,
	NID_aes_256_cbc,
};

static int af_alg_cipher_nids_num = (sizeof(af_alg_cipher_nids)/sizeof(af_alg_cipher_nids[0]));

int af_alg_init(ENGINE * engine)
{
	int sock;
	if((sock = socket(AF_ALG, SOCK_SEQPACKET, 0)) == -1)
		return 0;
	close(sock);
	return 1;
}


static int af_alg_bind_helper(ENGINE * e)
{
	if( !ENGINE_set_id(e, AF_ALG_ENGINE_ID) ||
		!ENGINE_set_init_function(e, af_alg_init) ||
		!ENGINE_set_name(e, AF_ALG_ENGINE_NAME) ||
		!ENGINE_set_ciphers (e, af_alg_ciphers) )
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
	};

	const char *type = "skcipher";
	const char *name = "cbc(aes)";
	strncpy((char *)sa.salg_type, type, strlen(type));
	strncpy((char *)sa.salg_name, name, strlen(name));

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
		return 0;
	}
	return 1;
}

