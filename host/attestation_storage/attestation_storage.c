/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <adbg.h>
#include <fcntl.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <tee_client_api.h>
#include <time.h>
#include <unistd.h>

#include "crypto_common.h"
#include "attestation.h"

#define MAX_SHM_SIZE 1048576

double tee_time = 0;
double total_time = 0;

typedef struct
{
	char data[32];
} sha_out_blk;

static TEEC_Context ctx;
static TEEC_Session sess;
static TEEC_SharedMemory in_shm = {
	.flags = TEEC_MEM_INPUT
};
static TEEC_SharedMemory out_shm = {
	.flags = TEEC_MEM_OUTPUT
};

static void errx(const char *msg, TEEC_Result res, uint32_t *orig)
{
	fprintf(stderr, "%s: 0x%08x", msg, res);
	if (orig)
		fprintf(stderr, " (orig=%d)", (int)*orig);
	fprintf(stderr, "\n");
	exit (1);
}

static void check_res(TEEC_Result res, const char *errmsg, uint32_t *orig)
{
	if (res != TEEC_SUCCESS)
		errx(errmsg, res, orig);
}

static void open_ta(void)
{
	TEEC_Result res;
	TEEC_UUID uuid = TA_SHA_PERF_UUID;
	uint32_t err_origin;

	res = TEEC_InitializeContext(NULL, &ctx);
	check_res(res,"TEEC_InitializeContext", NULL);

	res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL,
			       NULL, &err_origin);
	check_res(res,"TEEC_OpenSession", &err_origin);
}

static int hash_size(uint32_t algo)
{
	switch (algo) {
	case TA_SHA_SHA1:
		return 20;
	case TA_SHA_SHA224:
		return 28;
	case TA_SHA_SHA256:
		return 32;
	case TA_SHA_SHA384:
		return 48;
	case TA_SHA_SHA512:
		return 64;
	default:
		return 0;
	}
}

#define _TO_STR(x) #x
#define TO_STR(x) _TO_STR(x)


static void alloc_shm(size_t sz, uint32_t algo, int offset)
{
	TEEC_Result res;

	in_shm.buffer = NULL;
	in_shm.size = sz + offset;
	res = TEEC_AllocateSharedMemory(&ctx, &in_shm);
	check_res(res, "TEEC_AllocateSharedMemory", NULL);

	out_shm.buffer = NULL;
	out_shm.size = hash_size(algo);
	res = TEEC_AllocateSharedMemory(&ctx, &out_shm);
	check_res(res, "TEEC_AllocateSharedMemory", NULL);
}

static void free_shm(void)
{
	TEEC_ReleaseSharedMemory(&in_shm);
	TEEC_ReleaseSharedMemory(&out_shm);
}

static void prepare_op(int algo)
{
	TEEC_Result res;
	uint32_t ret_origin;
	TEEC_Operation op;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].value.a = algo;
	res = TEEC_InvokeCommand(&sess, TA_SHA_PERF_CMD_PREPARE_OP, &op,
				 &ret_origin);
	check_res(res, "TEEC_InvokeCommand", &ret_origin);
}

void generate_hash(TEEC_Operation *op)
{
	TEEC_Result res;
	uint32_t ret_origin;

	res = TEEC_InvokeCommand(&sess, TA_SHA_PERF_CMD_PROCESS, op,
				 &ret_origin);
	check_res(res, "TEEC_InvokeCommand", &ret_origin);
}

/* Hash test: buffer of size byte. Run test n times.
 * Entry point for running SHA benchmark
 * Params:
 * algo - Algorithm
 * data - Cac hash of this data
 * size - Buffer size
 * offset - Buffer offset wrt. alloc-ed address
 * */
void sha_attest(int algo, char* data,
				size_t size, int offset)
{
	TEEC_Operation op;

	alloc_shm(size, algo, offset);

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_PARTIAL_INPUT,
					 TEEC_MEMREF_PARTIAL_OUTPUT,
					 TEEC_VALUE_INPUT, TEEC_NONE);
	op.params[0].memref.parent = &in_shm;
	op.params[0].memref.offset = 0;
	op.params[0].memref.size = size + offset;
	op.params[1].memref.parent = &out_shm;
	op.params[1].memref.offset = 0;
	op.params[1].memref.size = hash_size(algo);
	op.params[2].value.a = 1;
	// op.params[2].value.b = offset;

	memcpy(in_shm.buffer, data, size);

	struct timeval tv1, tv2;
  	gettimeofday(&tv1, NULL);

	generate_hash(&op);

  	gettimeofday(&tv2, NULL);

  	tee_time += ((double) (tv2.tv_usec - tv1.tv_usec) / 1000000 + (double) (tv2.tv_sec - tv1.tv_sec));
}

int main(int argc, char* argv[])
{
	if(argc < 2)
	{
		printf("Usage: attestation_storage path-to-kern-image\n");
		exit(1);
	}
	FILE *f = fopen(argv[1], "rb");
	while(f == NULL)
	{
		f = fopen(argv[1], "rb");	
	}

	int offset = 0;
	char *kern_img = (char*) calloc(1, MAX_SHM_SIZE);
	size_t bytes_read;

	fseek(f, 0, SEEK_END);
	long fsize = ftell(f);
	fseek(f, 0, SEEK_SET);

	int num_blocks = ((int) fsize/MAX_SHM_SIZE) + 1;
	sha_out_blk* sha_blks = (sha_out_blk*) calloc(num_blocks, sizeof(sha_out_blk));
	int i = 0;
	char hash_buf[32];

	open_ta();
	prepare_op(TA_SHA_SHA256);
	
	/* real stuff happens below this */
	struct timeval tv1, tv2;
  	gettimeofday(&tv1, NULL);

	while((bytes_read = fread(kern_img, 1, MAX_SHM_SIZE, f)) > 0)
	{
		sha_attest(TA_SHA_SHA256, kern_img, MAX_SHM_SIZE, offset);
		memcpy(hash_buf, out_shm.buffer, 32);
		// hash_buf = (char*) out_shm.buffer;
		memcpy(sha_blks+i, hash_buf, sizeof(sha_out_blk));
		i++;
		free_shm();
	}

	if(num_blocks != 1)
	{
		sha_out_blk sha_append_data[2];
		memcpy(sha_append_data, sha_blks, 32);
		memcpy(sha_append_data+1, sha_blks+1, 32);

		sha_attest(TA_SHA_SHA256, (char*)sha_append_data, 64, offset);
		memcpy(hash_buf, out_shm.buffer, 32);
		free_shm();

		for(i=2; i<num_blocks; i++)
		{
			memcpy(sha_append_data, hash_buf, 32);
			memcpy(sha_append_data+1, sha_blks+i, 32);
			sha_attest(TA_SHA_SHA256, (char*)sha_append_data, 64, offset);
			memcpy(hash_buf, out_shm.buffer, 32);
			free_shm();
		}
	}

	gettimeofday(&tv2, NULL);

  	total_time = ((double) (tv2.tv_usec - tv1.tv_usec) / 1000000 + (double) (tv2.tv_sec - tv1.tv_sec));

  	for(i=0; i<32; i++)
  	{
  		printf("%02X", hash_buf[i]);
  	}
  	printf("\n");  	

	free(kern_img);
	printf("%f\n", total_time);

	return 0;
}
