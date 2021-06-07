// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2021, IoT.bzh
 */
#include <io.h>
#include <crypto/crypto.h>
#include <kernel/delay.h>
#include <rproc_pub_key.h>
#include <remoteproc_pta.h>
#include <initcall.h>
#include <kernel/pseudo_ta.h>
#include <kernel/user_ta.h>
#include <platform_config.h>
#include <string.h>
#include <mm/core_memprot.h>

#define p2v_ioadr(r)	((vaddr_t)(phys_to_virt((r), MEM_AREA_IO_SEC)))

#define CR7BAR          p2v_ioadr(0xE6160070U)
#define PWRON           p2v_ioadr(0xE618024cU)

#define SRCR2           p2v_ioadr(0xE61500B0U)
#define SRSTCLR2        p2v_ioadr(0xE6150948U)

#define RCAR_CR7_FW_ID	0

#define PTA_NAME "remoteproc.pta"

/* Firmware states */
enum rproc_load_state {
	REMOTEPROC_OFF = 0,
	REMOTEPROC_ON,
};

static enum rproc_load_state rproc_ta_state;


static TEE_Result rproc_pta_capabilities(uint32_t pt,
					 TEE_Param params[TEE_NUM_PARAMS])
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_VALUE_OUTPUT,
						TEE_PARAM_TYPE_VALUE_OUTPUT,
						TEE_PARAM_TYPE_NONE);

	if (pt != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Support only ELF format */
	params[1].value.a = PTA_REMOTEPROC_ELF_FMT;

	params[2].value.a = PTA_REMOTEPROC_FW_WITH_HASH_TABLE;

	return TEE_SUCCESS;
}

static TEE_Result da_to_pa(paddr_t da, size_t size, paddr_t *pa)
{

	if (da < MEMORY_CR7_BASE)
		return TEE_ERROR_ACCESS_DENIED;

	if (da + size > MEMORY_CR7_BASE + MEMORY_CR7_SIZE)
		return TEE_ERROR_ACCESS_DENIED;

	*pa = da;
	return TEE_SUCCESS;
}

static TEE_Result rproc_pta_da_to_pa(uint32_t pt,
				     TEE_Param params[TEE_NUM_PARAMS])
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_VALUE_OUTPUT);
	TEE_Result res = TEE_ERROR_GENERIC;
	paddr_t da = params[1].value.a;
	size_t size = params[2].value.a;
	paddr_t pa = 0;

	if (pt != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Only RCAR_CR7_FW_ID supported */
	if (params[0].value.a != RCAR_CR7_FW_ID) {
		EMSG("Unsupported firmware ID %#"PRIx32, params[0].value.a);
		return TEE_ERROR_NOT_SUPPORTED;
	}

	DMSG("Conversion for address %#"PRIxPA" size %zu", da, size);
		/* Target address is expected 32bit, ensure 32bit MSB are zero */
	if (params[1].value.b || params[2].value.b)
		return TEE_ERROR_BAD_PARAMETERS;

	res = da_to_pa(da, size, &pa);
	if (res)
		return res;

	reg_pair_from_64((uint64_t)pa, &params[3].value.b, &params[3].value.a);

	return TEE_SUCCESS;
}

static TEE_Result rproc_pta_load_segment(uint32_t pt,
					 TEE_Param params[TEE_NUM_PARAMS])
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_MEMREF_INPUT,
						TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_MEMREF_INPUT);
	TEE_Result res = TEE_ERROR_GENERIC;
	paddr_t pa = 0;
	uint8_t *dst = 0;
	uint8_t *src = params[1].memref.buffer;
	size_t size = params[1].memref.size;
	uint8_t *hash = params[3].memref.buffer;
	paddr_t da = (paddr_t)reg_pair_to_64(params[2].value.b,
					     params[2].value.a);

	if (pt != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!hash || params[3].memref.size != TEE_SHA256_HASH_SIZE)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Only RCAR_CR7_FW_ID supported */
	if (params[0].value.a != RCAR_CR7_FW_ID) {
		EMSG("Unsupported firmware ID %#"PRIx32, params[0].value.a);
		return TEE_ERROR_NOT_SUPPORTED;
	}

	if (rproc_ta_state != REMOTEPROC_OFF)
		return TEE_ERROR_BAD_STATE;

	/* Get the physical address in CR7 mapping */
	res = da_to_pa(da, size, &pa);
	if (res)
		return res;
	/* Get the associated va */
	dst = (void *)core_mmu_get_va(pa, MEM_AREA_IO_SEC);
	if (!dst)
		return TEE_ERROR_ACCESS_DENIED;
	/* Copy the segment to the remote processor memory*/
	memcpy(dst, src, size);

	/* Verify that loaded segment is valid */
	res = hash_sha256_check(hash, dst, size);
	if (res)
		memset(dst, 0, size);

	return res;
}

static TEE_Result rproc_pta_set_memory(uint32_t pt,
				       TEE_Param params[TEE_NUM_PARAMS])
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_VALUE_INPUT);
	TEE_Result res = TEE_ERROR_GENERIC;
	paddr_t pa = 0;
	vaddr_t dst = 0;
	paddr_t da = params[1].value.a;
	size_t size = params[2].value.a;
	char value = (char)params[3].value.a;

	if (pt != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Only RCAR_CR7_FW_ID supported */
	if (params[0].value.a != RCAR_CR7_FW_ID) {
		EMSG("Unsupported firmware ID %#"PRIx32, params[0].value.a);
		return TEE_ERROR_NOT_SUPPORTED;
	}

	if (rproc_ta_state != REMOTEPROC_OFF)
		return TEE_ERROR_BAD_STATE;


	/* Get the physical address in CPU mapping */
	res = da_to_pa(da, size, &pa);
	if (res)
		return res;

	dst = core_mmu_get_va(pa, MEM_AREA_IO_SEC);
	if (!dst)
		return TEE_ERROR_ACCESS_DENIED;
	memset((void *)dst, value, size);

	return TEE_SUCCESS;
}

static TEE_Result rproc_pta_start(uint32_t pt,
				  TEE_Param params[TEE_NUM_PARAMS])
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);
	if (pt != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Only RCAR_CR7_FW_ID supported */
	if (params[0].value.a != RCAR_CR7_FW_ID) {
		EMSG("Unsupported firmware ID %#"PRIx32, params[0].value.a);
		return TEE_ERROR_NOT_SUPPORTED;
	}

	/* release the cr7 reset */
	io_write32(SRSTCLR2, 0x00400000);

	rproc_ta_state = REMOTEPROC_ON;

	return TEE_SUCCESS;
}

static TEE_Result rproc_pta_stop(uint32_t pt,
				 TEE_Param params[TEE_NUM_PARAMS])
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);
	if (pt != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Only RCAR_CR7_FW_ID supported */
	if (params[0].value.a != RCAR_CR7_FW_ID) {
		EMSG("Unsupported firmware ID %#"PRIx32, params[0].value.a);
		return TEE_ERROR_NOT_SUPPORTED;
	}

	if (rproc_ta_state != REMOTEPROC_ON)
		return TEE_ERROR_BAD_STATE;

	io_write32(SRCR2, 0x00400000);

	rproc_ta_state = REMOTEPROC_OFF;

	return TEE_SUCCESS;
}

static TEE_Result rproc_pta_verify_rsa_signature(TEE_Param *hash,
						 TEE_Param *sig, uint32_t algo)
{
	struct rsa_public_key key = { };
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t e = TEE_U32_TO_BIG_ENDIAN(rproc_pub_key_exponent);
	size_t hash_size = (size_t)hash->memref.size;
	size_t sig_size = (size_t)sig->memref.size;


	res = crypto_acipher_alloc_rsa_public_key(&key, sig_size);
	if (res)
		return TEE_ERROR_SECURITY;

	res = crypto_bignum_bin2bn((uint8_t *)&e, sizeof(e), key.e);
	if (res)
		goto out;

	res = crypto_bignum_bin2bn(rproc_pub_key_modulus,
				   rproc_pub_key_modulus_size, key.n);
	if (res)
		goto out;

	res = crypto_acipher_rsassa_verify(algo, &key, hash_size,
					   hash->memref.buffer, hash_size,
					   sig->memref.buffer, sig_size);

out:
	crypto_acipher_free_rsa_public_key(&key);
	return res;
}

static TEE_Result rproc_pta_verify_digest(uint32_t pt,
					  TEE_Param params[TEE_NUM_PARAMS])
{
	struct rproc_pta_key_info *keyinfo = NULL;
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_MEMREF_INPUT,
						TEE_PARAM_TYPE_MEMREF_INPUT,
						TEE_PARAM_TYPE_MEMREF_INPUT);

	if (pt != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Only RCAR_CR7_FW_ID supported */
	if (params[0].value.a != RCAR_CR7_FW_ID) {
		EMSG("Unsupported firmware ID %#"PRIx32, params[0].value.a);
		return TEE_ERROR_NOT_SUPPORTED;
	}

	if (rproc_ta_state != REMOTEPROC_OFF)
		return TEE_ERROR_BAD_STATE;

	keyinfo = params[1].memref.buffer;

	if (!keyinfo ||
	    RPROC_PTA_GET_KEYINFO_SIZE(keyinfo) != params[1].memref.size)
		return TEE_ERROR_BAD_PARAMETERS;

	if (keyinfo->algo != TEE_ALG_RSASSA_PKCS1_V1_5_SHA256)
		return TEE_ERROR_NOT_SUPPORTED;

	return rproc_pta_verify_rsa_signature(&params[2], &params[3],
					      keyinfo->algo);
}

static TEE_Result rproc_pta_invoke_command(void *pSessionContext __unused,
					   uint32_t cmd_id,
					   uint32_t param_types,
					   TEE_Param params[TEE_NUM_PARAMS])
{
	switch (cmd_id) {
	case PTA_REMOTEPROC_HW_CAPABILITIES:
		return rproc_pta_capabilities(param_types, params);
	case PTA_REMOTEPROC_LOAD_SEGMENT_SHA256:
		return rproc_pta_load_segment(param_types, params);
	case PTA_REMOTEPROC_SET_MEMORY:
		return rproc_pta_set_memory(param_types, params);
	case PTA_REMOTEPROC_FIRMWARE_START:
		return rproc_pta_start(param_types, params);
	case PTA_REMOTEPROC_FIRMWARE_STOP:
		return rproc_pta_stop(param_types, params);
	case PTA_REMOTEPROC_FIRMWARE_DA_TO_PA:
		return rproc_pta_da_to_pa(param_types, params);
	case PTA_REMOTEPROC_VERIFY_DIGEST:
		return rproc_pta_verify_digest(param_types, params);
	default:
		break;
	}

	return TEE_ERROR_NOT_IMPLEMENTED;
}

static TEE_Result rproc_pta_init(void)
{
	/* Set the boot address */
	io_write32(CR7BAR, MEMORY_CR7_BASE | 0x10);
	/* Make sure to keep CR7 in reset */
	io_write32(SRCR2, 0x00400000);
	io_write32(PWRON, 1);
	/* hack to handle power on */
	udelay(100 * 1000);

	return TEE_SUCCESS;
}
service_init_late(rproc_pta_init);

pseudo_ta_register(.uuid = PTA_REMOTEPROC_UUID, .name = PTA_NAME,
		   .flags = PTA_DEFAULT_FLAGS,
		   .invoke_command_entry_point = rproc_pta_invoke_command);
