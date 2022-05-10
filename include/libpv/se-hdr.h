/*
 * PV header definitions
 *
 * Copyright IBM Corp. 2020
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */
#pragma once

#include "libpv/common.h"

#include <openssl/sha.h>

#include "boot/s390.h"
#include "lib/zt_common.h"

#include "libpv/crypto.h"

/* Magic number which is used to identify the file containing the PV
 * header
 */
#define PV_MAGIC_NUMBER 0x49424d5365634578ULL
#define PV_VERSION_1 0x00000100U

/* Internal helper macro */
#define __PV_BIT(nr) (1ULL << (63 - (nr)))

/* Plaintext control flags */
/* dumping of the configuration is allowed */
#define PV_PCF_ALLOW_DUMPING __PV_BIT(34)
/* prevent Ultravisor decryption during unpack operation */
#define PV_PCF_NO_DECRYPTION __PV_BIT(35)
/* PCKMO encrypt-DEA/TDEA-key functions allowed */
#define PV_PCF_PCKMO_DEA_TDEA __PV_BIT(56)
/* PCKMO encrypt-AES-key functions allowed */
#define PV_PCF_PCKMO_AES __PV_BIT(57)
/* PCKMO encrypt-ECC-key functions allowed */
#define PV_PCF_PCKM_ECC __PV_BIT(58)

/* maxima for the PV version 1 */
#define PV_V1_IPIB_MAX_SIZE PAGE_SIZE
#define PV_V1_PV_HDR_MAX_SIZE (2 * PAGE_SIZE)

#define PV_IMAGE_ENCR_KEY_SIZE 64

typedef struct pv_hdr_key_slot {
	uint8_t digest_key[SHA256_DIGEST_LENGTH];
	uint8_t wrapped_key[32];
	uint8_t tag[16];
} __packed PvHdrKeySlot;

typedef struct pv_hdr_opt_item {
	uint32_t otype;
	uint8_t ibk[32];
	uint8_t data[];
} __packed PvHdrOptItem;

/* integrity protected data (by GCM tag), but non-encrypted */
struct pv_hdr_head {
	uint64_t magic;
	uint32_t version;
	uint32_t phs;
	uint8_t iv[12];
	uint32_t res1;
	uint64_t nks;
	uint64_t sea;
	uint64_t nep;
	uint64_t pcf;
	PvEcdhPubKey cust_pub_key;
	uint8_t pld[SHA512_DIGEST_LENGTH];
	uint8_t ald[SHA512_DIGEST_LENGTH];
	uint8_t tld[SHA512_DIGEST_LENGTH];
} __packed;

/* Must not have any padding */
struct pv_hdr_encrypted {
	uint8_t cust_comm_key[32];
	uint8_t img_enc_key_1[PV_IMAGE_ENCR_KEY_SIZE / 2];
	uint8_t img_enc_key_2[PV_IMAGE_ENCR_KEY_SIZE / 2];
	struct psw_t psw;
	uint64_t scf;
	uint32_t noi;
	uint32_t res2;
};
STATIC_ASSERT(sizeof(struct pv_hdr_encrypted) ==
	      32 + 32 + 32 + sizeof(struct psw_t) + 8 + 4 + 4)

typedef struct pv_hdr {
	struct pv_hdr_head head;
	struct pv_hdr_key_slot *slots;
	struct pv_hdr_encrypted *encrypted;
	struct pv_hdr_opt_item **optional_items;
	uint8_t tag[16];
} PvHdr;
