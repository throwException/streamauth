#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <endian.h>
#include <openssl/evp.h>
#include "key.h"
#include "config.h"
#include "util.h"

bool create_roundkey(uint8_t const* key, uint8_t const* iv, uint64_t counter, uint8_t* roundkey)
{
	const EVP_MD* md = EVP_sha512_256();
	EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
	if (mdctx == nullptr) {
		return false;
	}
	if (!EVP_DigestInit_ex2(mdctx, md, nullptr)) {
		EVP_MD_CTX_free(mdctx);
		return false;
	}
	if (!EVP_DigestUpdate(mdctx, key, KEY_SIZE)) {
		EVP_MD_CTX_free(mdctx);
		return false;
	}
	if (!EVP_DigestUpdate(mdctx, iv, IV_SIZE)) {
		EVP_MD_CTX_free(mdctx);
		return false;
	}
	uint64_t counter_big_endian = htobe64(counter);
	if (!EVP_DigestUpdate(mdctx, (uint8_t*)&counter_big_endian, sizeof(uint64_t))) {
		EVP_MD_CTX_free(mdctx);
		return false;
	}
	uint32_t roundkeylen = KEY_SIZE;
	if (!EVP_DigestFinal_ex(mdctx, roundkey, &roundkeylen)) {
		EVP_MD_CTX_free(mdctx);
		return false;
	}
	EVP_MD_CTX_free(mdctx);
	if (roundkeylen != KEY_SIZE) {
		return false;
	}
	return true;
}

