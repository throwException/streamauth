#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "add.h"
#include "key.h"
#include "config.h"
#include "util.h"

int Add::run(uint8_t const* key)
{
	uint8_t buffer[BLOCK_SIZE];
	uint8_t mac[MAC_SIZE];
	memset(mac, 0, MAC_SIZE);
	uint64_t counter = 0;
	bool success = true;
	EVP_MAC* macalgo = EVP_MAC_fetch(nullptr, "poly1305", nullptr);
	if (macalgo == nullptr) {
		fprintf(stderr, "I/O error\n");
		return -21;
	}
	uint8_t iv[IV_SIZE];
	if (!RAND_bytes(iv, IV_SIZE)) {
		fprintf(stderr, "I/O error\n");
		return -22;
	}
	if (fwrite(iv, 1, IV_SIZE, stdout) != IV_SIZE) {
		fprintf(stderr, "I/O error\n");
		return -23;
	}

	while (feof(stdin) == 0) {
		uint8_t rkey[KEY_SIZE];
		if (!create_roundkey(key, iv, counter, rkey)) {
			success = false;
			break;
		}
		EVP_MAC_CTX* ctx = EVP_MAC_CTX_new(macalgo);
		if (ctx == nullptr) {
			success = false;
			break;
		}
		if (!EVP_MAC_init(ctx, rkey, KEY_SIZE, nullptr)) {
			char errbuf[256];
			EVP_MAC_CTX_free(ctx);
			success = false;
			break;
		}
		if (!EVP_MAC_update(ctx, mac, MAC_SIZE)) {
			EVP_MAC_CTX_free(ctx);
			success = false;
			break;
		}
		size_t bytes = fread(buffer, 1, BLOCK_SIZE, stdin);
		if (ferror(stdin)) {
			EVP_MAC_CTX_free(ctx);
			success = false;
			break;
		}
		if (!EVP_MAC_update(ctx, buffer, bytes)) {
			EVP_MAC_CTX_free(ctx);
			success = false;
			break;
		}
		size_t maclen = 0;
		if (!EVP_MAC_final(ctx, mac, &maclen, MAC_SIZE)) {
			EVP_MAC_CTX_free(ctx);
			success = false;
			break;
		}
		EVP_MAC_CTX_free(ctx);
		if (maclen != MAC_SIZE) {
			success = false;
			break;
		}
		if (fwrite(buffer, 1, bytes, stdout) != bytes) {
			success = false;
			break;
		}
		if (fwrite(mac, 1, MAC_SIZE, stdout) != MAC_SIZE) {
			success = false;
			break;
		}
		counter++;
	}

	EVP_MAC_free(macalgo);
	fclose(stdin);
	fclose(stdout);

	if (success) {
		return 0;
	} else {
		fprintf(stderr, "I/O error\n");
		return -20;
	}
}

