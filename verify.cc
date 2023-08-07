#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <openssl/evp.h>
#include "verify.h"
#include "key.h"
#include "config.h"
#include "util.h"

int Verify::run(uint8_t const* key)
{
	uint8_t buffer[BLOCK_SIZE + MAC_SIZE];
	memset(buffer, 0, sizeof(buffer));
	uint8_t mac[MAC_SIZE];
	uint64_t counter = 0;
	bool success = true;
	EVP_MAC* macalgo = EVP_MAC_fetch(nullptr, "poly1305", nullptr);
	if (macalgo == nullptr) {
		return -11;
	}

	uint8_t iv[IV_SIZE];
	size_t bytes = fread(iv, 1, IV_SIZE, stdin);
	if (ferror(stdin)) {
		fprintf(stderr, "I/O error\n");
		return -11;
	}
	if (bytes < IV_SIZE) {
		fprintf(stderr, "I/O error\n");
		return -12;
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
			EVP_MAC_CTX_free(ctx);
			success = false;
			break;
		}
		if (!EVP_MAC_update(ctx, buffer + BLOCK_SIZE, MAC_SIZE)) {
			EVP_MAC_CTX_free(ctx);
			success = false;
			break;
		}
		bytes = fread(buffer, 1, sizeof(buffer), stdin);
		if (ferror(stdin)) {
			success = false;
			break;
		}
		if (bytes < MAC_SIZE) {
			success = false;
			break;
		}
		if (!EVP_MAC_update(ctx, buffer, bytes - MAC_SIZE)) {
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
		if (memcmp(buffer + bytes - MAC_SIZE, mac, MAC_SIZE) == 0) {
			if (fwrite(buffer, 1, bytes - MAC_SIZE, stdout) != bytes - MAC_SIZE) {
				success = false;
				break;
			}
		} else {
			fprintf(stderr, "Invalid mac\n");
			return -11;
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
		return -10;
	}
}

