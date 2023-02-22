#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include "add.h"
#include "config.h"
#include "hmac_sha2.h"

int Add::run(uint8_t const* key, uint8_t const* iv)
{
	uint8_t buffer[BLOCK_SIZE];
	uint8_t mac[MAC_SIZE];
	memcpy(mac, iv, MAC_SIZE);
	bool success = true;

	while (feof(stdin) == 0) {
		hmac_sha256_ctx ctx;
		hmac_sha256_init(&ctx, key, 32);
		hmac_sha256_update(&ctx, mac, MAC_SIZE);
		size_t bytes = fread(buffer, 1, BLOCK_SIZE, stdin);
		if (ferror(stdin)) {
			success = false;
			break;
		}
		hmac_sha256_update(&ctx, buffer, bytes);
		hmac_sha256_final(&ctx, mac, MAC_SIZE);
		if (fwrite(buffer, 1, bytes, stdout) != bytes) {
			success = false;
			break;
		}
		if (fwrite(mac, 1, MAC_SIZE, stdout) != MAC_SIZE) {
			success = false;
			break;
		}
	}

	fclose(stdin);
	fclose(stdout);

	if (success) {
		return 0;
	} else {
		fprintf(stderr, "I/O error\n");
		return -20;
	}
}

