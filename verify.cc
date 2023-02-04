#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include "verify.h"
#include "config.h"
#include "hmac_sha2.h"

int Verify::run(uint8_t const* key, uint8_t const* iv)
{
	uint8_t buffer[BLOCK_SIZE + MAC_SIZE];
	memcpy(buffer + BLOCK_SIZE, iv, MAC_SIZE);
	uint8_t mac[MAC_SIZE];
	bool success = true;

	while (feof(stdin) == 0) {
		hmac_sha256_ctx ctx;
		hmac_sha256_init(&ctx, key, 32);
		hmac_sha256_update(&ctx, buffer + BLOCK_SIZE, MAC_SIZE);
		size_t bytes = fread(buffer, 1, sizeof(buffer), stdin);
		if (bytes < MAC_SIZE) {
			success = false;
			break;
		}
		hmac_sha256_update(&ctx, buffer, bytes - MAC_SIZE);
		hmac_sha256_final(&ctx, mac, MAC_SIZE);
		if (memcmp(buffer + bytes - MAC_SIZE, mac, MAC_SIZE) == 0) {
			if (fwrite(buffer, 1, bytes - MAC_SIZE, stdout) != bytes - MAC_SIZE) {
				success = false;
				break;
			}
		} else {
			fprintf(stderr, "Invalid mac\n");
			return -11;
		}
	}

	fclose(stdin);
	fclose(stdout);

	if (success) {
		return 0;
	} else {
		fprintf(stderr, "I/O error\n");
		return -10;
	}
}

