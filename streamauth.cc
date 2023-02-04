#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "add.h"
#include "verify.h"
#include "util.h"
#include "config.h"

void usage()
{
	fprintf(stderr, "usage: streamauth add <key> <iv>\n");
	fprintf(stderr, "       streamauth verfiy <key> <iv>\n");
}

bool get_hex_or_env(char const* text, uint8_t* buffer, size_t length)
{
	if (ishex(text, strlen(text))) {
		parsehex(text, strlen(text), buffer, length);
		return true;
	} else {
		char* envval = getenv(text);
		if (envval != nullptr && ishex(envval, strlen(envval))) {
			parsehex(envval, strlen(envval), buffer, length);
			return true;
		} else {
			return false;
		}
	}
}

int main (int argc, char *argv[])
{
	if (argc < 3) {
		usage();
		return -1;
	}

	uint8_t key[KEY_SIZE];
	memset(key, 0, sizeof(key));
	get_hex_or_env(argv[2], key, sizeof(key));

	uint8_t iv[MAC_SIZE];
	memset(iv, 0, sizeof(iv));
	if (argc >= 4) {
		get_hex_or_env(argv[3], iv, sizeof(iv));
	}

	if (strcmp(argv[1], "add") == 0) {
		Add* add = new Add();
		int result = add->run(key, iv);
		delete add;
		return result;
	} else if (strcmp(argv[1], "verify") == 0) {
		Verify* verify = new Verify();
		int result = verify->run(key, iv);
		delete verify;
		return result;
	} else {
		usage();
		return -1;
	}
}
