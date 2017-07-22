#ifndef SIMON_H
#define SIMON_H

#ifndef CIPHER_CONSTANTS
#define CIPHER_CONSTANTS
enum mode_t { ECB, CTR, CBC, CFB, OFB };
#endif
#include <stdio.h>
#include <stdint.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

enum simon_cipher_config_t {
	Simon_128_128
};

typedef struct {
	enum simon_cipher_config_t cipher_cfg;
	uint16_t key_size;
	uint16_t block_size;
	uint8_t round_limit;
	uint8_t init_vector[16];
	uint8_t counter[16];
	uint8_t key_schedule[576];
	uint8_t z_seq;
} Simon_Cipher;

typedef struct _bword_24{
	uint32_t data : 24;
} bword_24;

typedef struct _bword_48{
	uint64_t data : 48;
} bword_48;

#endif