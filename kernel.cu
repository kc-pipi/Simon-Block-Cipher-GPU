#include "cuda_runtime.h"
#include "device_launch_parameters.h"
#include "device_functions.h"
#include <cuda.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>
#include <stdlib.h>
#include <inttypes.h>
#include <time.h>
#include "Simon.h"

// Cipher Operation Macros
#define shift_one ((x_word << 1) | (x_word >> (word_size - 1)))
#define shift_eight ((x_word << 8) | (x_word >> (word_size - 8)))
#define shift_two ((x_word << 2) | (x_word >> (word_size - 2)))
#define rshift_three(x) (x >> 3) |((x & 0x7) << (word_size - 3))
#define rshift_one(x)   (x >> 1) |((x & 0x1) << (word_size - 1))

uint64_t z_arrays[5] = { 0x19C3522FB386A45F, 0x16864FB8AD0C9F71, 0x3369F885192C0EF5, 0x3C2CE51207A635DB, 0x3DC94C3A046D678B };

// Valid Cipher Parameters
const uint8_t simon_rounds[] = { 32, 36, 36, 42, 44, 52, 54, 68, 69, 72 };
const uint8_t simon_block_sizes[] = { 32, 48, 48, 64, 64, 96, 96, 128, 128, 128 };
const uint16_t simon_key_sizes[] = { 64, 72, 96, 96, 128, 96, 144, 128, 192, 256 };
const uint8_t  z_assign[] = { 0, 0, 1, 2, 3, 2, 3, 2, 3, 4 };

uint8_t Simon_Init(Simon_Cipher *cipher_object, enum simon_cipher_config_t cipher_cfg, enum mode_t c_mode, uint8_t *key, uint8_t *iv, uint8_t *counter) {

	if (cipher_cfg != Simon_128_128) {
		return -1;
	}

	cipher_object->block_size = simon_block_sizes[cipher_cfg];
	cipher_object->key_size = simon_key_sizes[cipher_cfg];
	cipher_object->round_limit = simon_rounds[cipher_cfg];
	cipher_object->cipher_cfg = cipher_cfg;
	cipher_object->z_seq = z_assign[cipher_cfg];
	uint8_t word_size = simon_block_sizes[cipher_cfg] >> 1;
	uint8_t word_bytes = word_size >> 3;
	uint8_t key_words = simon_key_sizes[cipher_cfg] / word_size;
	uint64_t sub_keys[4] = {};
	uint64_t mod_mask = ULLONG_MAX >> (64 - word_size);

	// Setup
	for (int i = 0; i < key_words; i++) {
		memcpy(&sub_keys[i], key + (word_bytes * i), word_bytes);
	}

	uint64_t tmp1, tmp2;
	uint64_t c = 0xFFFFFFFFFFFFFFFC;

	// Store First Key Schedule Entry
	memcpy(cipher_object->key_schedule, &sub_keys[0], word_bytes);

	for (int i = 0; i < simon_rounds[cipher_cfg] - 1; i++) {
		tmp1 = rshift_three(sub_keys[key_words - 1]);

		if (key_words == 4) {
			tmp1 ^= sub_keys[1];
		}

		tmp2 = rshift_one(tmp1);
		tmp1 ^= sub_keys[0];
		tmp1 ^= tmp2;

		tmp2 = c ^ ((z_arrays[cipher_object->z_seq] >> (i % 62)) & 1);

		tmp1 ^= tmp2;

		// Shift Sub Words
		for (int j = 0; j < (key_words - 1); j++){
			sub_keys[j] = sub_keys[j + 1];
		}
		sub_keys[key_words - 1] = tmp1 & mod_mask;

		// Append sub key to key schedule
		memcpy(cipher_object->key_schedule + (word_bytes * (i + 1)), &sub_keys[0], word_bytes);
	}

	return 0;
}

void Simon_Encrypt_128(Simon_Cipher *cipher_object, uint8_t *plaintext, uint8_t *ciphertext) {

	const uint8_t word_size = 64;
	uint64_t y_word = *(uint64_t *)plaintext;
	uint64_t x_word = *(((uint64_t *)plaintext) + 1);
	uint64_t *round_key_ptr = (uint64_t *)cipher_object->key_schedule;
	uint64_t *word_ptr = (uint64_t *)ciphertext;

	for (uint8_t i = 0; i < cipher_object->round_limit; i++) {  // Block size 32 has only one round number option

		// Shift, AND , XOR ops
		uint64_t temp = (shift_one & shift_eight) ^ y_word ^ shift_two;

		// Feistel Cross
		y_word = x_word;

		// XOR with Round Key
		x_word = temp ^ *(round_key_ptr + i);
		//printf("x: %d, %"PRIx64"\n", i, x_word);
	}
	// Assemble Ciphertext Output Array   
	*word_ptr = y_word;
	*(word_ptr + 1) = x_word;
}

__global__ void Simon_Decrypt_128(Simon_Cipher *cipher_object, uint8_t* keySchedule, uint8_t *ciphertext, uint8_t *plaintext)
{
	const uint8_t word_size = 64;
	uint64_t x_word = *(uint64_t *)ciphertext;
	uint64_t y_word = *(((uint64_t *)ciphertext) + 1);
	uint64_t *round_key_ptr = (uint64_t *)(keySchedule);
	uint64_t *word_ptr = (uint64_t *)plaintext;

	//printf("x_word %02x\n", x_word);
	//printf("y_word %02x\n", y_word);

	//printf("\n\n");

	//printf("round_limit %d\n", cipher_object->round_limit);
	int8_t round_limit_minus_one = cipher_object->round_limit - 1;

	for (int8_t i = round_limit_minus_one; i >= 0; i--) {

		//printf(" x: %d, %"PRIx64"\n", i, x_word);
		//printf("y: %d, %"PRIx64"\n", i, y_word);

		// Shift, AND , XOR ops
		//uint64_t temp = (shift_one & shift_eight) ^ y_word ^ shift_two;
		uint64_t temp = (((x_word << 1) | (x_word >> (word_size - 1))) &
			((x_word << 8) | (x_word >> (word_size - 8)))) ^ y_word ^
			((x_word << 2) | (x_word >> (word_size - 2)));
		//printf("temp %02d: %"PRIx64"\n", i, temp);

		// Feistel Cross
		y_word = x_word;
		//printf("x_word, y_word after (y_word = x_word) %02d: %02x, %02x\n", i, x_word, y_word);

		// XOR with Round Key
		x_word = temp ^ *(round_key_ptr + i);
	}

	// Assemble Plaintext Output Array   
	*word_ptr = x_word;
	*(word_ptr + 1) = y_word;

	return;
}

int main(void) {
	clock_t start = clock();

	// Create reuseable cipher objects for each alogirthm type
	Simon_Cipher my_simon_cipher = *(Simon_Cipher *)malloc(sizeof(Simon_Cipher));

	// Create generic tmp variables
	uint8_t ciphertext_buffer[16];

	uint8_t deciphertext_buffer[16];
	uint32_t result;

	// Initialize IV and Counter Values for Use with Block Modes
	uint8_t my_IV[] = { 0x32, 0x14, 0x76, 0x58 };
	uint8_t my_counter[] = { 0x2F, 0x3D, 0x5C, 0x7B };
	Simon_Cipher *d_my_simon_cipher;
	uint8_t *d_simon128_128_plain, *d_ciphertext_buffer, *d_simon128_128_cipher;
	uint8_t *d_key_schedule;

	printf("***********************************\n");
	printf("******* Simon Cipher Tests ********\n");
	printf("***********************************\n");

	// Simon 128/128 Test
	// Key: 0f0e0d0c0b0a0908 0706050403020100 Plaintext: 6373656420737265 6c6c657661727420 Ciphertext: 49681b1e1e54fe3f 65aa832af84e0bbc
	printf("Test Simon 128/128\n");
	uint8_t simon128_128_key[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
	uint8_t simon128_128_plain[] = { 0x21, 0x75, 0x6a, 0x84, 0x76, 0x65, 0x6c, 0x6c, 0x65, 0x72, 0x73, 0x20, 0x90, 0x88, 0x73, 0x63 };
	uint8_t simon128_128_cipher[16];
	result = Simon_Init(&my_simon_cipher, Simon_128_128, ECB, simon128_128_key, my_IV, my_counter);

	printf("\nEncryption Test:\n");

	Simon_Encrypt_128(&my_simon_cipher, simon128_128_plain, ciphertext_buffer);

	for (int i = 0; i < 16; i++) {
		printf("Ciphertext Byte %02d: %02x - %02x", i, simon128_128_plain[i], ciphertext_buffer[i]);
		simon128_128_cipher[i] = ciphertext_buffer[i];
		printf("\n");
	}

	cudaMalloc((Simon_Cipher**)&d_my_simon_cipher, sizeof(Simon_Cipher));
	cudaMalloc((void **)&d_simon128_128_cipher, sizeof(uint8_t) * sizeof(simon128_128_cipher));
	cudaMalloc((void **)&d_ciphertext_buffer, sizeof(uint8_t) * sizeof(ciphertext_buffer));
	cudaMalloc((void **)&d_key_schedule, sizeof(uint8_t) * sizeof(my_simon_cipher.key_schedule)); // 576 is size of key_schedule array

	if (0 != cudaMemcpy(d_my_simon_cipher, &my_simon_cipher, sizeof(Simon_Cipher), cudaMemcpyHostToDevice)) {
		printf("Mem allocation error n");
		getchar();
	}

	if (0 != cudaMemcpy(d_simon128_128_cipher, simon128_128_cipher, sizeof(uint8_t) * sizeof(simon128_128_cipher), cudaMemcpyHostToDevice)) {
		printf("Mem allocation error n");
		getchar();
	}

	if (0 != cudaMemcpy(d_ciphertext_buffer, ciphertext_buffer, sizeof(uint8_t) * sizeof(ciphertext_buffer), cudaMemcpyHostToDevice)) {
		printf("Mem allocation error n");
		getchar();
	}

	cudaMemcpy(d_key_schedule, my_simon_cipher.key_schedule, sizeof(uint8_t) *  sizeof(my_simon_cipher.key_schedule), cudaMemcpyHostToDevice);

	Simon_Decrypt_128 <<<1, 1>>>(d_my_simon_cipher, d_key_schedule, d_simon128_128_cipher, d_ciphertext_buffer);
	cudaDeviceSynchronize();

	cudaMemcpy(&my_simon_cipher, d_my_simon_cipher, sizeof(Simon_Cipher), cudaMemcpyDeviceToHost);
	cudaMemcpy(simon128_128_cipher, d_simon128_128_cipher, sizeof(uint8_t) * sizeof(simon128_128_cipher), cudaMemcpyDeviceToHost);
	cudaMemcpy(ciphertext_buffer, d_ciphertext_buffer, sizeof(uint8_t) * sizeof(ciphertext_buffer), cudaMemcpyDeviceToHost);

	printf("\nDecryption Test:\n");
	for (int i = 0; i < 16; i++) {
		printf("Plaintext Byte %02d: %02x", i, ciphertext_buffer[i]);
		if (ciphertext_buffer[i] != simon128_128_plain[i]) printf("  FAIL\n");
		else printf("\n");
	}
	printf("\n");

	cudaFree(d_my_simon_cipher);
	cudaFree(d_ciphertext_buffer);
	cudaFree(d_simon128_128_cipher);

	clock_t stop = clock();

	printf("Time Taken: %f seconds\n", ((double)stop - start) / CLOCKS_PER_SEC);

	system("pause");

	return 0;
}