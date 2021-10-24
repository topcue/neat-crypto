#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define SWAP(A, B) { uint16_t T; T = A; A = B; B = T; }

typedef struct neat_key_struct_s {
	uint16_t	enc_round_keys[13][4];
	uint16_t	dec_round_keys[13][4];
	uint8_t		enc_round_xcons[12][8];
	uint8_t		dec_round_xcons[12][8];
} neat_key_struct_t;

const uint16_t key_const[] = {
	0xFD56, 0xC7D1, 0xE36C, 0xA2DC
};

const uint8_t fixed_xcon[] = {
	0, 1, 0, 1, 2, 3, 2, 3
};

const uint8_t xbox[] = {
	0, 1, 0, 1, 2, 3, 2, 3, 0, 1, 0, 1, 2, 3, 3, 2, 0, 1, 1, 0, 2, 3, 2, 3, 0, 1, 1, 0, 2, 3, 3, 2,
	0, 1, 0, 2, 1, 3, 3, 2, 0, 1, 2, 0, 1, 3, 2, 3, 0, 1, 2, 0, 1, 3, 3, 2, 0, 1, 0, 3, 1, 2, 2, 3,
	0, 1, 0, 3, 1, 2, 3, 2, 0, 1, 3, 0, 1, 2, 2, 3, 0, 1, 3, 0, 1, 2, 3, 2, 0, 1, 1, 2, 0, 3, 2, 3,
	0, 1, 1, 2, 0, 3, 3, 2, 0, 1, 2, 1, 0, 3, 2, 3, 0, 1, 2, 1, 0, 3, 3, 2, 0, 1, 1, 3, 0, 2, 2, 3,
	0, 1, 1, 3, 0, 2, 3, 2, 0, 1, 3, 1, 0, 2, 2, 3, 0, 1, 3, 1, 0, 2, 3, 2, 0, 1, 2, 3, 0, 1, 3, 2,
	0, 1, 3, 2, 0, 1, 2, 3, 0, 2, 0, 1, 2, 3, 3, 1, 0, 2, 1, 0, 2, 3, 1, 3, 0, 2, 1, 0, 2, 3, 3, 1,
	0, 2, 0, 2, 1, 3, 1, 3, 0, 2, 0, 2, 1, 3, 3, 1, 0, 2, 2, 0, 1, 3, 1, 3, 0, 2, 2, 0, 1, 3, 3, 1,
	0, 2, 0, 3, 1, 2, 1, 3, 0, 2, 0, 3, 1, 2, 3, 1, 0, 2, 3, 0, 1, 2, 1, 3, 0, 2, 3, 0, 1, 2, 3, 1,
	0, 2, 1, 2, 0, 3, 1, 3, 0, 2, 1, 2, 0, 3, 3, 1, 0, 2, 2, 1, 0, 3, 1, 3, 0, 2, 2, 1, 0, 3, 3, 1,
	0, 2, 1, 3, 0, 2, 1, 3, 0, 2, 3, 1, 0, 2, 1, 3, 0, 2, 3, 1, 0, 2, 3, 1, 0, 2, 2, 3, 0, 1, 1, 3,
	0, 2, 2, 3, 0, 1, 3, 1, 0, 2, 3, 2, 0, 1, 1, 3, 0, 2, 3, 2, 0, 1, 3, 1, 0, 3, 0, 1, 2, 3, 2, 1,
	0, 3, 0, 1, 2, 3, 1, 2, 0, 3, 1, 0, 2, 3, 2, 1, 0, 3, 1, 0, 2, 3, 1, 2, 0, 3, 0, 2, 1, 3, 2, 1,
	0, 3, 0, 2, 1, 3, 1, 2, 0, 3, 2, 0, 1, 3, 2, 1, 0, 3, 2, 0, 1, 3, 1, 2, 0, 3, 0, 3, 1, 2, 2, 1,
	0, 3, 3, 0, 1, 2, 2, 1, 0, 3, 1, 2, 0, 3, 2, 1, 0, 3, 1, 2, 0, 3, 1, 2, 0, 3, 2, 1, 0, 3, 2, 1,
	0, 3, 2, 1, 0, 3, 1, 2, 0, 3, 1, 3, 0, 2, 2, 1, 0, 3, 1, 3, 0, 2, 1, 2, 0, 3, 3, 1, 0, 2, 2, 1,
	0, 3, 3, 1, 0, 2, 1, 2, 0, 3, 2, 3, 0, 1, 2, 1, 0, 3, 2, 3, 0, 1, 1, 2, 0, 3, 3, 2, 0, 1, 2, 1,
	0, 3, 3, 2, 0, 1, 1, 2, 1, 2, 0, 1, 2, 3, 0, 3, 1, 2, 0, 1, 2, 3, 3, 0, 1, 2, 1, 0, 2, 3, 0, 3,
	1, 2, 1, 0, 2, 3, 3, 0, 1, 2, 0, 2, 1, 3, 0, 3, 1, 2, 0, 2, 1, 3, 3, 0, 1, 2, 2, 0, 1, 3, 0, 3,
	1, 2, 2, 0, 1, 3, 3, 0, 1, 2, 0, 3, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 0, 3, 1, 2, 3, 0, 1, 2, 3, 0,
	1, 2, 1, 2, 0, 3, 0, 3, 1, 2, 1, 2, 0, 3, 3, 0, 1, 2, 2, 1, 0, 3, 0, 3, 1, 2, 2, 1, 0, 3, 3, 0,
	1, 2, 1, 3, 0, 2, 3, 0, 1, 2, 3, 1, 0, 2, 0, 3, 1, 2, 3, 1, 0, 2, 3, 0, 1, 2, 2, 3, 0, 1, 0, 3,
	1, 2, 2, 3, 0, 1, 3, 0, 1, 2, 3, 2, 0, 1, 0, 3, 1, 2, 3, 2, 0, 1, 3, 0, 1, 3, 0, 1, 2, 3, 0, 2,
	1, 3, 1, 0, 2, 3, 0, 2, 1, 3, 0, 2, 1, 3, 0, 2, 1, 3, 0, 2, 1, 3, 2, 0, 1, 3, 2, 0, 1, 3, 0, 2,
	1, 3, 2, 0, 1, 3, 2, 0, 1, 3, 0, 3, 1, 2, 0, 2, 1, 3, 0, 3, 1, 2, 2, 0, 1, 3, 3, 0, 1, 2, 0, 2,
	1, 3, 3, 0, 1, 2, 2, 0, 1, 3, 1, 2, 0, 3, 0, 2, 1, 3, 1, 2, 0, 3, 2, 0, 1, 3, 2, 1, 0, 3, 0, 2,
	1, 3, 2, 1, 0, 3, 2, 0, 1, 3, 1, 3, 0, 2, 0, 2, 1, 3, 1, 3, 0, 2, 2, 0, 1, 3, 3, 1, 0, 2, 0, 2,
	1, 3, 3, 1, 0, 2, 2, 0, 1, 3, 2, 3, 0, 1, 2, 0, 1, 3, 3, 2, 0, 1, 0, 2, 2, 3, 0, 1, 2, 3, 0, 1,
	2, 3, 0, 1, 2, 3, 1, 0, 2, 3, 1, 0, 2, 3, 1, 0, 2, 3, 0, 2, 1, 3, 0, 1, 2, 3, 0, 2, 1, 3, 1, 0,
	2, 3, 2, 0, 1, 3, 0, 1, 2, 3, 2, 0, 1, 3, 1, 0, 2, 3, 0, 3, 1, 2, 0, 1, 2, 3, 0, 3, 1, 2, 1, 0,
	2, 3, 3, 0, 1, 2, 0, 1, 2, 3, 3, 0, 1, 2, 1, 0, 2, 3, 1, 2, 0, 3, 0, 1, 2, 3, 1, 2, 0, 3, 1, 0,
	2, 3, 2, 1, 0, 3, 0, 1, 2, 3, 2, 1, 0, 3, 1, 0, 2, 3, 1, 3, 0, 2, 0, 1, 2, 3, 1, 3, 0, 2, 1, 0,
	2, 3, 3, 1, 0, 2, 1, 0, 2, 3, 2, 3, 0, 1, 0, 1, 2, 3, 2, 3, 0, 1, 1, 0, 2, 3, 3, 2, 0, 1, 1, 0
};

uint16_t mul(uint32_t a, uint32_t b) {
	if (a == 0)
		a = 0x10000;
	if (b == 0)
		b = 0x10000;
	return (a * b) % 0x10001;
}

uint16_t inv_mul(uint16_t a) {
	// calc multiplicative inverse with extended euclidean algorithm
	if (a <= 1)
		return a;

	int m = 0x10001, x = 0, x0 = 1, q, tmp;

	while (a) {
		q = m / a, tmp = x;
		x = x0, x0 = tmp - q * x0;
		tmp = m, m = a;
		a = tmp - q * a;
	}

	return (x + 0x10001) % 0x10001;
}

uint16_t rotate_left (uint16_t n, uint16_t d) {
	d &= 0xF;
	return (n << d) | (n >> (16 - d));
}

uint16_t rotate_right (uint16_t n, uint16_t d) {
	d &= 0xF;
	return (n << (16 - d)) | (n >> d);
}

void f_function(uint16_t* x, const uint16_t* k) {
	x[1] ^= x[0];
	x[2] ^= x[3];
	x[0] += x[2];
	x[3] += x[1];
	x[1] = mul(x[1], k[0]);
	x[2] = mul(x[2], k[1]);
	x[0] = rotate_left(x[0], x[1]);
	x[3] = rotate_left(x[3], x[2]);
	x[1] += x[3];
	x[2] += x[0];
}

void inv_f_function(uint16_t* x, const uint16_t* k) {
	x[1] -= x[3];
	x[2] -= x[0];
	x[0] = rotate_right(x[0], x[1]);
	x[3] = rotate_right(x[3], x[2]);
	x[1] = mul(x[1], k[2]);
	x[2] = mul(x[2], k[3]);
	x[0] -= x[2];
	x[3] -= x[1];
	x[1] ^= x[0];
	x[2] ^= x[3];
}

void xor_layer(uint16_t* x, uint8_t* xcon) {
	x[xcon[0]] ^= x[xcon[2] + 4];
	x[xcon[1]] ^= x[xcon[3] + 4];
	x[xcon[4] + 4] ^= x[xcon[6]];
	x[xcon[5] + 4] ^= x[xcon[7]];
}

void round_function(uint16_t* x, uint16_t* rk, uint8_t* xcon) {
	f_function(x, rk);
	inv_f_function(x+4, rk);
	xor_layer(x, xcon);
}

void neat_enc_key_schedule(neat_key_struct_t* ks, uint8_t* key) {
	uint16_t x[8] = {0x0000, };
	uint16_t pos = -1;
	uint8_t xcon[8] = {0x0, };

	// block to uint16
	for (int i = 0; i < 16; i += 2)
		x[i / 2] = key[i + 1] | (key[i] << 8);

	// generate 12 round keys
	for (int i = 0; i < 12; i += 2) {
		round_function(&x, &key_const, &fixed_xcon);
		memcpy(ks->enc_round_keys[i], x, 8);
		memcpy(ks->enc_round_keys[i + 1], x + 4, 8);
	}
	// generate 1 round keys
	round_function(&x, &key_const, &fixed_xcon);
	memcpy(ks->enc_round_keys[12], x, 8);
	
	// generate 12 round xcon
	for (int i = 0; i < 12; ++i) {
		pos = ((ks->enc_round_keys[i][0] ^ ks->enc_round_keys[i][3]) & 0x7F) << 3;
		memcpy(ks->enc_round_xcons[i], &xbox[pos], 16);
	}
}

void neat_dec_key_schedule(neat_key_struct_t* ks, uint8_t* key) {
	// generate 13 dec round keys
	for (int i = 0; i < 13; ++i) {
		ks->dec_round_keys[i][0] = inv_mul(ks->enc_round_keys[12 - i][2]);
		ks->dec_round_keys[i][1] = inv_mul(ks->enc_round_keys[12 - i][3]);
		ks->dec_round_keys[i][2] = inv_mul(ks->enc_round_keys[12 - i][0]);
		ks->dec_round_keys[i][3] = inv_mul(ks->enc_round_keys[12 - i][1]);
	}
	
	// generate 12 dec round xcon
	for (int i = 0; i < 12; ++i) {
		memcpy(ks->dec_round_xcons[i], ks->enc_round_xcons[11 - i] + 4, 4);
		memcpy(ks->dec_round_xcons[i] + 4, ks->enc_round_xcons[11 - i], 4);
	}
}

void neat_init_key_schedule(neat_key_struct_t* ks, uint8_t* key) {
	neat_enc_key_schedule(ks, key);
	neat_dec_key_schedule(ks, key);
}

void neat_crypt(uint8_t* xb, uint16_t* rk, uint8_t* rx) {
	uint16_t x[8] = {0x0000, };

	// block to uint16
	for(int i = 0; i < 16; i += 2)
		x[i / 2] = xb[i] | (xb[i + 1] << 8);

	// 12 full rounds
	for(int i = 0; i < 12; ++i)
		round_function(x, &rk[i*4], &rx[i*8]);

	// half round
	f_function(&x[0], &rk[48]);
	inv_f_function(&x[4], &rk[48]);

	// final swap
	for (int i = 0; i < 4; ++i)
		SWAP(x[i], x[i + 4]);

	// convert back to bytes
	for (int i = 0; i < 16; i += 2) {
		xb[i] = x[i / 2];
		xb[i + 1] = x[i / 2] >> 8;
	}
}

void neat_encrypt(uint8_t* xb, const neat_key_struct_t* ks) {
	neat_crypt(xb, &ks->enc_round_keys, &ks->enc_round_xcons);
}

void neat_decrypt(uint8_t* xb, const neat_key_struct_t* ks) {
	neat_crypt(xb, &ks->dec_round_keys, &ks->dec_round_xcons);
}

void show_as_hex(uint8_t* x) {
	for (int i = 0; i < 16; ++i)
		printf("%02X", x[i]);
	printf("\n");
}

void show_as_str(uint8_t* x) {
	for (int i = 0; i < 16; ++i)
		printf("%c", x[i]);
	printf("\n");
}

int main (int argc, char* argv[]) {
	uint8_t key[16] = {	0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
						0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50 };
	uint8_t x[16] = {	0x4d, 0x34, 0x4b, 0x45, 0x5f, 0x4e, 0x45, 0x34,
						0x54, 0x5f, 0x4e, 0x45, 0x34, 0x54, 0x45, 0x52 };

	printf("[*] key:\t");
	show_as_hex(&key);

	neat_key_struct_t ks;
	neat_init_key_schedule(&ks, key);

	printf("[*] plaintext:\t");
	show_as_hex(&x);
	neat_encrypt(x, &ks);
	
	printf("[*] ciphertext:\t");
	show_as_hex(&x);

	neat_decrypt(x, &ks);
	printf("[*] recovered:\t");
	show_as_str(&x);

}

// EOF
