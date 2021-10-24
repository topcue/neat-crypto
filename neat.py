#!/usr/bin/python3
# -*- coding: utf-8 -*-

INT_BITS = 16
INT_SIZE = 0xFFFF

key_const = [0xFD56, 0xC7D1, 0xE36C, 0xA2DC]
fixed_xcon = [0, 1, 0, 1, 2, 3, 2, 3]
xbox = [
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
]

def rotate_left(n, d):
	d &= 0xF
	return (((n << d) & INT_SIZE) | (n >> (INT_BITS - d)))

def rotate_right(n, d):
	d &= 0xF
	return (((n >> d) & INT_SIZE) | (n << (INT_BITS - d)))

def mul(a, b):
	if a == 0:
		a = 0x10000
	if b == 0:
		b = 0x10000
	return (((a * b) % 0x10001) & INT_SIZE)

def inv_mul(a):
	# calc multiplicative inverse with fermat's little theorem
	return pow(a, 65535, 0x10001)


class NEAT():
	round_keys = []
	round_xcons = []
	dec_round_keys = []
	dec_round_xcons = []
	
	def __init__(self, key):
		self.key_schedule(key)
		self.dekey_schedule()
	
	def f_function(self, x, k):
		x[1] ^= x[0]
		x[2] ^= x[3]
		x[0] = (x[0]+x[2]) & INT_SIZE
		x[3] = (x[3]+x[1]) & INT_SIZE
		x[1] = mul(x[1], k[0])
		x[2] = mul(x[2], k[1])
		x[0] = rotate_left(x[0], x[1])
		x[3] = rotate_left(x[3], x[2])
		x[1] = (x[1] + x[3]) & INT_SIZE
		x[2] = (x[2] + x[0]) & INT_SIZE

	def inv_f_function(self, x, k):
		x[1] = (x[1] - x[3]) & INT_SIZE
		x[2] = (x[2] - x[0]) & INT_SIZE
		x[0] = rotate_right(x[0], x[1])
		x[3] = rotate_right(x[3], x[2])
		x[1] = mul(x[1], k[2])
		x[2] = mul(x[2], k[3])
		x[0] = (x[0] - x[2]) & INT_SIZE
		x[3] = (x[3] - x[1]) & INT_SIZE
		x[1] ^= x[0]
		x[2] ^= x[3]

	def xor_layer(self, x, xcon):
		x[xcon[0]] ^= x[xcon[2] + 4]
		x[xcon[1]] ^= x[xcon[3] + 4]
		x[xcon[4] + 4] ^= x[xcon[6]]
		x[xcon[5] + 4] ^= x[xcon[7]]

	def round_function(self, x, k, xcon):
		l, r = x[:4], x[4:]
		self.f_function(l, k)
		self.inv_f_function(r, k)
		x = l + r
		self.xor_layer(x, xcon)
		return x

	def key_schedule(self, key):
		x = []
		rk = []

		# block to uint16	
		for i in range(0, 16, 2):
			x.append(key[i] << 8 | key[i+1])

		# generate 13 round keys
		for i in range(7):
			x = self.round_function(x, key_const, fixed_xcon)
			rk.append(x[:4])
			rk.append(x[4:])
		self.round_keys = rk[:13]

		# generate 12 round xcon
		for i in range(12):
			pos = ((rk[i][0] ^ rk[i][3]) & 0x7F) * 8
			xcon = xbox[pos:pos + 8]
			self.round_xcons.append(xcon)
		
	def dekey_schedule(self):
		# generate 13 dec round keys
		rev_rk = self.round_keys[::-1]
		for i in range(13):
			dec_rk = inv_mul(rev_rk[i][2]), inv_mul(rev_rk[i][3]), inv_mul(rev_rk[i][0]), inv_mul(rev_rk[i][1])
			self.dec_round_keys.append(list(dec_rk))

		# generate 12 dec round xcon
		rk = self.round_keys
		for i in range(12):
			pos = ((rk[i][0] ^ rk[i][3]) & 0x7F) * 8
			xcon = xbox[pos:pos + 8]
			xcon[:4], xcon[4:] = xcon[4:], xcon[:4]
			self.dec_round_xcons.append(xcon)
		self.dec_round_xcons = self.dec_round_xcons[::-1]


	def encrypt(self, in_block):
		rk = self.round_keys
		rx = self.round_xcons
		out_block = self.neat_crypt(in_block, rk, rx)
		return out_block

	def decrypt(self, in_block):
		rk = self.dec_round_keys
		rx = self.dec_round_xcons
		out_block = self.neat_crypt(in_block, rk, rx)
		return out_block

	def neat_crypt(self, in_block, rk, rx):
		x = []
		out_block = []
		
		# block to uint16
		for i in range(0, 16, 2):
			x.append(in_block[i] | (in_block[i+1] << 8))
		
		# 12 round function
		for i in range(12):
			x = self.round_function(x, rk[i], rx[i])
		
		# half round
		l, r = x[:4], x[4:]
		self.f_function(l, rk[12])
		self.inv_f_function(r, rk[12])
		x = l + r

		# final swap
		x[:4], x[4:] = x[4:], x[:4]
		
		# uint16 to block
		for i in range(0, 8):
			out_block.append(x[i] & 0xFF)
			out_block.append(x[i] >> 8)

		return bytes(out_block)


def main():
	print("[*] Preprocess")
	# key = bytes.fromhex("4142434445464748494A4B4C4D4E4F50")
	key = b'ABCDEFGHIJKLMNOP'
	print("[*] key:", key)
	neat = NEAT(key)

	plaintext = b'M4KE_NE4T_NE4TER'
	print("[*] plaintext:", plaintext)

	print("\n[*] Encrypt")
	ciphertext = neat.encrypt(plaintext)
	print("[*] ciphertext:", ciphertext)
	
	print("\n[*] Decrypt")
	recovered = neat.decrypt(ciphertext)
	print("[*] recovered:", recovered)


if __name__ == '__main__':
	main()

# EOF
