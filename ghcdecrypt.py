#!/usr/bin/env python3
import re
import sys
import array

val = '^#com.ghc.1![0-9A-F]+$'
key = array.array('H', [0x12FD, 0x4AAD, 0x4405, 0xE327, 0xA28A, 0x7211, 0x1111, 0x5543, 0x0CDD, 0x6A31, 0x4080, 0x217E, 0x7E73])

def decrypt(e):
	p = re.compile(val, re.IGNORECASE)
	if p.match(e) and len(e) > 19 and len(e) % 2 == 1: 
		seed = int(e[11:15], 16)
		enc = bytes.fromhex(e[15:])
		index = seed

		i = 0
		xor = array.array('H')
		while i < (len(enc) // 2):
			j = index % len(key)
			xor.append(key[j])
			index += 1
			i += 1
			
		i = 0
		pwd = ''
		while i < len(enc):
			c = (enc[i] << 8) + enc[i + 1]
			c ^= xor[i // 2]
			pwd += chr(c)
			i = i + 2

		print(f'{e}:\t{pwd}')
	else:
		print(f'Invalid format: {e}', file=sys.stderr)

def main(argv):
	for arg in argv:
		decrypt(arg)

if __name__ == "__main__":
	if len(sys.argv) < 2:
		print(f'Usage: {sys.argv[0]} pwd [pwd ...]')
		print(f'Example: {sys.argv[0]} \'#com.ghc.1!57d0E377A2CA7262116255340CED6A4340E4\'')
	else:
		main(sys.argv[1:])