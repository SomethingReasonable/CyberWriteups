# CSAW 2019
- Writeup for Byte Me

## Byte Me
We are presented a service to connect to, at `crypto.chal.csaw.io` port `1003`

Connecting immediately prints a number of ciphertext blocks, which changes with each connect, sometimes even changing in size.

After sending a significant number of the same character, it is clear that identical ciphertext blocks are formed, indicating an AES-ECB type encryption.

Solve Script:
```python
from pwn import *

# assume AES-ECB
cBlock = 32 # 32 characters since it is hex encoded
pBlock = 16 # 16 plaintext characters

# For logging and debugging purposes
def blockify(str, title):
	for i in range(1, len(str)):
		if i % cBlock == 0:
			f.write(title + ": " + str[i-cBlock:i] + '\n')
	f.write("===================================\n")

def calcPadding():

	# Assumes that the program is awaiting input
	p.sendline("") # Get the response from the server when sent nothing
	echoBypass = p.recvuntil('\n') # Clear the echo of the previous input
	response = p.recvuntil('\n').rstrip() # Receive the encrypted data and remove the \n
	initLen = len(response)
	p.recvuntil(': ')

	for i in range(0, cBlock):
		p.sendline('a' * i)
		echoBypass = p.recvuntil('\n')
		response = p.recvuntil('\n').rstrip()
		if len(response) != initLen:
			# We have stepped into a new block
			print("Found padding equal to " + str(pBlock-(i-1))) # i-1 since on i we are in a new block
			p.recvuntil(': ')
			break
		p.recvuntil(': ')
	return pBlock - (i - 1)

# =========================================================

f = open("output.txt", "w")
p = remote('crypto.chal.csaw.io', 1003)

originalCipher = p.recvuntil('\n')
print(originalCipher)
blockify(originalCipher, "O")

p.recvuntil(': ') # Get to where the program is awaiting input

padSize = calcPadding()

# Can take a partially completed flag
flag = ""
for i in range(len(flag)+1,50): # Assume the flag is not extremely long

	for j in range (32,127): # Printable Range
		toSend = "."*(pBlock-(padSize+2)) + "."*((4*pBlock)-i) + flag + chr(j) + "."*((4*pBlock)-i)
		p.sendline(toSend)
		p.recvuntil('\n').rstrip()
		enc = p.recvuntil('\n').rstrip()
		p.recvuntil(': ').rstrip()

		if len(enc) == 384:
			if (enc[-256:-224] == enc[-128:-96]):
				flag = flag + chr(j)
				break
		elif len(enc) == 352: 
			if (enc[-224:-192] == enc[-96:-64]):
				flag = flag + chr(j)
				break
		elif len(enc) == 320:
			if (enc[-192:-160] == enc[-64:-32]):
				flag = flag + chr(j)
				break
		else:
			if (enc[-160:-128] == enc[-32:0]):
				flag = flag + chr(j)
				break
```

Flag: `flag{y0u_kn0w_h0w_B10cks_Are_n0T_r31iab13...}`
