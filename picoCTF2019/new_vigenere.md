

# New Vigenère
- Category: Cryptography
- Points: 300
- Flag: `picoCTF{73885da7b4e46e4d01ee934278716e68}`

## Initial Setup
The challenge comes with a python file new_vignere.py, and an encrypted string.

### Python Script
```python
import string

LOWERCASE_OFFSET = ord("a")
ALPHABET = string.ascii_lowercase[:16]

def b16_encode(plain):
	enc = ""
	for c in plain:
		binary = "{0:08b}".format(ord(c))
		enc += ALPHABET[int(binary[:4], 2)]
		enc += ALPHABET[int(binary[4:], 2)]
	return enc

def shift(c, k):
	t1 = ord(c) - LOWERCASE_OFFSET
	t2 = ord(k) - LOWERCASE_OFFSET
	return ALPHABET[(t1 + t2) % len(ALPHABET)]

flag = "redacted"
assert all([c in "abcdef0123456789" for c in flag])

key = "redacted"
assert all([k in ALPHABET for k in key]) and len(key) < 15

b16 = b16_encode(flag)
enc = ""
for i, c in enumerate(b16):
	enc += shift(c, key[i % len(key)])
print(enc)
```

### Provided Encrypted String
```lejjlnjmjndkmjinkilbmlljjkmnakmmighhocmllojhjmaijpiohnlojmokjkja```

### Initial Thoughts
By reading through the script, it is clear that the flag (comprised of hex characters) was base 16 encoded (into the range of letters from a-p) and then encrypted with a Vigenère cipher and printed.

![Vigenère cipher example](https://lh3.googleusercontent.com/pw/ACtC-3cMs1oel7XXVjAmifzeFAj6cdjp2dHtfqHRJFhVlPSJRitcHhDTSq1DAkyb0kZSLdAONSKfvkf6GtbfBLBKoGjaKvvhlT2NWu5lY6E8CBUTCkw5RFf7XzbVagRkcMLOoTS4cjua0yGkrIC2mQkSynRO=w677-h122-no?authuser=0)

In a [Vigenère cipher](https://en.wikipedia.org/wiki/Vigen%C3%A8re_cipher), a shifting mechanism is used as in a [Caesar cipher](https://en.wikipedia.org/wiki/Caesar_cipher), but instead of a static shift for every letter, the shift amount is determined by using a word or phrase as a key and repeating the key over the length of the plaintext.

To support reversing base16 and shifting backwards, I created the following functions and included them in the script.
### b16_decode
```python
def b16_decode(enc):
        #print(enc)
        dec = ""
        for i in range(0,len(enc),2):
            bin1 = "{0:04b}".format(ord(enc[i])-97)
            bin2 = "{0:04b}".format(ord(enc[i+1])-97)
            final = bin1 + bin2
            dec += chr(int(final,2))
        return dec
```

### shift_back
```python
def shiftBack(c, k):
	t1 = ord(c) - LOWERCASE_OFFSET
	t2 = ord(k) - LOWERCASE_OFFSET
	return ALPHABET[(t1 - t2) % len(ALPHABET)]def shiftBack(c, k):
	t1 = ord(c) - LOWERCASE_OFFSET
	t2 = ord(k) - LOWERCASE_OFFSET
	return ALPHABET[(t1 - t2) % len(ALPHABET)]
```

## Basic Cryptanalysis
At first glance, it seems nearly impossible to figure out the key easily. We know that it's less than length 15, but that could be ```16^14 = 7.2e16``` keys, which is not going to be brute forced anytime soon.

### Cryptanalysis
Reading about [cryptanalysis for Vigenère ciphers](https://en.wikipedia.org/wiki/Vigen%C3%A8re_cipher#Cryptanalysis) shows that determining the length of the key may be very useful. There are several ways to do this, such as the Kasiski test.

Applying the Kasiski test over the ciphertext shows the following offsets for pairs of matching characters.
```
# jm = 38
# jm = 12
# km = 14
# km = 4
# mll = 18
# jk = 36
# loj = 14
# kj = 2
```

Looking for common factors among these yields some mixed results. For example, looking at 12 and 4 suggests a key length that may be length 4, 2, or 1, although these are very small and unlikely. Looking at 18 and 36 suggests a key of length 9, and the offsets of length 14 suggest a key of length 7.

## Critical Observation
A critical observation comes from close analysis of the way that the encryption process works. Each hex character from the flag is base_16 encoded into 2 characters in the range a-p.  In reality, reading the b16_encode function shows that it interprets the input as a string, using ord(). So while the flag is comprised of only hex characters, they are encoded as literal string characters.

For example, encoding the letter 'a':
```python
	binary = "{0:08b}".format(ord('a')) # '01100001'
	enc += ALPHABET[int(binary[:4], 2)] # 'g'
	enc += ALPHABET[int(binary[4:], 2)] # 'b'
	return enc                          # 'gb'
```

Base_16 encoding all characters in the set of characters that create the flag:
```python
flag = "abcdef0123456789"
b16 = b16_encode(flag)
print(b16) # "gbgcgdgegfggdadbdcdddedfdgdhdidj"
```

An interesting and important observation is that any character in the flag, when base_16 encoded to a 2 character string (of characters a-p), **always** begins with a ```g``` or a ```d```.

This is because the binary representation of each input character is as follows.
```python
>>> for a in "abcdef0123456789": print(a + ": {0:08b}".format(ord(a)))
a: 01100001
b: 01100010
c: 01100011
d: 01100100
e: 01100101
f: 01100110
0: 00110000
1: 00110001
2: 00110010
3: 00110011
4: 00110100
5: 00110101
6: 00110110
7: 00110111
8: 00111000
9: 00111001
```
The first four bits of the letters ```a-f``` are always ```0110```, and the first four bits of the numbers  ```0-9``` are always ```0011```.
```
0110 = 6
ALPHABET[6] = 'g'
0011 = 3
ALPHABET[3] = 'd'
```
## Determining the Key
Since we know that every even-indexed character in the cipher text **must** be have been shifted *from* a `d` or a `g` into the encrypted character, then every even-indexed character in the cipher text only has **two** possible corresponding values in the key.

For example, the first 2 characters of the cipher text are ```le```
The letter `l` must have come from either a ```d``` or a ```g```.

```python
# ALPHABET
0  1  2  3  4  5  6  7  8  9  10 11 12 13 14 15
a  b  c  d  e  f  g  h  i  j  k  l  m  n  o  p
```
`l` is index 11, but it must have come from either a `d` (index 3) or a `g` (index 6). The shift from `l` to `d` or `g` must be of either magnitude 8 or 5, respectively.
``` 
ALPHABET[5] = 'f'
ALPHABET[8] = 'i'
```
Therefore, the **first** character of the key must have been *either* an `f` or an `i`.

### Visual Representation
Repeating this process for the entire ciphertext:
```
* = character is of even index and two possible characters of the key can be determined
# = index of the key in question
l * 1; i,f
e   2 
j * 3; d,g
j   4
l * 5; i,f
n   6
j * 7; d,g
m   8 
j * 9; d,g
n   1
d * 2; a,n
k   3
m * 4; g,j
j   5
i * 6; c,f
n   7
k * 8; e,h
i   9
l * 1; i,f
b   2
m * 3; g,j
l   4
l * 5; i,f
j   6
j * 7; d,g
k   8
m * 9; g,j
n   1
a * 2; k,n
k   3
m * 4; g,j
m   5
i * 6; c,f
g   7
h * 8; a,e
h   9
o * 1; i, l
c   2
m * 3; g, j
l   4
l * 5; i,f
o   6
j * 7; d,g
h   8
j * 9; d,g
m   1
a * 2; k,n
i   3
j * 4; d,g
p   5
i * 6; c,f
o   7
h * 8; a,e
n   9
l * 1; i,f
o   2
j * 3; d,g
m   4
o * 5; i,l
k   6
j * 7; d,g
k   8
j * 9; d,g
a   1
```
Here I have already provided the numbers 1-9 to indicate indices of the key. The same analysis as described above in the Kasiski test can be applied here, but the results are much more clear. For example, **every** even index 18 apart has at least one letter in common for the key. Since we know the key is < 15 from the provided script, we can confidently say that the key is length 9.


For example, the first character of the key must be the union of the sets {i, f} and {i, l}. So, the first character of the key is `i`.
Repeating this for the remaining key indices yields the follow key:
```
1: i
2: n
3: g
4: g
5: i
6: c/f
7: d/g
8: e
9: g
```
There are two characters which are not yet determined, but this only leaves four possible keys.

## Final Solve Script
```python
import string

LOWERCASE_OFFSET = ord("a")
ALPHABET = string.ascii_lowercase[:16]

def b16_encode(plain):
	enc = ""
	for c in plain:
		binary = "{0:08b}".format(ord(c))
		enc += ALPHABET[int(binary[:4], 2)]
		enc += ALPHABET[int(binary[4:], 2)]
	return enc

def b16_decode(enc):
        dec = ""
        for i in range(0,len(enc),2):
            bin1 = "{0:04b}".format(ord(enc[i])-97)
            bin2 = "{0:04b}".format(ord(enc[i+1])-97)
            final = bin1 + bin2
            dec += chr(int(final,2))
        return dec

def shift(c, k):
	t1 = ord(c) - LOWERCASE_OFFSET
	t2 = ord(k) - LOWERCASE_OFFSET
	return ALPHABET[(t1 + t2) % len(ALPHABET)]

def shiftBack(c, k):
	t1 = ord(c) - LOWERCASE_OFFSET
	t2 = ord(k) - LOWERCASE_OFFSET
	return ALPHABET[(t1 - t2) % len(ALPHABET)]

keys = ["inggicdeg", "inggicgeg", "inggifdeg", "inggifgeg"] 
enc = "lejjlnjmjndkmjinkilbmlljjkmnakmmighhocmllojhjmaijpiohnlojmokjkja"
for key in keys:
	dec = ""
	for i, c in enumerate(enc):
		dec += shiftBack(c, key[i % len(key)])
	dec = b16_decode(dec)
	if (all([c in "abcdef0123456789" for c in dec])):
			print("found key " + key)
			print(dec)
```
```
> python solve.py 
found key inggifgeg
73885da7b4e46e4d01ee934278716e68
```
Flag: `picoCTF{73885da7b4e46e4d01ee934278716e68}`
