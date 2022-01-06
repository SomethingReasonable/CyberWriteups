# Unbreakable Encryption

 - Category: Cryptography
 - Points: 100
 - Difficulty: Easy
 - Flag: ``MetaCTF{you're_better_than_steve!}``

## Initial Setup

We are provided the following values.

```python
c1 = "4fd098298db95b7f1bc205b0a6d8ac15f1f821d72fbfa979d1c2148a24feaafdee8d3108e8ce29c3ce1291"
p = :hey let's rob the bank at midnight tonight!"
c2 = "41d9806ec1b55c78258703be87ac9e06edb7369133b1d67ac0960d8632cfb7f2e7974e0ff3c536c1871b"
```

This is an implementation of a one-time pad.
A one time pad involves the random selection of a key in equal length to the plaintext. If you then XOR the plaintext with the ciphertext, then the ciphertext is secure as long as the key is not resused.

![enter image description here](https://wikimedia.org/api/rest_v1/media/math/render/svg/ff9b8f1e11968e11bb13fae563ea5113ca1578b8)

## Vulnerability

The vulnerability here is based upon the associative property of the XOR operator.
``A ⊕ (B ⊕ C) = (A ⊕ B) ⊕ C``

Assume that the same key was used multiple times to create ciphertext. Then we have:
![enter image description here](https://wikimedia.org/api/rest_v1/media/math/render/svg/ff9b8f1e11968e11bb13fae563ea5113ca1578b8)
![enter image description here](https://wikimedia.org/api/rest_v1/media/math/render/svg/9e87e7aba43cfbd3b30ce4fe095d22902f0ebb72)

We can recover the key used by simply calculating ``c1 ⊕ p1``, which are both known quantities. This would normally be useless in a correctly implemented one time pad, but in this instance, the key has been reused.

Therefore, since we know the key, we can recover p2 by XOR'ing it against the key.
``p2 = k ⊕ c2``

## Solve Script

```python
from binascii import unhexlify
  
c1 = unhexlify("4fd098298db95b7f1bc205b0a6d8ac15f1f821d72fbfa979d1c2148a24feaafdee8d3108e8ce29c3ce1291")
p = "hey let's rob the bank at midnight tonight!".encode()
c2 = unhexlify("41d9806ec1b55c78258703be87ac9e06edb7369133b1d67ac0960d8632cfb7f2e7974e0ff3c536c1871b")

key = bytes(a ^ b for (a, b) in zip(c1, p))
flag = bytes(a ^ b for (a,b) in zip(c2, key))
print(flag.decode())
```

## Flag
```
❯ python3 solve.py 
flag is MetaCTF{you're_better_than_steve!}
```

