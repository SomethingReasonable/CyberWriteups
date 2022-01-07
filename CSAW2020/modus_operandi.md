# Modus Operandi
- Category: Crypto
- Points: 100
- Flag: `flag{ECB_re@lly_sUck$}`

## Initial Setup
![Challenge Description](https://lh3.googleusercontent.com/pw/ACtC-3cW9sO-mFpQdh-Ic8C0Tm7-R9CAzrm07dwZ4CwvOm6Qxx7TnZtCoDUqQ-P8X5l8XCw1ac2ih9G0AjxObTDCDdJ07GJt3Bc1sr6AMGt1a9FvtQoJ3Vo3y9E8YEqeMm96G4qktXJy5c1J8meXSM1apR5W=w496-h424-no?authuser=0)
<br />
This challenge simply gave a server to connect to using netcat.

After connecting, it prompted for user input. Then, it returned ciphertext, and asked if it was AES_ECB or AES_CBC.

In AES CBC, the resulting cipher text from each block is XOR'd with the plaintext before being encrypted in the next block. Therefore, two identical blocks of plaintext do not produce identical blocks of ciphertext.
<br />
![AES CBC](https://lh3.googleusercontent.com/pw/ACtC-3cIF_TIY4ME3pzFW7fVdbvxvlZG7cJK3KD42gAHUyICn9Qo6n0vPUYZWz4C6pMPMv2GYIl2I0nCOae1ChZffQk5v0wlUi083SisNrjALgfiYaDloHP70et3cNnFgUHajW5cKljXj8kiqYcIJFGUNZNP=w694-h263-no?authuser=0)
<br />
In AES ECB, each block is independent from other blocks. Therefore, two identical blocks of plaintext produce two identical blocks of ciphertext.
<br />
![AES ECB](https://lh3.googleusercontent.com/pw/ACtC-3eGbx6LmeXUCUbbVEB7PvqhoCvIh6A1HHCa-JJPvkMgv5B4Ml9zrb_9iwDjrKwSx6ffI1hgVJAZQs9hvDCHlJRZ7TU0OGMhDK3G8cQloCG8NU0TBtoRJOplWyXuxL31tli5rFG_tc0Vq0x3TBYiGfC0=w695-h269-no?authuser=0)
<br />

Therefore, if we send two full blocks of identical plaintext, and the resulting ciphertext has two matching blocks of ciphertext, then the cipher used was AES ECB.

## Solve Script

```python
    from pwn import *
    import binascii
    
    p = remote('crypto.chal.csaw.io', 5001)
    record = ""
    
    toSend = 'a' * 32
    for i in range(176):
    
    	p.recvuntil(': ') # Get to where the program is awaiting input
    	p.sendline(toSend)
    	p.recvuntil(': ')
    	ciphertext = p.recvline().strip()
    
    	c1 = ciphertext[:32]
    	c2 = ciphertext[32:64]
    	c3 = ciphertext[64:]
    
    	p.recvuntil('?')
    	
    	if (c1 == c2):
    		#print("===== MATCH = ECB =====")
    		print("Iteration " + str(i) + " -> ECB")
    		p.sendline('ECB')
    		record += 'E'
    	else:
    		#print("===== NO MATCH = CBC ==")
    		print("Iteration " + str(i) + " -> CBC")
    		p.sendline('CBC')
    		record += 'C'
    	
    print(record)
    flag = record.replace("E","0").replace("C","1")
    print(flag)
    print(binascii.unhexlify('%x' % int(flag, 2)))
```

The above script uses pwn tools to connect to the server and receive/send input accordingly.

If the first and second blocks match, it sends ECB. If they don't match, it sends CBC.

This continues for 176 iterations until the server stops asking for input. At this point, ECB and CBC were selected in the following order (with E for ECB and C for CBC)

    order = "ECCEECCEECCECCEEECCEEEECECCEECCCECCCCECCECEEECECECEEEECCECEEEECEECECCCCCECCCEECEECCEECECECEEEEEEECCECCEEECCECCEEECCCCEECECECCCCCECCCEECCECECECECECCEEECCECCECECCEECEECEEECCCCCEC"

Interpreting this as binary with E = 0 and C = 1 yields 
 

    01100110011011000110000101100111011110110100010101000011010000100101111101110010011001010100000001101100011011000111100101011111011100110101010101100011011010110010010001111101


Converting this string to ascii yields the flag.

Final program output:

    [x] Opening connection to crypto.chal.csaw.io on port 5001
    [x] Opening connection to crypto.chal.csaw.io on port 5001: Trying 216.165.2.45
    [+] Opening connection to crypto.chal.csaw.io on port 5001: Done
    Iteration 0 -> ECB
    Iteration 1 -> CBC
    Iteration 2 -> CBC
    Iteration 3 -> ECB
    Iteration 4 -> ECB
    Iteration 5 -> CBC
    Iteration 6 -> CBC
    Iteration 7 -> ECB
    Iteration 8 -> ECB
    Iteration 9 -> CBC
    Iteration 10 -> CBC
    Iteration 11 -> ECB
    Iteration 12 -> CBC
    Iteration 13 -> CBC
    Iteration 14 -> ECB
    Iteration 15 -> ECB
    Iteration 16 -> ECB
    Iteration 17 -> CBC
    Iteration 18 -> CBC
    Iteration 19 -> ECB
    Iteration 20 -> ECB
    Iteration 21 -> ECB
    Iteration 22 -> ECB
    Iteration 23 -> CBC
    Iteration 24 -> ECB
    Iteration 25 -> CBC
    Iteration 26 -> CBC
    Iteration 27 -> ECB
    Iteration 28 -> ECB
    Iteration 29 -> CBC
    Iteration 30 -> CBC
    Iteration 31 -> CBC
    Iteration 32 -> ECB
    Iteration 33 -> CBC
    Iteration 34 -> CBC
    Iteration 35 -> CBC
    Iteration 36 -> CBC
    Iteration 37 -> ECB
    Iteration 38 -> CBC
    Iteration 39 -> CBC
    Iteration 40 -> ECB
    Iteration 41 -> CBC
    Iteration 42 -> ECB
    Iteration 43 -> ECB
    Iteration 44 -> ECB
    Iteration 45 -> CBC
    Iteration 46 -> ECB
    Iteration 47 -> CBC
    Iteration 48 -> ECB
    Iteration 49 -> CBC
    Iteration 50 -> ECB
    Iteration 51 -> ECB
    Iteration 52 -> ECB
    Iteration 53 -> ECB
    Iteration 54 -> CBC
    Iteration 55 -> CBC
    Iteration 56 -> ECB
    Iteration 57 -> CBC
    Iteration 58 -> ECB
    Iteration 59 -> ECB
    Iteration 60 -> ECB
    Iteration 61 -> ECB
    Iteration 62 -> CBC
    Iteration 63 -> ECB
    Iteration 64 -> ECB
    Iteration 65 -> CBC
    Iteration 66 -> ECB
    Iteration 67 -> CBC
    Iteration 68 -> CBC
    Iteration 69 -> CBC
    Iteration 70 -> CBC
    Iteration 71 -> CBC
    Iteration 72 -> ECB
    Iteration 73 -> CBC
    Iteration 74 -> CBC
    Iteration 75 -> CBC
    Iteration 76 -> ECB
    Iteration 77 -> ECB
    Iteration 78 -> CBC
    Iteration 79 -> ECB
    Iteration 80 -> ECB
    Iteration 81 -> CBC
    Iteration 82 -> CBC
    Iteration 83 -> ECB
    Iteration 84 -> ECB
    Iteration 85 -> CBC
    Iteration 86 -> ECB
    Iteration 87 -> CBC
    Iteration 88 -> ECB
    Iteration 89 -> CBC
    Iteration 90 -> ECB
    Iteration 91 -> ECB
    Iteration 92 -> ECB
    Iteration 93 -> ECB
    Iteration 94 -> ECB
    Iteration 95 -> ECB
    Iteration 96 -> ECB
    Iteration 97 -> CBC
    Iteration 98 -> CBC
    Iteration 99 -> ECB
    Iteration 100 -> CBC
    Iteration 101 -> CBC
    Iteration 102 -> ECB
    Iteration 103 -> ECB
    Iteration 104 -> ECB
    Iteration 105 -> CBC
    Iteration 106 -> CBC
    Iteration 107 -> ECB
    Iteration 108 -> CBC
    Iteration 109 -> CBC
    Iteration 110 -> ECB
    Iteration 111 -> ECB
    Iteration 112 -> ECB
    Iteration 113 -> CBC
    Iteration 114 -> CBC
    Iteration 115 -> CBC
    Iteration 116 -> CBC
    Iteration 117 -> ECB
    Iteration 118 -> ECB
    Iteration 119 -> CBC
    Iteration 120 -> ECB
    Iteration 121 -> CBC
    Iteration 122 -> ECB
    Iteration 123 -> CBC
    Iteration 124 -> CBC
    Iteration 125 -> CBC
    Iteration 126 -> CBC
    Iteration 127 -> CBC
    Iteration 128 -> ECB
    Iteration 129 -> CBC
    Iteration 130 -> CBC
    Iteration 131 -> CBC
    Iteration 132 -> ECB
    Iteration 133 -> ECB
    Iteration 134 -> CBC
    Iteration 135 -> CBC
    Iteration 136 -> ECB
    Iteration 137 -> CBC
    Iteration 138 -> ECB
    Iteration 139 -> CBC
    Iteration 140 -> ECB
    Iteration 141 -> CBC
    Iteration 142 -> ECB
    Iteration 143 -> CBC
    Iteration 144 -> ECB
    Iteration 145 -> CBC
    Iteration 146 -> CBC
    Iteration 147 -> ECB
    Iteration 148 -> ECB
    Iteration 149 -> ECB
    Iteration 150 -> CBC
    Iteration 151 -> CBC
    Iteration 152 -> ECB
    Iteration 153 -> CBC
    Iteration 154 -> CBC
    Iteration 155 -> ECB
    Iteration 156 -> CBC
    Iteration 157 -> ECB
    Iteration 158 -> CBC
    Iteration 159 -> CBC
    Iteration 160 -> ECB
    Iteration 161 -> ECB
    Iteration 162 -> CBC
    Iteration 163 -> ECB
    Iteration 164 -> ECB
    Iteration 165 -> CBC
    Iteration 166 -> ECB
    Iteration 167 -> ECB
    Iteration 168 -> ECB
    Iteration 169 -> CBC
    Iteration 170 -> CBC
    Iteration 171 -> CBC
    Iteration 172 -> CBC
    Iteration 173 -> CBC
    Iteration 174 -> ECB
    Iteration 175 -> CBC
    ECCEECCEECCECCEEECCEEEECECCEECCCECCCCECCECEEECECECEEEECCECEEEECEECECCCCCECCCEECEECCEECECECEEEEEEECCECCEEECCECCEEECCCCEECECECCCCCECCCEECCECECECECECCEEECCECCECECCEECEECEEECCCCCEC
    01100110011011000110000101100111011110110100010101000011010000100101111101110010011001010100000001101100011011000111100101011111011100110101010101100011011010110010010001111101
    flag{ECB_re@lly_sUck$}
    [*] Closed connection to crypto.chal.csaw.io port 5001
`flag{ECB_re@lly_sUck$}`
