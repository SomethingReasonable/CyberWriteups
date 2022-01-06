

# Adversarial
- Category: Crypto
- Points: 200
- Flag: `flag{m1ss1on_acc00mpl11shheedd!!}`

## Initial Setup
![Initial NC Prompt](https://lh3.googleusercontent.com/pw/ACtC-3chlvGr0AYj6r00Rn6ZoCB_Cwi8nhtMVo92wNhPD6XBW0Z3WLuMtq-eC1mwwuX_iUD3MM-1Gh7yD_oC7mclqCJ67pvoQo3wUvEbUS_PQKzAHPM0zk7ajM8uqC6IgMfirnJEdtNPvusgDCut55x2wKms=w495-h501-no?authuser=0)
<br />
The challenge comes with a text file, assignment.txt.

> While digging through system logs, Morpheus discovered machines on the
> local network transmitting the following base64-encoded ciphertexts to
> an IP address known to be under enemy control:
> 
> 2us8eN+xyfX3m+ouq+Rp51ruXKXYbKCbe5GjrddBHVm0vhKd2KMXMjFWQVclCmNnsGuEhFSOoFRo 0hIKHGZrrCS/BRITjW7DJ5L+c0C6Dhu6yBNSnWDpf7sYMknxcaZ+FSwg0nVVNxlNZsfqpd9NOg7F
> OGsysrh8EIGXZiovI6mLWo9FobtcCDbRZXT7Op5rz7hFynKLtFLIx1GTt4CUrKw6J/tpjTZ9mv/w
> bBjD5Iwd060oTwfZd4NVg+GdDqyz1PA= . .  .  .  .  .  `19 more base 64
> strings` .
> zPB9dZCtmrThm/o39bBE5FTuSL+MOe+aM5Dmu8xAGhWjtlOYlKM9PH5GTUcsWEQysCqfih2BqwZs
> 0RkGSC1yqzLrUgMdjG7ZKYn+dFe6QlD11hVUyTT/MKpXfQj7Prs0BGA7m2oCHhRLI9/hqd9newOE
> Iioyo7h8BYeWZjoiJ+zFDpVFrvhaBDjTfz38cogiwaBM3juNuVuLw1Gft5SK/7AhM7V8iSQp0+Lt
> bgTS+skd3qwoQhCKa5gAnqffHaP637Nu0dDDJZIzSW7E6Hp6fcp5zyU9gJeiCoco0gZsnph9M+Wq
> oSFDUyWMboAoJxchDzPLIJC4xE5Xg0zlW3CVlnYSXucoXs1vL5Dujy88KNTfH0VHl/1WMbIQG6VZ
> Gx+cCL0hamoLvF/6pVCopja0hDH90n03YjO4fTuCkERXadI8yT0RuzaV5Liv5y4SbUnkGLOf4z7W
> jWeBJsBPIXVBpaksvv8k2DCSKM2gEHVueRotbRFnr1YIUj8PxyxDsB7yKLRJz72r4rORfVMtNkU5
> 06OsghVVJb1rxeTs6OwLTT40QblSrAXBcxppynreTWGAo2DqXCL8akzWn5tIkE74KApF76ICrVOe
> +zuZV/V96TUDQegU1OmqQyiCip5iFoP6jI8ZimKnDPfSC+HoutV6WceBVQD3IDN4yals+AuUifLj
> PxRWnVY=
> 
> Upon further investigation, the following script was found:
> 
>     #!/usr/bin/env python2
>     
>     import os
>     
>     import Crypto.Cipher.AES
>     import Crypto.Util.Counter
>     
>     from Messager import send
>     
>     
>     KEY = os.environ['key']
>     IV = os.environ['iv']
>     
>     secrets = open('/tmp/exfil.txt', 'r')
>     
>     for pt in secrets:
>         # initialize our counter
>         ctr = Crypto.Util.Counter.new(128, initial_value=long(IV.encode("hex"), 16))
>     
>         # create our cipher
>         cipher = Crypto.Cipher.AES.new(KEY, Crypto.Cipher.AES.MODE_CTR, counter=ctr)
>     
>         # encrypt the plaintext
>         ciphertext = cipher.encrypt(pt)
>     
>         # send the ciphertext
>         send(ciphertext.encode("base-64"))
> 
> Unfortunately, the environment variables used for KEY and IV are no
> longer recoverable and the file /tmp/exfil.txt has been deleted.
> 
> Use your knowledge of how AES in CTR mode work to decrypt the
> ciphertexts and find the flag.

## The Recovered Script
Analyzing the recovered script shows that the Base 64 strings were encoded using AES-CTR.
![AES-CTR Diagram](https://lh3.googleusercontent.com/pw/ACtC-3d4DeL91cg2a2-fdoQV7e1ARqr833CIXCLQ8ILcGr4WvPQ-tIBx0OXmzKoZpXa7hbtngi7KItbSnQlNDlGAjOL2J_Lpvz4jMih3SAIWTKuwCT0eYDWsoWHJxx_xsJGobvUB7UTXweyPd79eLc6Lc4ob=w711-h266-no?authuser=0)
<br />
In AES-CTR, there is a counter that is randomly selected. This is seen in the recovered script in:
`ctr = Crypto.Util.Counter.new(128, initial_value=long(IV.encode("hex"), 16))`

The counter was initialized from the Initialization Vector file, which we do not have access to.

The key was similarly pulled from the Key file, and we do not have access to that, either.
`cipher = Crypto.Cipher.AES.new(KEY, Crypto.Cipher.AES.MODE_CTR, counter=ctr)`

## The Vulnerability
Closer examination of the recovered script shows that the counter and key are pulled from the file for the encryption of every plaintext. This means that every plaintext was encrypted with the same counter and key.

In AES-CTR, the counter is encrypted with AES using the key, and the resulting encryption is XOR'ed with the plaintext. Referring to the encrypted counter at block index i as E<sub>Ci</sub>, we can say that E<sub>Ci</sub> is the same for every *column* of the encryption.

Remember that we have 21 ciphertexts. Lets examine two hypothetical chunks of ciphertext, P1 and P2. In the given challenge, each block is 16 bytes long, but we'll treat them as 2 byte chunks for readability.

   P1: `01101001 01010111`
   P2: `10110111 10010000`
Each chunk will be XOR'd with E<sub>Ci</sub> to produce the cipher text. Let's examine a hypothetical value for E<sub>C</sub>.
E<sub>C</sub>: `00101001 11101111`
In this case, `00101001` is E<sub>C0</sub> and `11101111` is E<sub>C1</sub>.

We know that P1's first block and P2's first block will both be XOR'd with E<sub>C0</sub>. Similarly, P1's second block and P2's second block will be XOR'd with E<sub>C1</sub>. The key takeaway is that if we are considering block `i`, regardless of the ciphertext we are currently looking at, they will all be XOR'd with the same E<sub>C</sub>.
E<sub>C</sub>: `01101001 01010111`
P1: `10110111 10010000`
P2: `00101001 11101111`
P1<sub>0</sub> and P2<sub>0</sub> are both XOR'd with `01101001`, and P1<sub>1</sub> and P2<sub>1</sub> are both XOR'd with `01010111`.

However, we don't know P1 and P2. We only know C1 and C2.
C1 = P1 **⊕** E<sub>C</sub>, and C2 = P2 **⊕** E<sub>C</sub>.

### XOR Trick
C1 **⊕** C2 = (P1 **⊕** E<sub>C</sub>) **⊕** (P2 **⊕** E<sub>C</sub>) = P1 **⊕** P2
Therefore, for a block of ciphertext of index `i`, if we **⊕** it with a different block of index `i`, we end up with P<sub>1i</sub> **⊕** P<sub>2i</sub>, and E<sub>C</sub> (the actual encrypted part that we can never figure out) is completely out of the question!

## Figuring out P1 or P2 Given P1 **⊕** P2
The problem now is how to get back to the non XOR'd plaintext. One technique, called Crib Dragging, is described as follows:

A key property of XOR is that:
```
A ^ B = C
C ^ B = A
C ^ A = B
```

Let's take the two plaintext strings from above:
   P1 : : : : : :`01101001 01010111`
   P2: : : : : : `10110111 10010000`
   P1 **⊕** P2: `11011110 11000111`
   If we could figure out a part of P1, for example, then we could figure out a part of P2!
   Let's say the phrase `1101`is very common in English, so it's probably going to appear in P1.
   P1 **⊕** (P1 **⊕** P2) = P2
   
   Let's craft two bytes with that known word, and pad the rest with 0. We'll call it G for guess.
   <pre>
   G: 11010000 00000000
   </pre>
   Now let's perform G **⊕** (P1 **⊕** P2). If we guess a part of P1 correctly, we will get some of the plaintext of P2.
    
<pre>
G:             <b>1101</b>0000 00000000
P1 ^ P2:       11011110 11000111
G ^ (P1 ^ P2): <b>0000</b>1110 11000111
</pre>
Unfortunately, this is gibberish and doesn't reveal any of the plaintext of P2.

So, now we will **drag the crib** one position and try again.
<pre>
G:             0<b>1101</b>000 00000000
P1 ^ P2:       11011110 11000111
G ^ (P1 ^ P2): 1<b>0110</b>110 11000111
P2:            1<b>0110</b>111 10010000
</pre>

Bingo! The `0110` in `G ^ (P1 ^ P2)` is the plaintext from P2! Because we guessed the right crib in the right position, we were able to see through to the plaintext of P2.

## Coding the Exploit
The following script performs a crib drag across `G ^ (P1 ^ P2)` for a given guess string.

We don't need to specify whether we are trying to get plaintext from P1 or P2. If we guess a string correctly that appears in P1, the resulting plaintext will come from P2. If we guess a string correctly that appears in P2, the resulting plaintext will come from P1.

Ciphertexts index 16 and 20 were chosen because they were the two longest ciphertexts in the given set of 21.

    import base64
    import binascii
    import string
    
    f = open("ct.txt")
    a = f.read().split("\n\n")
    byteArrays = []
    
    for ctb64 in a:
    	byteArrays.append(base64.b64decode(ctb64.replace('\n','')))
    
    c1 = byteArrays[16] # 709 bytes long
    c2 = byteArrays[20] # 518 bytes long = 32 chunks of 16 + 6 bytes
    
    m12 = [ord(a) ^ ord(b) for a,b in zip(c1,c2)]
    
    guess = " the "
    count = 0
    for i in range(len(guess)):
    	blockSize = (32*16 / len(guess))
    	toXor = i * 'a' + guess * (blockSize)
    	toXorByteArray = [ord(a) for a in toXor]
    	finalXor = [a ^ b for a,b in zip(toXorByteArray, m12)]
    	output = ""
    
    	for x in finalXor:
    		output += chr(x)
    
    	for n in range(i, len(output), len(guess)):
    		check = output[n:n+len(guess)]
    		count += len(guess)
    		if all(c in string.printable for c in check):
    			print(str(count) + ": " + check)
    
    	print("=======================================")

Here is a portion of the program output with the crib of `" the "` (5 characters long because of the leading and trailing space).
![Guess 1](https://lh3.googleusercontent.com/pw/ACtC-3eQZGL3Tfjkrvsx2DXE0ofMIp4EC-q0e95lJ9kjPS37RjItXnC1jit2bDEN8ApZWg8UEAMBuTT06TuO08w2ucHk1jXQHa-CBdUn__VNpqvceM7YkNe8im6iS-CfIXxCkCeBUiCX4UsRi1cvb0ag8EUZ=w438-h329-no?authuser=0)
<br />
On 1125, we see something interesting. "Alrea" looks like it comes from "Already", so we can modify the guess to be `"Already "`. Then, instead of having to manually scrub through the results, we can simply search for "the" because we know that the plaintext " the " is what revealed this plaintext.

Put another way, let's say " the " is plaintext from P1, and "Alrea" is plaintext from P2. If we just revealed plaintext from P2, then when we switch our guess to a known string in P2 ("Already ") the resulting plaintext discovered will be from P1, beginning with "the".
![Guess 2](https://lh3.googleusercontent.com/pw/ACtC-3dNJ3aaloDYv_Y0-VAL1aDkqiHKS_GJ4ieLekT6bDf72lDANsufKfhsHKw5HwI12wNS3mGn268IqAiW_R4H_SytXdI9wjpIu2pojI17Vc_4HCkf6KxzxIuXx3sZIdi01dG_9208-QLV8GSr2vwCK6ws=w902-h39-no?authuser=0)
<br />
"the pro" is probably "the program". Changing guess to `" the program "` yields
![Guess 3](https://lh3.googleusercontent.com/pw/ACtC-3eslU7ei7kpH4wTgbKQaP_aiZd8P0j04BiPupA81x4pWocwqDcnuMzFxTZ-s4d7MnWrPZhXjHUYE3jiP7m2pf_SZWkyLkKvdvWYD9QbarzLks9pyBrlHu5IF1j-toGvIxzI0ezdaYrPWQViX7RTfk-3=w907-h40-no?authuser=0)
<br />
Performing this same technique a few more times allows us to incrementally discover more and more plaintext from P1 and P2. After a few iterations, we have:
![Guess 4](https://lh3.googleusercontent.com/pw/ACtC-3cG2NrLDPwYpivcOCVuQrcZM7w23CmmMPzwJPZ_Sno7-KjQo0cL86w60Ir8SOOdm4GzdYGc3biu-_XMlzs7DaMk6jyf--DSjW6GAHeZcXpZtStLZ-EGuw5vh-C3wmDGCmuErY5WqQRQqxWPWAbPIWFv=w922-h38-no?authuser=0)
<br />
A Google search for "Already I can see the chain reaction" yields a quote from the Matrix.
![Plaintext 1](https://lh3.googleusercontent.com/pw/ACtC-3fUwWRQ_yiaD2VjNSF0kpftqkerOxelqF-ppoWMAyJQH8-PzRjPDWFC77G8vKYjJsLyaAY-_npMhPBbQTNI6TG4viGJqj0DiHISQc9Uo_DoVH1Z8ccuSDTUT9wQ7BRQWbn8ZguBfle4IAgXHKryz1AP=w890-h362-no?authuser=0)
<br />
Now we know where P1 comes from! This allows us to easily figure out P2 as well (though not necessary).

Now P1 and P2 are known.
```
P1 = " the program as long as they were given a choice, even if they were only aware of that choice at a near-unconscious level. While this answer functioned, it was obviously fundamentally flawed, thus creating the otherwise-contradictory systemic anomaly that if left unchecked might threaten the system itself. Ergo, those that refused the program, while a minority, if unchecked would constitute an escalating probability of disaster"
P2 = "As you adequately put, the problem is choice. But we already know what you are going to do, don't we? Already I can see the chain reaction: the chemical precursors that signal the onset of an emotion, designed specifically to overwhelm logic and reason. An emotion that is already blinding you to the simple and obvious truth: she is going to die and there is nothing you can do to stop it. Hope. It is the quintessential human delusion, simultaneously the source of your greatest strength, and your greatest weakness."
```

## Decrypting All Messages
Let's go back to the original discussion of AES-CTR.

C = P **⊕** E<sub>C</sub>

Now, we know P, and we know C because it is given. Therefore, performing another **⊕**  can reveal E<sub>C</sub>.
E<sub>C</sub> = C **⊕**  P

The following script uses the known plaintext to find the encrypted counter E<sub>C</sub>, and then uses it to reveal all 21 blocks of ciphertext.

```
import base64
import binascii
import string

f = open("ct.txt")
a = f.read().split("\n\n")
byteArrays = []

for ctb64 in a:
	byteArrays.append(base64.b64decode(ctb64.replace('\n','')))

guess = "As you adequately put, the problem is choice. But we already know what you are going to do, don't we? Already I can see the chain reaction: the chemical precursors that signal the onset of an emotion, designed specifically to overwhelm logic and reason. An emotion that is already blinding you to the simple and obvious truth: she is going to die and there is nothing you can do to stop it. Hope. It is the quintessential human delusion, simultaneously the source of your greatest strength, and your greatest weakness."

ctRaw = byteArrays[20]
ct = [ord(a) for a in ctRaw]
pt = [ord(a) for a in guess]
key = [a ^ b for a,b in zip(ct,pt)]

for baRaw in byteArrays:
	ba = [ord(a) for a in baRaw]
	print("".join([chr(a ^ b) for a,b in zip(key,ba)]))
```
The output is as follows

![Solve Script Output](https://lh3.googleusercontent.com/pw/ACtC-3e8rugIfuK2uN9oMTYqh58iSX2N2laDchK1AciXnu16BwwnLQ-w0bgqFqV7sBxOrxIjgOX1XS9iM5mOIg1iHa7SW5D8Lz9lhk7vst0f7HER-d-I6tD9TKTKwaG2Vvw5kpE8nI9fHqt1CrCCYhHpTgeH=w1906-h617-no?authuser=0)
<br />

Finally returning to the problem description's given server:
![enter image description here](https://lh3.googleusercontent.com/pw/ACtC-3d8nHpnOVv6Yl7fpL2d9MilthxhB9INU35bQ3-fnL2urYPWzg2fMlrQptmd_qgN8glhIrgztr1chYle0i7sPV5jBzLBUFR8HlNOkGX_-aQumNqQ2KyB9J8RqfCHccDCrjYGFD0272ezs_2zMhIpF7DJ=w950-h136-no?authuser=0)
<br />
`flag{m1ss1on_acc00mpl11shheedd!!}`
