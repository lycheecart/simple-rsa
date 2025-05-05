# simple-rsa
Reference script for elementary insecure textbook RSA operations.

Contains a modular-multiplicative-inverse function that divides by 0 sometimes.
 (python does have a built-in pow(x, -1, m)).

For signing & verifying (different service), for now I'd prefer to just use a library or something
One very good guide is at https://cryptobook.nakov.com/digital-signatures/exercises-rsa-sign-and-verify

Reference videos were https://www.youtube.com/watch?v=Z8M2BTscoD4 and https://www.youtube.com/watch?v=D_PfV_IcUdA


### Usage examples

#### [encrypt/decrypt] 
 
Create a key pair for alice using p 5 and q 17 (e is hardcoded to 3) 
```
./rsa_agent.py --createkeys -p 5 -q 17 -pub "alice_pubkey.txt" -priv "alice_privkey.txt"
```

Create a key pair for bob using p 89 and q 107 
```
./rsa_agent.py --createkeys -p 89 -q 107 -pub "bob_pubkey.txt" -priv "bob_privkey.txt"
```

Alice uses Bob's public key to encrypt the message "mapo tofu" and save it as ./menu.txt
```
./rsa_agent.py --encrypt -pub "bob_pubkey.txt" -m "mapo tofu" > menu.txt
```

Bob decrypts the message saved in "menu.txt"

```
./rsa_agent.py --decrypt -pub bob_pubkey.txt -priv bob_privkey.txt -mf menu.txt
```


### RSA constants pseudocode
```
 have a message m
 choose two prime numbers p and q
  n = p*q
  phi = (p-1) * (q-1)
  encryption_exponent = "relatively prime to phi" meaning gcd of (e,phi) == 1
  decryption_exponent = 
   "multiplicative_inverse(encryption_exponent) % phi"
     multiplicative_inverse is the number a such that
      (a*encryption_exponent) % phi == 1
   ;
   you use the extended euclidean algorithm to find the multiplicative inverse
   python also has this built-in: pow(x, -1, m)
   ;

  to encrypt m:
   encrypted_message = (m**encryption_exponent) % n
   you can give someone else encryption_exponent and n as public information
   so they can encrypt the message for you

  to decrypt encrypted_message
   decrypted_message = encrypted_message**decryption_exponent % n
```

```
#alice can encrypt "hi bob" with bob's public key, and send him encrypted(hi_bob).
#then bob can use his own private key to decrypt it
```

