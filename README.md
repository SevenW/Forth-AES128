# Forth-AES128
Forth AES128 AES-CTR AES-CMAC for Mecrisp Forth and the JeeNode Zero

## Purpose
AES-128 encryption and decryption optimized for minimal memory use
Developed for Mecrisp Forth http://mecrisp.sourceforge.net/
Developed for the Jeelabs JeeNode Zero STM32L052 based family
See: http://embello.jeelabs.org/hardware/jnz.html
See: http://embello.jeelabs.org/

The AES128 has been implemented to enable LoraWAN of for example the Things Network on the JNZ.

The package contains the following files:
```
- aes128.fs           AES-128 AES (16-byte) block encryption with 128-bit key
- aesinv128.fs        AES-128 AES (16-byte) block decryption with 128-bit key
- aes-ctr-cmac.fs     AES-CTR and AES-CMAC implementation as used in LoraWAN
```

`aes-ctr-cmac.fs` does only require `aes128.fs`.

## Use
AES128 encryption
```
buf16 key +aes

\ Usage    : ( c-addr key ) +aes
\ With     : c-addr : input data in a 16-byte buffer
\            key    : the encryption key in 16-bytes 
\ Output   : Encryption is in-situ so the 16-byte input data buffer contains the encrypted output.
```

AES-128 decryption
```
buf16 key -aes

\ Usage    : ( c-addr key ) -aes
\ With     : c-addr : input data in a 16-byte buffer
\            key    : the orignal encryption key in 16-bytes 
\ Output   : Decryption is in-situ so the 16-byte input data buffer contains the decrypted output.
```

AES-CTR length-n buffer encryption
```
buf-n len-n key initvector aes-ctr

\ Usage    : ( buf len key iv -- ) aes-ctr
\ With     : buf        : c-addr input data in a byte buffer
\            len        : the length of the encrypted data
\            key        : c-addr of the encryption key
\            iv         : c-addr of the initialization vector
\ Output   : Encryption is in-situ so the input data buffer contains the encrypted output.
\ Note     : Decryption is achieved by calling the encrypted data with the same IV and key.
```

AES-CMAC calculation of a message authentication code
```
buf-n len-n key initvector aes-cmac

\ Usage    : ( buf len key iv -- mic ) aes-cmac
\ With     : buf        : c-addr input data in a byte buffer
\            len        : the length of the encrypted data
\            key        : c-addr of the encryption key
\            iv         : c-addr of the initialization vector
\ Output   : mic        : c-addr of the mac. Lora uses the first four bytes as 32-bit mic
```

## Test
The test folder contains test modules for the three mentioned files. Test functions can be called as follows:
```
test-aes
test-inv-aes
test-ctr
test-cmac
```

## references
There is one other known implementation of AES in Forth. Written in ANS Forth. It dies not easily run on Mecrisp Forth:
https://gist.github.com/jzakiya/28e0024524556828e2ff
