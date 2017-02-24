\ 128-bit AES for LMIC LoraWAN Test code
\ Author: SevenW from sevenwatt.com
\ Date  : 2017-Feb-21
\ 
\ Description:
\ Test module for AES128 block cipher encryption
\ Decryption test is supported in the separate file: aes128invtest.fs
\ 
\ Requires : aes128.fs
\ 
\ Usage    : test-shiftbytes
\ Usage    : test-mix
\ Usage    : test-aes
\ Output   : last printed line should read "passed" and not "failed"
\ 
\ 

: h.16 ( caddr -- )
  16 0 do dup i + c@ h.2 ."  " loop drop cr ;

0 [if]
Alternative test set
For 128-bit key:   000102030405060708090a0b0c0d0e0f
Plaintext input:   00112233445566778899aabbccddeeff
Known  ciphertext: 69c4e0d86a7b0430d8cdb78070b4c55a
Computed ciphtext: 69c4e0d86a7b0430d8cdb78070b4c55a
Computed original: 00112233445566778899aabbccddeeff
[then]

hex

create testdata
  17 C, 5A C, 5E C, B6 C, 91 C, 63 C, 45 C, FA C, 1B C, 20 C, 19 C, 4F C, AB C, 70 C, AD C, 95 C,
 
create testkey
  69 C, 20 C, e2 C, 99 C, a5 C, 20 C, 2a C, 6d C, 65 C, 6e C, 63 C, 68 C, 69 C, 74 C, 6f C, 2a C,

create valdata
  A2 C, 5C C, F8 C, A0 C, 14 C, 0C C, 25 C, 5A C, BB C, 22 C, CE C, CF C, 42 C, B0 C, 31 C, 78 C,

\ shiftbytes test data
create test-scratch-sb
00 C, 01 C, 02 C, 03 C, 04 C, 05 C, 06 C, 07 C, 08 C, 09 C, 0A C, 0B C, 0C C, 0D C, 0E C, 0F C,

create val-scratch-sb
00 C, 01 C, 02 C, 03 C, 05 C, 06 C, 07 C, 04 C, 0A C, 0B C, 08 C, 09 C, 0F C, 0C C, 0D C, 0E C,

\ mix-columns test data
\ vectors of $01, and $C6 remains unchanged in mix columns!
create test-scratch-mix-col
 db C, f2 C, 01 C, c6 C,    13 C, 0a C, 01 C, c6 C,   53 C, 22 C, 01 C, c6 C,   45 C, 5c C, 01 C, c6 C, 

create val-scratch-mix-col
 8E C, 9F C, 01 C, C6 C, 4D C, DC C, 01 C, C6 C, A1 C, 58 C, 01 C, C6 C, BC C, 9D C, 01 C, C6 C,

decimal

16 buffer: indata

\ Fill scratch with easy to read content
: sk! 16 0 do i scratch i + c! loop ;

\ print scratch 
: sk. scratch h.16 ;

\ : test-shiftbytes cr sk! sk. sh-bytes sk. ;
: test-shiftbytes 
  test-scratch-sb scratch 16 move
  cr ." in:  " sk. 
  sh-bytes 
  ." out: " sk. 
  true 16 0 do val-scratch-sb i + c@ scratch i + c@ = and loop if ." passed" else ." failed" then cr ;

\ print mix vectors m1 m2
: skb. 
  ." m1: " 4 0 do m1 i + c@ h.2 ."  " loop ."  - "
  ." m2: " 4 0 do m2 i + c@ h.2 ."  " loop cr ;

: test-mix
  test-scratch-mix-col scratch 16 move
  cr ." in:  " sk.
  mix-col
  ." out: " sk.
  true 16 0 do val-scratch-mix-col i + c@ scratch i + c@ = and loop if ." passed" else ." failed" then cr ;

: test-aes
  cr testdata indata 16 move
  indata testkey aes
  ." key: " testkey h.16 
  ." in:  " testdata h.16 
  ." out: " indata h.16
  ." val: " valdata h.16
  true 16 0 do valdata i + c@ indata i + c@ = and loop if ." passed" else ." failed" then cr ;

: time-aes millis 1000 0 do testdata testkey +aes loop millis swap - . ." /1000 ms" cr ;