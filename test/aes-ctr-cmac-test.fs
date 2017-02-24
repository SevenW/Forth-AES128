\ 128-bit AES-CTR and AES-CMAC for LMIC LoraWAN Test code
\ Author: SevenW from sevenwatt.com
\ Date  : 2017-Feb-23
\ 
\ Description:
\ Test module for AES128 CTR encryption and decryption
\ Test module for AES128 CMAC hash calculation
\ 
\ Requires : aes128.fs
\ Requires : aes-ctr-cmac.fs
\ 
\ Usage    : test-ctr
\ Usage    : test-cmac
\ Output   : last printed line should read "passed" and not "failed"
\ 
\ 

0 [if]
: helloworld s" LoraWAN Forth" ;
hex
create ctr-valdata-hw
  2B C, 38 C, C9 C, 38 C, 69 C, C7 C, 30 C, 47 C, 99 C, F3 C, 54 C, 1B C, 17 C, 00 C, 00 C, 00 C,
decimal
[then]

hex

create ctr-data
  17 C, 5A C, 5E C, B6 C, 91 C, 63 C, 45 C, FA C, 1B C, 20 C, 19 C, 4F C, AB C, 70 C, AD C, 95 C, 
  A2 C, 5C C, F8 C, A0 C, 14 C, 0C C, 25 C, 5A C, BB C, 22 C, CE C, CF C, 42 C, B0 C, 31 C, 78 C,

\ CTR initialization vector
create ctr-init-vector
01 C, 00 C, 00 C, 00 C, 00 C, 00 C, 1D C, 18 C, 01 C, 26 C, 00 C, 00 C, 00 C, 00 C, 00 C, 01 C,

create ctr-testkey
  69 C, 20 C, e2 C, 99 C, a5 C, 20 C, 2a C, 6d C, 65 C, 6e C, 63 C, 68 C, 69 C, 74 C, 6f C, 2a C,

create ctr-valdata
  CF C, 62 C, 83 C, 04 C, 36 C, 88 C, 15 C, 22 C, 65 C, 79 C, BD C, DE C, F3 C, 15 C, 4F C, 34 C,
  B6 C, A8 C, 26 C, 82 C, 57 C, 0B C, 3E C, 46 C, E2 C, 15 C, 6C C, E4 C, E0 C, D1 C, 67 C, A7 C, 

create cmac-msg-hdr \ 12 long to align, but 9 bytes meaningful
  40 C, 1D C, 18 C, 01 C, 26 C, 80 C, 00 C, 00 C, 01 C, 00 C, 00 C, 00 C,

create cmac-init-vector
  49 C, 00 C, 00 C, 00 C, 00 C, 00 C, 1D C, 18 C, 01 C, 26 C, 00 C, 00 C, 00 C, 00 C, 00 C, 16 C,

create cmac-hash-15
  EC C, DF C, 9C C, 8A C,

create cmac-hash-16
  CE C, 75 C, 31 C, B7 C,

create cmac-hash-17
  4F C, EE C, DA C, C6 C,

create cmac-hash-18
  8C C, 9F C, A8 C, C8 C,

decimal

32 buffer: indata
1 variable indata-len


: h.n ( caddr len -- )
  ( len ) 0 do dup i + c@ h.2 ."  " loop drop cr ;

: test-ctr-int ( len -- ) \ len <= 32
  cr 
  ctr-testkey AESkey 16 move
  ctr-init-vector AESaux 16 move
  indata-len ! 
  ctr-data indata indata-len @ move
  ." iv:  " ctr-init-vector 16 h.n 
  ." key: " ctr-testkey 16 h.n 
  ." in:  " indata indata-len @ h.n
  indata indata-len @ aes-ctr-int
  ." aux: " AESaux 16 h.n 
  ." out: " indata indata-len @ h.n
  ." val: " ctr-valdata indata-len @ h.n
  true indata-len @ 0 do ctr-valdata i + c@ indata i + c@ = and loop if ." passed" else ." failed" then cr
  ctr-init-vector AESaux 16 move
  ." iv:  " ctr-init-vector 16 h.n 
  ." key: " ctr-testkey 16 h.n 
  ." in:  " indata indata-len @ h.n
  indata indata-len @ aes-ctr-int
  ." aux: " AESaux 16 h.n 
  ." out: " indata indata-len @ h.n
  ." val: " ctr-data indata-len @ h.n
  true indata-len @ 0 do ctr-data i + c@ indata i + c@ = and loop if ." passed" else ." failed" then cr ;

: test-ctr ( -- )
   1 test-ctr-int
  15 test-ctr-int
  16 test-ctr-int
  17 test-ctr-int
  32 test-ctr-int ;

48 buffer: cmac-buffer

: test-cmac-int ( vali len -- ) \ len <= 32
  cr
  cmac-buffer 48 0 fill
  ctr-testkey AESkey 16 move
  cmac-init-vector AESaux 16 move
  cmac-msg-hdr cmac-buffer 9 move
  dup ctr-valdata cmac-buffer 9 + rot move  \ decrypted test data from test-ctr
  9 + dup
  dup AESaux 15 + c!                        \ update the length field to emulate LoraWAN IV
  ." key:   " AESkey 16 h.n
  ." aux:   " AESaux 16 h.n
  ." in:    " cmac-buffer over h.n
  cmac-buffer swap aes-cmac-int
  AESaux over cmac-buffer + 4 move 4 +
  ." key:   " AESkey 16 h.n
  ." aux:   " AESaux 16 h.n
  ." out:   " cmac-buffer swap h.n
  true 4 0 do ( vali flag ) over i + c@ AESaux i + c@ = and loop if ." passed" else ." failed" then drop cr ;

: test-cmac ( -- )
  cmac-hash-15 15 test-cmac-int
  cmac-hash-16 16 test-cmac-int
  cmac-hash-17 17 test-cmac-int
  cmac-hash-18 18 test-cmac-int ;
