\ 128-bit inverse AES Test code
\ Author: SevenW from sevenwatt.com
\ Date  : 2017-Feb-23
\ 
\ Description:
\ Test module for AES128 block cipher decryption
\ 
\ Requires : aes128.fs
\          : aes128inv.fs
\          : aes128test.fs
\ 
\ Usage    : test-inv-shiftbytes
\ Usage    : test-inv-mix
\ Usage    : test-inv-aes
\ Output   : last printed line should read "passed" and not "failed"
\ 
\ 

: test-inv-shiftbytes 
  test-scratch-sb scratch 16 move
  cr ." in:  " sk. 
  sh-bytes 
  ." out: " sk. 
  true 16 0 do val-scratch-sb i + c@ scratch i + c@ = and loop if ." passed" else ." failed" then cr
  ~sh-bytes 
  ." inv: " sk. 
  true 16 0 do test-scratch-sb i + c@ scratch i + c@ = and loop if ." passed" else ." failed" then cr ;

: test-inv-mix
  test-scratch-mix-col scratch 16 move
  cr ." in:  " scratch h.16
  mix-col
  ." out: " scratch h.16
  true 16 0 do val-scratch-mix-col i + c@ scratch i + c@ = and loop if ." passed" else ." failed" then cr
  ~mix-col
  ." inv: " scratch h.16 
  true 16 0 do test-scratch-mix-col i + c@ scratch i + c@ = and loop if ." passed" else ." failed" then cr ;

: test-inv-aes
  test-aes
  ." key: " testkey h.16 
  ." in:  " indata h.16 
  indata testkey -aes
  ." out: " indata h.16
  ." val: " testdata h.16
  true 16 0 do testdata i + c@ indata i + c@ = and loop if ." passed" else ." failed" then cr ;

: time-expkey millis 1000 0 do testkey expand-key loop millis swap - .  ." /1000 ms" cr ;
: time-inv-aes millis 1000 0 do testdata testkey -aes loop millis swap - . ." /1000 ms" cr ;