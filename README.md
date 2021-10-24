# NEAT crypto - kr std
## Index
  - [Overview](#overview) 
  - [Getting Started](#getting-started)
  - [Demo](#Demo)
## About this project
Reversing and Implementing Korea's standard block cipher **NEAT**(not currently used).

## Overview
- In this project, I reverse and analyze the implementation of NEAT, a private crypto algorithm in Korea's algorithm.
- detail: [neat-project](https://c11.kr/neat-crypto)

## Getting Started
### Depencies
None

## Demo

- neat w/ python

```
[*] Preprocess
[*] key: b'ABCDEFGHIJKLMNOP'
[*] plaintext: b'M4KE_NE4T_NE4TER'

[*] Encrypt
[*] ciphertext: b'2\x04I9\xe54F\xadf\xb7c\xbe:\xc2n\x8e'

[*] Decrypt
[*] recovered: b'M4KE_NE4T_NE4TER'
```

- neat w/ c

```
[*] key:	4142434445464748494A4B4C4D4E4F50
[*] plaintext:	4D344B455F4E4534545F4E4534544552
[*] ciphertext:	32044939E53446AD66B763BE3AC26E8E
[*] recovered:	M4KE_NE4T_NE4TER
```

