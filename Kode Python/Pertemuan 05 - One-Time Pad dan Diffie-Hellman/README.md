# Pertemuan 05 — One-Time Pad dan Diffie-Hellman

Kode demo dan studi kasus untuk Pertemuan 5. Semua skrip berdiri sendiri, cukup dijalankan dengan `python nama_file.py`.

```bash
pip install pycryptodome cryptography
```

## Demo dasar

| File | Isi | Library |
|---|---|---|
| `one_time_pad.py` | OTP huruf (mod 26), bukti satu cipherteks → banyak plainteks | — |
| `diffie_hellman.py` | Protokol DH P = 23, G = 5 dan sudut pandang Eve | — |
| `diffie_hellman_prima_512bit.py` | DH 512-bit dan brute force Eve dengan batas waktu (jawaban Latihan Mandiri) | pycryptodome |

## Studi kasus pendalaman

| # | File | Kasus | Library |
|---|---|---|---|
| 1 | `otp_biner_xor.py` | OTP digital (Vernam) dengan XOR byte | — |
| 2 | `otp_two_time_pad.py` | Kunci dipakai ulang → C1⊕C2 = P1⊕P2, crib dragging (VENONA) | — |
| 3 | `otp_malleability.py` | Mengubah nominal transfer tanpa kunci; pertahanan HMAC | — |
| 4 | `otp_prng_lemah.py` | Kunci dari `random.seed(waktu)` dibobol dalam milidetik | — |
| 5 | `dh_square_and_multiply.py` | Jejak perpangkatan modular cepat vs naif | — |
| 6 | `dh_mitm_simulasi.py` | MITM membaca & mengubah pesan AES-GCM; pertahanan tanda tangan Ed25519 | pycryptodome |
| 7 | `dh_brute_force_benchmark.py` | Brute force vs baby-step giant-step, ekstrapolasi ke 2048-bit | pycryptodome |
| 8 | `dh_validasi_parameter.py` | Serangan kunci publik 0/1/P−1, orde generator, safe prime | — |
| 9 | `ecdh_x25519_tls_mini.py` | Mini handshake TLS 1.3: X25519 + HKDF + AES-256-GCM, PFS | cryptography |

Semua parameter kecil (P = 23, prima 16–128 bit) **hanya untuk edukasi**. Penerapan nyata memakai grup ≥ 2048-bit (RFC 7919) atau X25519.
