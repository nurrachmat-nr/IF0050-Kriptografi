"""
Pertemuan 6 - Kriptografi Kunci-Publik: RSA & Elliptic Curve Cryptography
Implementasi RSA "buku teks" (textbook RSA) dengan bilangan prima KECIL,
HANYA untuk memahami mekanisme matematisnya langkah demi langkah.

PERINGATAN: JANGAN PERNAH memakai kode ini untuk keamanan sungguhan!
Bilangan prima yang dipakai sangat kecil (mudah difaktorkan), dan tidak
ada skema padding (mis. OAEP) -- lihat rsa_praktik.py untuk versi yang
aman dipakai di dunia nyata.
"""

import math


def egcd(a: int, b: int):
    if b == 0:
        return a, 1, 0
    g, x1, y1 = egcd(b, a % b)
    return g, y1, x1 - (a // b) * y1


def invers_modular(e: int, phi: int) -> int:
    g, x, _ = egcd(e, phi)
    if g != 1:
        raise ValueError("e dan phi(n) tidak koprima -- tidak ada invers modular")
    return x % phi


def bangkitkan_kunci(p: int, q: int, e: int = 17):
    n = p * q
    phi = (p - 1) * (q - 1)
    if math.gcd(e, phi) != 1:
        raise ValueError(f"e={e} tidak koprima dengan phi(n)={phi}, pilih e lain")
    d = invers_modular(e, phi)
    return {"n": n, "phi": phi, "e": e, "d": d}


def enkripsi(m: int, e: int, n: int) -> int:
    return pow(m, e, n)


def dekripsi(c: int, d: int, n: int) -> int:
    return pow(c, d, n)


if __name__ == "__main__":
    # Bilangan prima KECIL -- hanya demonstrasi (RSA nyata pakai prima >= 1024 bit)
    p, q = 61, 53
    kunci = bangkitkan_kunci(p, q, e=17)

    print("=" * 65)
    print("PEMBANGKITAN KUNCI RSA (contoh edukasi, p & q kecil)")
    print("=" * 65)
    print(f"p = {p}, q = {q}")
    print(f"n = p * q            = {kunci['n']}")
    print(f"phi(n) = (p-1)(q-1)  = {kunci['phi']}")
    print(f"e (kunci publik)     = {kunci['e']}   (koprima dengan phi(n))")
    print(f"d (kunci privat)     = {kunci['d']}   (invers modular dari e terhadap phi(n))")
    print(f"\nKunci publik  = (e={kunci['e']}, n={kunci['n']})")
    print(f"Kunci privat  = (d={kunci['d']}, n={kunci['n']})")

    print()
    print("=" * 65)
    print("ENKRIPSI & DEKRIPSI")
    print("=" * 65)
    pesan = 65  # pesan direpresentasikan sebagai bilangan bulat (0 <= m < n)
    cipherteks = enkripsi(pesan, kunci["e"], kunci["n"])
    hasil_dekripsi = dekripsi(cipherteks, kunci["d"], kunci["n"])
    print(f"Plainteks (m)  : {pesan}")
    print(f"Cipherteks (c) : m^e mod n = {pesan}^{kunci['e']} mod {kunci['n']} = {cipherteks}")
    print(f"Dekripsi       : c^d mod n = {cipherteks}^{kunci['d']} mod {kunci['n']} = {hasil_dekripsi}")
    print(f"Berhasil?      : {hasil_dekripsi == pesan}")

    print()
    print("=" * 65)
    print("KELEMAHAN TEXTBOOK RSA: DETERMINISTIK (tanpa padding)")
    print("=" * 65)
    c1 = enkripsi(pesan, kunci["e"], kunci["n"])
    c2 = enkripsi(pesan, kunci["e"], kunci["n"])
    print(f"Enkripsi pesan {pesan} dua kali menghasilkan cipherteks: {c1} dan {c2}")
    print(f"Identik? {c1 == c2}  <- penyerang bisa mendeteksi pesan yang sama diulang!")
    print("Inilah sebabnya RSA di dunia nyata WAJIB memakai skema padding")
    print("acak seperti OAEP (lihat rsa_praktik.py).")
