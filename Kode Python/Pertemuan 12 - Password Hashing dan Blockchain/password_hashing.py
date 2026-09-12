"""
Pertemuan 12 - Kriptografi Aplikatif: Password Hashing & Keamanan Blockchain
Mengapa SHA-256 polos TIDAK COCOK untuk menyimpan kata sandi, dan mengapa
Argon2 (pemenang Password Hashing Competition 2015, rekomendasi OWASP)
adalah pilihan yang benar.

Instal dependensi:
    pip install argon2-cffi bcrypt
"""

import hashlib
import time

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError


def hash_naif_sha256(password: str) -> str:
    """CARA YANG SALAH: hash cepat tanpa salt, rentan rainbow table & brute force GPU."""
    return hashlib.sha256(password.encode()).hexdigest()


if __name__ == "__main__":
    print("=" * 65)
    print("MASALAH 1: HASH CEPAT TANPA SALT RENTAN RAINBOW TABLE")
    print("=" * 65)
    password_umum = "password123"
    print(f"Password umum   : {password_umum}")
    print(f"SHA-256         : {hash_naif_sha256(password_umum)}")
    print("Nilai hash password yang SAMA akan SELALU identik -- penyerang cukup")
    print("mencocokkan dengan rainbow table (daftar hash password umum yang")
    print("sudah dihitung sebelumnya) untuk membongkarnya dalam hitungan detik.")

    print()
    print("=" * 65)
    print("MASALAH 2: SHA-256 TERLALU CEPAT -- MEMUDAHKAN BRUTE FORCE GPU")
    print("=" * 65)
    mulai = time.perf_counter()
    for _ in range(200_000):
        hashlib.sha256(b"tebakan-password").hexdigest()
    durasi = time.perf_counter() - mulai
    print(f"200.000 kali hashing SHA-256 di CPU biasa: {durasi:.3f} detik")
    print(f"-> ~{200_000 / durasi:,.0f} percobaan/detik HANYA di satu CPU;")
    print("   GPU modern dapat mencapai MILIARAN percobaan/detik untuk SHA-256.")

    print()
    print("=" * 65)
    print("SOLUSI: ARGON2 -- KEY DERIVATION FUNCTION UNTUK PASSWORD")
    print("=" * 65)
    ph = PasswordHasher()  # otomatis membangkitkan salt acak setiap kali
    hash_1 = ph.hash(password_umum)
    hash_2 = ph.hash(password_umum)
    print(f"Password sama    : {password_umum}")
    print(f"Argon2 hash #1   : {hash_1}")
    print(f"Argon2 hash #2   : {hash_2}")
    print(f"Kedua hash identik? {hash_1 == hash_2}  <- SELALU berbeda berkat salt acak")

    mulai = time.perf_counter()
    ph.hash(password_umum)
    durasi_argon2 = time.perf_counter() - mulai
    print(f"\nWaktu SATU KALI hashing Argon2: {durasi_argon2 * 1000:.1f} ms")
    print("(SENGAJA lambat & memakan banyak memori -- inilah yang membuat")
    print(" brute force menjadi TIDAK EKONOMIS bagi penyerang, bahkan dengan GPU.)")

    print()
    print("=" * 65)
    print("VERIFIKASI LOGIN")
    print("=" * 65)
    try:
        ph.verify(hash_1, "password123")
        print("Login dengan password BENAR -> diterima")
    except VerifyMismatchError:
        print("Login DITOLAK")

    try:
        ph.verify(hash_1, "password124")
        print("Login dengan password SALAH -> diterima (seharusnya tidak!)")
    except VerifyMismatchError:
        print("Login dengan password SALAH -> DITOLAK sebagaimana mestinya")
