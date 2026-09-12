"""
Pertemuan 5 - One-Time Pad & Pertukaran Kunci (Diffie-Hellman)
Demonstrasi Diffie-Hellman dengan bilangan prima 512-bit dan simulasi
brute force Eve yang dibatasi waktu.

Ukuran 512-bit dipilih agar pembangkitan parameter masih nyaman untuk demo.
Ini bukan ukuran yang direkomendasikan untuk penerapan nyata; gunakan grup
standar minimal 2048-bit atau ECDH modern seperti X25519.

Instal dependensi:
    pip install pycryptodome
"""

import secrets
import time

from Crypto.Util.number import getPrime

PANJANG_PRIMA_BIT = 512
BATAS_BRUTE_FORCE_DETIK = 10.0


def bangkitkan_kunci_privat(p: int) -> int:
    """Membangkitkan eksponen privat acak dalam rentang [2, p - 2]."""
    return secrets.randbelow(p - 3) + 2


def hitung_kunci_publik(g: int, privat: int, p: int) -> int:
    """Menghitung g^privat mod p."""
    return pow(g, privat, p)


def hitung_rahasia_bersama(kunci_publik_lawan: int, kunci_privat: int, p: int) -> int:
    """Menghitung kunci_publik_lawan^kunci_privat mod p."""
    return pow(kunci_publik_lawan, kunci_privat, p)


def coba_brute_force(
    g: int, p: int, kunci_publik_target: int, batas_detik: float
) -> tuple[int | None, int, float]:
    """Mencari eksponen secara linear hanya sampai batas waktu tercapai."""
    waktu_mulai = time.perf_counter()
    kandidat = 1

    while time.perf_counter() - waktu_mulai < batas_detik:
        if pow(g, kandidat, p) == kunci_publik_target:
            return kandidat, kandidat, time.perf_counter() - waktu_mulai
        kandidat += 1

    return None, kandidat - 1, time.perf_counter() - waktu_mulai


if __name__ == "__main__":
    print("=" * 70)
    print("DIFFIE-HELLMAN DENGAN PRIMA 512-BIT")
    print("=" * 70)

    waktu_mulai_prima = time.perf_counter()
    p = getPrime(PANJANG_PRIMA_BIT)
    waktu_prima = time.perf_counter() - waktu_mulai_prima
    g = 5

    print(f"Panjang P          : {p.bit_length()} bit")
    print(f"Waktu membuat P    : {waktu_prima:.4f} detik")
    print(f"Generator sederhana: G = {g}")

    waktu_mulai_dh = time.perf_counter()
    privat_alice = bangkitkan_kunci_privat(p)
    publik_alice = hitung_kunci_publik(g, privat_alice, p)
    privat_bob = bangkitkan_kunci_privat(p)
    publik_bob = hitung_kunci_publik(g, privat_bob, p)
    rahasia_alice = hitung_rahasia_bersama(publik_bob, privat_alice, p)
    rahasia_bob = hitung_rahasia_bersama(publik_alice, privat_bob, p)
    waktu_dh = time.perf_counter() - waktu_mulai_dh

    print(f"\nPertukaran kunci selesai dalam {waktu_dh:.6f} detik.")
    print(f"Rahasia bersama sama? {rahasia_alice == rahasia_bob}")
    print(f"Kunci publik Alice  : {publik_alice}\n")

    print("=" * 70)
    print(f"EVE: BRUTE FORCE DIBATASI {BATAS_BRUTE_FORCE_DETIK:.0f} DETIK")
    print("=" * 70)
    kandidat, jumlah_percobaan, waktu_brute_force = coba_brute_force(
        g, p, publik_alice, BATAS_BRUTE_FORCE_DETIK
    )

    print(f"Percobaan Eve       : {jumlah_percobaan:,} kandidat")
    print(f"Waktu berjalan      : {waktu_brute_force:.4f} detik")
    if kandidat is None:
        print("Hasil               : kunci privat Alice TIDAK ditemukan.")
        print("Kesimpulan: P sangat besar membuat ruang pencarian eksponen")
        print("terlalu luas untuk brute force, walaupun DH sah tetap cepat.")
    else:
        print(f"Hasil               : Eve menemukan kandidat a = {kandidat}.")
        print("Hasil ini sangat tidak lazim untuk eksponen privat 512-bit acak.")