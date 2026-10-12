"""
Pertemuan 5 - One-Time Pad & Pertukaran Kunci (Diffie-Hellman)
Studi Kasus 7: Seberapa cepat Eve memecahkan logaritma diskrit?

Membandingkan dua algoritma pada prima P berukuran 16 s.d. 40 bit:
  1. Brute force       : coba x = 1, 2, 3, ...        -> O(P) langkah
  2. Baby-step giant-step (Shanks, 1971)              -> O(sqrt(P)) langkah
Lalu mengekstrapolasi waktunya ke ukuran P nyata (512 dan 2048 bit).

Pelajaran: algoritma lebih pintar memangkas waktu secara drastis, tetapi
untuk P >= 2048 bit tetap tak terjangkau. (Penyerang nyata memakai Number
Field Sieve yang lebih cepat lagi -- karena itu 512 & 1024 bit sudah tidak
aman, lihat kasus Logjam 2015.)

Instal dependensi:
    pip install pycryptodome
"""

import math
import secrets
import time

from Crypto.Util.number import getPrime

BATAS_BRUTE_FORCE_DETIK = 10.0


def brute_force(g: int, target: int, p: int) -> int | None:
    nilai, mulai = 1, time.perf_counter()
    for x in range(1, p):
        nilai = (nilai * g) % p                   # g^x secara inkremental
        if nilai == target:
            return x
        if time.perf_counter() - mulai > BATAS_BRUTE_FORCE_DETIK:
            return None
    return None


def baby_step_giant_step(g: int, target: int, p: int) -> int | None:
    m = math.isqrt(p - 1) + 1
    tabel = {}
    nilai = 1
    for j in range(m):                            # baby steps: g^j
        tabel.setdefault(nilai, j)
        nilai = (nilai * g) % p
    faktor = pow(g, -m, p)                        # g^(-m) mod p
    gamma = target
    for i in range(m):                            # giant steps: target * g^(-im)
        if gamma in tabel:
            return i * m + tabel[gamma]
        gamma = (gamma * faktor) % p
    return None


def format_waktu(log10_detik: float) -> str:
    """Menampilkan waktu dari nilai log10(detik) agar bilangan raksasa tidak overflow."""
    if log10_detik < math.log10(3600):
        return f"{10 ** log10_detik:,.2f} detik"
    if log10_detik < math.log10(31_557_600):
        return f"{10 ** log10_detik / 86_400:,.1f} hari"
    log10_tahun = log10_detik - math.log10(31_557_600)
    if log10_tahun < 6:
        return f"{10 ** log10_tahun:,.0f} tahun"
    return f"~10^{log10_tahun:.0f} tahun"


if __name__ == "__main__":
    print("=" * 72)
    print(f"{'Ukuran P':>9} | {'Brute force':>14} | {'Baby-step giant-step':>21} | Cocok?")
    print("=" * 72)
    laju_bf = laju_bsgs = None
    for bit in [16, 24, 32, 40]:
        p, g = getPrime(bit), 5
        a = secrets.randbelow(p - 3) + 2
        target = pow(g, a, p)

        t0 = time.perf_counter(); x_bsgs = baby_step_giant_step(g, target, p)
        t_bsgs = time.perf_counter() - t0
        laju_bsgs = t_bsgs / math.sqrt(p)

        if bit <= 32:
            t0 = time.perf_counter(); x_bf = brute_force(g, target, p)
            t_bf = time.perf_counter() - t0
            if x_bf is not None:
                laju_bf = t_bf / x_bf
            teks_bf = f"{t_bf:10.4f} s" if x_bf is not None else "> batas waktu"
        else:
            x_bf, teks_bf = None, "(dilewati)"
        cocok = pow(g, x_bsgs, p) == target
        print(f"{bit:>6} bit | {teks_bf:>14} | {t_bsgs:18.4f} s | {cocok}")

    print("\nEkstrapolasi (berdasarkan laju di komputer ini):")
    for bit in [64, 128, 512, 2048]:
        log_bf = (bit - 1) * math.log10(2) + math.log10(laju_bf)      # rata-rata 2^(bit-1) langkah
        log_bsgs = (bit / 2) * math.log10(2) + math.log10(laju_bsgs)  # sqrt(2^bit) langkah
        print(f"  P {bit:>4} bit: brute force {format_waktu(log_bf):>18}"
              f" | BSGS {format_waktu(log_bsgs):>18}")
    print("Catatan: BSGS juga butuh memori sebesar sqrt(P) entri tabel.")
