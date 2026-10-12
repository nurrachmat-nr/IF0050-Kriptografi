"""
Pertemuan 5 - One-Time Pad & Pertukaran Kunci (Diffie-Hellman)
Studi Kasus 8: Validasi parameter dan kunci publik Diffie-Hellman.

Dua kesalahan implementasi yang sering terjadi:
  1. Tidak memvalidasi kunci publik lawan. Penyerang aktif mengirim B = 1
     atau B = P-1 sehingga rahasia bersama menjadi 1 atau +-1 -- mudah ditebak.
  2. Memakai prima sembarang. Jika P-1 punya banyak faktor kecil, G bisa
     terjebak di subgrup kecil (small-subgroup). Solusi: safe prime P = 2q+1.

Tidak perlu library tambahan (uji prima Miller-Rabin ditulis sendiri).
"""

import secrets


def adalah_prima(n: int, putaran: int = 40) -> bool:
    """Uji prima probabilistik Miller-Rabin."""
    if n < 2:
        return False
    for kecil in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29):
        if n % kecil == 0:
            return n == kecil
    d, s = n - 1, 0
    while d % 2 == 0:
        d, s = d // 2, s + 1
    for _ in range(putaran):
        x = pow(secrets.randbelow(n - 3) + 2, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def bangkitkan_safe_prime(bit: int) -> tuple[int, int]:
    """Cari P = 2q + 1 dengan q dan P sama-sama prima."""
    while True:
        q = secrets.randbits(bit - 1) | (1 << (bit - 2)) | 1
        if adalah_prima(q) and adalah_prima(2 * q + 1):
            return 2 * q + 1, q


def orde(g: int, p: int, q: int) -> int:
    """Pada safe prime, orde elemen hanya bisa 1, 2, q, atau 2q."""
    for kandidat in (1, 2, q, 2 * q):
        if pow(g, kandidat, p) == 1:
            return kandidat
    raise ValueError("bukan safe prime")


def validasi_kunci_publik(y: int, p: int, q: int) -> bool:
    """Tolak 0, 1, P-1, nilai di luar rentang, dan nilai di luar subgrup orde q."""
    return 2 <= y <= p - 2 and pow(y, q, p) == 1


if __name__ == "__main__":
    print("=" * 65)
    print("1. SERANGAN KUNCI PUBLIK TIDAK VALID (P = 23, G = 5)")
    print("=" * 65)
    P, Q = 23, 11                                   # 23 = 2*11 + 1 adalah safe prime
    a = secrets.randbelow(P - 3) + 2
    for b_palsu in [1, P - 1, 0]:
        rahasia = pow(b_palsu, a, P)
        print(f"Eve kirim B={b_palsu:>2} -> rahasia Alice = {rahasia:>2} "
              f"(validasi: {'LOLOS' if validasi_kunci_publik(b_palsu, P, Q) else 'DITOLAK'})")
    print(">> Tanpa validasi, Eve bisa menebak kunci sesi hanya dari 1-2 kemungkinan.")

    print("\n" + "=" * 65)
    print("2. MEMILIH GENERATOR PADA SAFE PRIME P = 23")
    print("=" * 65)
    for g in [2, 5, 22]:
        o = orde(g, P, Q)
        print(f"G = {g:>2}: orde {o:>2} -> menghasilkan {o} nilai berbeda")

    print("\n" + "=" * 65)
    print("3. MEMBANGKITKAN SAFE PRIME 128-BIT")
    print("=" * 65)
    p, q = bangkitkan_safe_prime(128)
    print(f"P = {p}")
    print(f"q = (P-1)/2 = {q}")
    print(f"P prima? {adalah_prima(p)} | q prima? {adalah_prima(q)}")
    print("Pada produksi: JANGAN membuat sendiri; pakai grup ffdhe2048 (RFC 7919)")
    print("atau ECDH X25519 yang tidak memerlukan validasi rumit ini.")
