"""
Pertemuan 5 - One-Time Pad & Pertukaran Kunci (Diffie-Hellman)
Studi Kasus 5: Perpangkatan modular cepat (square-and-multiply).

Inti komputasi Diffie-Hellman adalah G^a mod P. Menghitung G^a dulu baru
di-mod tidak mungkin untuk a ratusan digit. Square-and-multiply membaca
eksponen dalam biner dan mereduksi mod P di SETIAP langkah, sehingga hanya
butuh ~2*log2(a) perkalian. Inilah yang dikerjakan pow(G, a, P) di Python.
Tidak perlu library tambahan.
"""

import secrets
import time


def pangkat_modular(basis: int, eksponen: int, modulus: int, jejak: bool = False) -> int:
    """Square-and-multiply kiri-ke-kanan, dengan opsi menampilkan langkah."""
    hasil = 1
    for bit in bin(eksponen)[2:]:
        hasil = (hasil * hasil) % modulus            # SQUARE selalu
        langkah = "S"
        if bit == "1":
            hasil = (hasil * basis) % modulus        # MULTIPLY bila bit = 1
            langkah = "S+M"
        if jejak:
            print(f"  bit {bit}  {langkah:<4} -> {hasil}")
    return hasil


def pangkat_naif(basis: int, eksponen: int, modulus: int) -> int:
    """Perkalian berulang sebanyak eksponen kali (dengan reduksi mod)."""
    hasil = 1
    for _ in range(eksponen):
        hasil = (hasil * basis) % modulus
    return hasil


if __name__ == "__main__":
    print("=" * 65)
    print("JEJAK SQUARE-AND-MULTIPLY: 11^10 mod 23  (10 = 1010 biner)")
    print("=" * 65)
    print(f"Hasil = {pangkat_modular(11, 10, 23, jejak=True)}  |  pow() = {pow(11, 10, 23)}")

    print("\n" + "=" * 65)
    print("PERBANDINGAN WAKTU (modulus 2048-bit)")
    print("=" * 65)
    p = (1 << 2048) - 159                      # bilangan ganjil besar untuk uji kecepatan
    for bit_eksponen in [16, 20, 24]:
        e = secrets.randbits(bit_eksponen) | (1 << (bit_eksponen - 1))
        t0 = time.perf_counter(); r1 = pangkat_naif(5, e, p); t_naif = time.perf_counter() - t0
        t0 = time.perf_counter(); r2 = pangkat_modular(5, e, p); t_sm = time.perf_counter() - t0
        print(f"eksponen {bit_eksponen:>2}-bit: naif {t_naif:8.4f} s | "
              f"square-multiply {t_sm * 1000:7.3f} ms | sama? {r1 == r2}")

    e = secrets.randbits(2048)
    t0 = time.perf_counter(); pangkat_modular(5, e, p); t_sm = time.perf_counter() - t0
    print(f"eksponen 2048-bit: naif ~ mustahil (2^2048 perkalian) | "
          f"square-multiply {t_sm * 1000:7.3f} ms")
