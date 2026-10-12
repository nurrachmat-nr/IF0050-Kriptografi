"""
Pertemuan 5 - One-Time Pad & Pertukaran Kunci (Diffie-Hellman)
Studi Kasus 2: Serangan Two-Time Pad (kunci OTP dipakai ulang).

Jika kunci K yang sama dipakai untuk dua pesan:
    C1 = P1 XOR K
    C2 = P2 XOR K
    C1 XOR C2 = P1 XOR P2      <- kunci HILANG, penyerang tak butuh K

Teknik crib dragging: geser sebuah tebakan kata (crib) di sepanjang
C1 XOR C2. Bila di suatu posisi hasil XOR berupa teks yang masuk akal,
tebakan itu kemungkinan benar dan membuka potongan pesan lainnya.
Kasus nyata: proyek VENONA (1943-1980). Tidak perlu library tambahan.
"""

import secrets
import string

KARAKTER_WAJAR = set(string.ascii_uppercase + " ")


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def tampak_wajar(potongan: bytes) -> bool:
    """Heuristik sederhana: semua karakter berupa huruf kapital atau spasi."""
    try:
        teks = potongan.decode("ascii")
    except UnicodeDecodeError:
        return False
    return all(ch in KARAKTER_WAJAR for ch in teks)


def crib_dragging(c1_xor_c2: bytes, crib: bytes) -> list[tuple[int, str]]:
    """Coba crib di setiap posisi; kembalikan posisi yang menghasilkan teks wajar."""
    hasil = []
    for posisi in range(len(c1_xor_c2) - len(crib) + 1):
        potongan = xor_bytes(c1_xor_c2[posisi:posisi + len(crib)], crib)
        if tampak_wajar(potongan):
            hasil.append((posisi, potongan.decode()))
    return hasil


if __name__ == "__main__":
    p1 = b"SERANG POS UTARA PUKUL LIMA PAGI"
    p2 = b"PASUKAN CADANGAN TETAP DI MARKAS"
    kunci = secrets.token_bytes(len(p1))   # kunci acak sah ...
    c1 = xor_bytes(p1, kunci)              # ... tetapi dipakai DUA kali
    c2 = xor_bytes(p2, kunci)

    print("=" * 65)
    print("KESALAHAN OPERATOR: SATU KUNCI UNTUK DUA PESAN")
    print("=" * 65)
    print(f"C1 (hex): {c1.hex()}")
    print(f"C2 (hex): {c2.hex()}")

    x = xor_bytes(c1, c2)
    print(f"\nC1 XOR C2 == P1 XOR P2 ? {x == xor_bytes(p1, p2)}  -> kunci lenyap!")

    print("\n" + "=" * 65)
    print("CRIB DRAGGING OLEH PENYERANG (hanya memegang C1 dan C2)")
    print("=" * 65)
    for crib in [b"SERANG ", b" MARKAS", b"PUKUL "]:
        temuan = crib_dragging(x, crib)
        print(f"Crib {crib.decode()!r:<10} -> {len(temuan)} posisi wajar:"
              f" {temuan[:4]}")

    # Setelah satu pesan berhasil ditebak penuh, kunci & pesan lain terbuka total
    print("\nMisal penyerang berhasil menebak P1 secara utuh:")
    kunci_pulih = xor_bytes(c1, p1)
    print(f"  Kunci pulih   : {kunci_pulih.hex()}")
    print(f"  Sama dg asli? : {kunci_pulih == kunci}")
    print(f"  P2 terbongkar : {xor_bytes(c2, kunci_pulih).decode()}")
