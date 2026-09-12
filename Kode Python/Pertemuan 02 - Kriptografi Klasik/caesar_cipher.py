"""
Pertemuan 2 - Kriptografi Klasik & Kriptanalisis Dasar
Implementasi Caesar Cipher: enkripsi, dekripsi, dan kriptanalisis
dengan exhaustive key search (brute force).

Rumus:
    Enkripsi : c = E(p) = (p + k) mod 26
    Dekripsi : p = D(c) = (c - k) mod 26
    k        = kunci pergeseran (0..25)
"""

A = ord("A")  # kode ASCII huruf 'A', dipakai sebagai basis 0


def enkripsi(plainteks: str, k: int) -> str:
    hasil = []
    for ch in plainteks.upper():
        if ch.isalpha():
            p = ord(ch) - A
            c = (p + k) % 26
            hasil.append(chr(c + A))
        else:
            hasil.append(ch)  # spasi & tanda baca tidak diubah
    return "".join(hasil)


def dekripsi(cipherteks: str, k: int) -> str:
    return enkripsi(cipherteks, -k % 26)


def kriptanalisis_brute_force(cipherteks: str) -> None:
    """Mencoba seluruh 26 kemungkinan kunci (exhaustive key search)."""
    print(f"Kriptogram : {cipherteks}\n")
    print(f"{'k':>3} | Hasil Dekripsi")
    print("-" * 40)
    for k in range(26):
        print(f"{k:>3} | {dekripsi(cipherteks, k)}")

if __name__ == "__main__":
    plainteks = "AWASI ASTERIX DAN TEMANNYA OBELIX"
    kunci = 3

    cipherteks = enkripsi(plainteks, kunci)
    hasil_dekripsi = dekripsi(cipherteks, kunci)

    print("=" * 60)
    print("ENKRIPSI & DEKRIPSI CAESAR CIPHER")
    print("=" * 60)
    print(f"Plainteks   : {plainteks}")
    print(f"Kunci (k)   : {kunci}")
    print(f"Cipherteks  : {cipherteks}")
    print(f"Dekripsi    : {hasil_dekripsi}")
    print(f"Berhasil?   : {hasil_dekripsi == plainteks}")

    print()
    print("=" * 60)
    print("KRIPTANALISIS: EXHAUSTIVE KEY SEARCH (BRUTE FORCE)")
    print("=" * 60)
    kriptanalisis_brute_force("XMZVH")  # contoh kriptogram, k rahasia = 21 -> "CREAM"
