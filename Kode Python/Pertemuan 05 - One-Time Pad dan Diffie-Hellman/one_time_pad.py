"""
Pertemuan 5 - One-Time Pad & Pertukaran Kunci (Diffie-Hellman)
Implementasi One-Time Pad (OTP) yang benar: kunci dibangkitkan dengan
secrets.choice() (Cryptographically Secure PRNG), BUKAN random.choice()
biasa yang tidak aman secara kriptografis.

Rumus:
    Enkripsi : c_i = (p_i + k_i) mod 26
    Dekripsi : p_i = (c_i - k_i) mod 26
    Syarat mutlak: panjang kunci = panjang plainteks, kunci acak sungguhan,
    dan kunci HANYA dipakai satu kali lalu dibuang.
"""

import secrets
import string

A = ord("A")
ALPHABET = string.ascii_uppercase


def bangkitkan_kunci(panjang: int) -> str:
    """Kunci acak sungguhan (CSPRNG) sepanjang plainteks -- dipakai SEKALI saja."""
    return "".join(secrets.choice(ALPHABET) for _ in range(panjang))


def enkripsi(plainteks: str, kunci: str) -> str:
    plainteks = plainteks.upper().replace(" ", "")
    if len(kunci) < len(plainteks):
        raise ValueError("Kunci OTP harus sepanjang atau lebih panjang dari plainteks!")
    return "".join(chr((ord(p) - A + ord(k) - A) % 26 + A) for p, k in zip(plainteks, kunci))


def dekripsi(cipherteks: str, kunci: str) -> str:
    return "".join(chr((ord(c) - A - (ord(k) - A)) % 26 + A) for c, k in zip(cipherteks, kunci))


if __name__ == "__main__":
    plainteks = "OTPADALAHCIPHERYANGTIDAKBISADIPECAHKAN"
    kunci = bangkitkan_kunci(len(plainteks))

    cipherteks = enkripsi(plainteks, kunci)
    hasil_dekripsi = dekripsi(cipherteks, kunci)

    print("=" * 65)
    print("ENKRIPSI & DEKRIPSI ONE-TIME PAD")
    print("=" * 65)
    print(f"Plainteks   : {plainteks}")
    print(f"Kunci (CSPRNG, dipakai sekali): {kunci}")
    print(f"Cipherteks  : {cipherteks}")
    print(f"Dekripsi    : {hasil_dekripsi}")
    print(f"Berhasil?   : {hasil_dekripsi == plainteks}")

    print()
    print("=" * 65)
    print("PEMBUKTIAN: SATU CIPHERTEKS, BANYAK KEMUNGKINAN PLAINTEKS")
    print("=" * 65)
    print("Tanpa mengetahui kunci, cipherteks di bawah ini bisa didekripsi")
    print("menjadi PESAN BERMAKNA APAPUN -- asalkan kunci yang dicoba tepat:")
    print()

    kriptogram = "HOJKOREGHP"  # 10 huruf, hasil enkripsi "onetimepad" dengan sebuah kunci
    kandidat_plainteks = ["ONETIMEPAD", "SALMONEGGS", "GREENFIELD"]
    for kandidat in kandidat_plainteks:
        # kunci = (cipherteks - plainteks) mod 26 -- dihitung mundur agar
        # pembuktian ini terjamin benar secara matematis, bukan sekadar contoh.
        kunci_kandidat = "".join(
            chr((ord(c) - ord(p)) % 26 + A) for c, p in zip(kriptogram, kandidat)
        )
        hasil = dekripsi(kriptogram, kunci_kandidat)
        cocok = "OK" if hasil == kandidat else "TIDAK COCOK"
        print(f"  Kunci {kunci_kandidat} -> dekripsi = {hasil}  [{cocok}]")

    print()
    print(">> Karena kunci bisa berupa APA SAJA, kriptanalis tidak punya cara")
    print(">> matematis untuk menentukan mana plainteks yang benar -- inilah")
    print(">> perfect secrecy (Claude Shannon, 1949).")
