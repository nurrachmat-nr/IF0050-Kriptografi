"""
Pertemuan 5 - One-Time Pad & Pertukaran Kunci (Diffie-Hellman)
Studi Kasus 1: One-Time Pad versi biner (Vernam) dengan operasi XOR.

Komputer menyimpan data sebagai byte, bukan huruf A-Z. OTP digital bekerja
per byte:
    Enkripsi : c = p XOR k
    Dekripsi : p = c XOR k      (karena k XOR k = 0 dan x XOR 0 = x)

Kunci dibangkitkan dengan secrets.token_bytes() (CSPRNG) sepanjang pesan.
Tidak perlu library tambahan.
"""

import secrets


def bangkitkan_kunci(panjang: int) -> bytes:
    """Kunci acak sungguhan (CSPRNG) sepanjang pesan -- dipakai SEKALI saja."""
    return secrets.token_bytes(panjang)


def xor_bytes(a: bytes, b: bytes) -> bytes:
    if len(b) < len(a):
        raise ValueError("Kunci OTP harus sepanjang atau lebih panjang dari pesan!")
    return bytes(x ^ y for x, y in zip(a, b))


def enkripsi(plainteks: bytes, kunci: bytes) -> bytes:
    return xor_bytes(plainteks, kunci)


def dekripsi(cipherteks: bytes, kunci: bytes) -> bytes:
    return xor_bytes(cipherteks, kunci)  # operasi yang SAMA dengan enkripsi


def tampilkan_bit(label: str, data: bytes, n: int = 4) -> None:
    bit = " ".join(f"{x:08b}" for x in data[:n])
    print(f"  {label:<12}: {bit} ...")


if __name__ == "__main__":
    pesan = "Rapat dosen Senin pukul 09.00 di Lab Kripto".encode("utf-8")
    kunci = bangkitkan_kunci(len(pesan))
    cipherteks = enkripsi(pesan, kunci)
    hasil = dekripsi(cipherteks, kunci)

    print("=" * 65)
    print("ONE-TIME PAD BINER (XOR)")
    print("=" * 65)
    print(f"Plainteks   : {pesan.decode()}")
    print(f"Panjang     : {len(pesan)} byte  -> kunci juga {len(kunci)} byte")
    print(f"Kunci (hex) : {kunci.hex()}")
    print(f"Cipher (hex): {cipherteks.hex()}")
    print(f"Dekripsi    : {hasil.decode()}")
    print(f"Berhasil?   : {hasil == pesan}")

    print("\nTampilan per bit (4 byte pertama):")
    tampilkan_bit("plainteks", pesan)
    tampilkan_bit("kunci", kunci)
    tampilkan_bit("cipherteks", cipherteks)

    # Statistik: cipherteks OTP terlihat seperti derau acak murni
    jumlah_bit_1 = sum(bin(x).count("1") for x in cipherteks)
    total_bit = len(cipherteks) * 8
    print(f"\nProporsi bit 1 pada cipherteks: {jumlah_bit_1}/{total_bit}"
          f" = {jumlah_bit_1 / total_bit:.2%}  (ideal ~50%)")
