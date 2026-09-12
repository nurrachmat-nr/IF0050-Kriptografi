"""
Pertemuan 3 - Kriptografi Simetris: Stream & Block Cipher
Demo RC4 (Rivest Cipher 4), stream cipher historis.

RC4 pernah digunakan pada WEP dan TLS, tetapi kini tidak aman karena bias
keystream. File ini hanya untuk pembelajaran, bukan penggunaan nyata.

Instal dependensi:
    pip install pycryptodome
"""

from Crypto.Cipher import ARC4
from Crypto.Random import get_random_bytes


def enkripsi_rc4(plainteks: bytes, kunci: bytes) -> bytes:
    """Mengenkripsi data; operasi yang sama juga digunakan untuk dekripsi."""
    cipher = ARC4.new(kunci, drop=3072)
    return cipher.encrypt(plainteks)


if __name__ == "__main__":
    plainteks = b"Pesan rahasia untuk demonstrasi RC4."
    kunci = get_random_bytes(32)

    print("=" * 65)
    print("DEMONSTRASI RC4 - HISTORIS, JANGAN DIGUNAKAN DI PRODUKSI")
    print("=" * 65)
    cipherteks = enkripsi_rc4(plainteks, kunci)
    hasil_dekripsi = enkripsi_rc4(cipherteks, kunci)

    print(f"Plainteks : {plainteks.decode()}")
    print(f"Cipherteks: {cipherteks.hex()}")
    print(f"Dekripsi berhasil? {hasil_dekripsi == plainteks}")
    print("RC4 memakai keystream XOR; enkripsi dan dekripsi adalah operasi sama.")