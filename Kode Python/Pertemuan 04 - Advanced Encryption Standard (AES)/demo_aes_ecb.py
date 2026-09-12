"""
Pertemuan 4 - Advanced Encryption Standard (AES)
Demonstrasi kelemahan AES-ECB (Electronic Codebook).

ECB mengenkripsi blok plaintext identik menjadi blok cipherteks identik.
Karena pola data dapat terlihat, ECB tidak boleh digunakan untuk mengenkripsi
file, gambar, atau pesan pada aplikasi nyata.

Instal dependensi:
    pip install pycryptodome
"""

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

ITERASI_KDF = 600_000


def turunkan_kunci(passphrase: str, salt: bytes) -> bytes:
    """Menurunkan kunci AES-256 (32 byte) dari passphrase pengguna."""
    return PBKDF2(passphrase, salt, dkLen=32, count=ITERASI_KDF, hmac_hash_module=SHA256)


def bagi_blok(data: bytes) -> list[bytes]:
    """Memisahkan data menjadi blok AES berukuran 16 byte."""
    return [data[indeks : indeks + AES.block_size] for indeks in range(0, len(data), AES.block_size)]


def enkripsi_ecb(data: bytes, passphrase: str) -> tuple[bytes, bytes]:
    salt = get_random_bytes(16)
    kunci = turunkan_kunci(passphrase, salt)
    cipher = AES.new(kunci, AES.MODE_ECB)
    return salt, cipher.encrypt(pad(data, AES.block_size))


def dekripsi_ecb(salt: bytes, cipherteks: bytes, passphrase: str) -> bytes:
    kunci = turunkan_kunci(passphrase, salt)
    cipher = AES.new(kunci, AES.MODE_ECB)
    return unpad(cipher.decrypt(cipherteks), AES.block_size)


if __name__ == "__main__":
    blok_identik = b"0123456789ABCDEF"
    dokumen_asli = blok_identik * 4
    passphrase = "K@t4S4ndi-Kuat-2026!"

    print("=" * 60)
    print("DEMONSTRASI POLA AES-ECB - JANGAN GUNAKAN DI PRODUKSI")
    print("=" * 60)
    salt, cipherteks = enkripsi_ecb(dokumen_asli, passphrase)

    print("Blok plaintext:")
    for indeks, blok in enumerate(bagi_blok(dokumen_asli), start=1):
        print(f"  {indeks}: {blok!r}")

    print("\nBlok cipherteks ECB:")
    for indeks, blok in enumerate(bagi_blok(cipherteks), start=1):
        print(f"  {indeks}: {blok.hex()}")

    hasil = dekripsi_ecb(salt, cipherteks, passphrase)
    print(f"\nBerhasil dipulihkan: {hasil == dokumen_asli}")
    print("Empat blok cipherteks pertama identik: ", end="")
    print(len(set(bagi_blok(cipherteks)[:4])) == 1)