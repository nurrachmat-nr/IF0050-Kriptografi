"""
Pertemuan 4 - Advanced Encryption Standard (AES)
Contoh AES-256-EAX, mode AEAD yang menyediakan kerahasiaan dan integritas.

EAX menghasilkan authentication tag. Dekripsi akan gagal jika passphrase salah
atau arsip terenkripsi telah dimanipulasi.

Instal dependensi:
    pip install pycryptodome
"""

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

ITERASI_KDF = 600_000
PANJANG_SALT = 16
PANJANG_NONCE = 16
PANJANG_TAG = 16


def turunkan_kunci(passphrase: str, salt: bytes) -> bytes:
    """Menurunkan kunci AES-256 (32 byte) dari passphrase pengguna."""
    return PBKDF2(passphrase, salt, dkLen=32, count=ITERASI_KDF, hmac_hash_module=SHA256)


def enkripsi_file(data: bytes, passphrase: str) -> bytes:
    salt = get_random_bytes(PANJANG_SALT)
    nonce = get_random_bytes(PANJANG_NONCE)
    kunci = turunkan_kunci(passphrase, salt)

    cipher = AES.new(kunci, AES.MODE_EAX, nonce=nonce)
    cipherteks, tag = cipher.encrypt_and_digest(data)

    # Format arsip: salt || nonce || tag || cipherteks
    return salt + nonce + tag + cipherteks


def dekripsi_file(arsip_terenkripsi: bytes, passphrase: str) -> bytes:
    ukuran_minimum = PANJANG_SALT + PANJANG_NONCE + PANJANG_TAG
    if len(arsip_terenkripsi) < ukuran_minimum:
        raise ValueError("Format arsip EAX tidak valid.")

    salt = arsip_terenkripsi[:PANJANG_SALT]
    awal_tag = PANJANG_SALT + PANJANG_NONCE
    nonce = arsip_terenkripsi[PANJANG_SALT:awal_tag]
    tag = arsip_terenkripsi[awal_tag : awal_tag + PANJANG_TAG]
    cipherteks = arsip_terenkripsi[awal_tag + PANJANG_TAG :]
    kunci = turunkan_kunci(passphrase, salt)

    cipher = AES.new(kunci, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(cipherteks, tag)


if __name__ == "__main__":
    dokumen_asli = b"Dokumen rahasia dengan perlindungan AEAD."
    passphrase = "K@t4S4ndi-Kuat-2026!"

    print("=" * 60)
    print("ENKRIPSI FILE DENGAN AES-256-EAX")
    print("=" * 60)
    arsip = enkripsi_file(dokumen_asli, passphrase)
    print(f"Arsip terenkripsi: {arsip.hex()[:80]}...")

    hasil = dekripsi_file(arsip, passphrase)
    print(f"Berhasil dipulihkan: {hasil == dokumen_asli}")

    print("\nPERCOBAAN SETELAH CIPHERTEKS DIMANIPULASI")
    arsip_dimanipulasi = bytearray(arsip)
    arsip_dimanipulasi[-1] ^= 0x01
    try:
        dekripsi_file(bytes(arsip_dimanipulasi), passphrase)
    except ValueError as error:
        print(f"Ditolak sebagaimana mestinya -> ValueError: {error}")