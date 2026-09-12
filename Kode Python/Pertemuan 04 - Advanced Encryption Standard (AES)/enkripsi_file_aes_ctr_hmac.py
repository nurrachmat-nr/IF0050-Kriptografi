"""
Pertemuan 4 - Advanced Encryption Standard (AES)
Contoh AES-256-CTR dengan pola Encrypt-then-MAC memakai HMAC-SHA256.

HMAC memverifikasi salt, nonce, dan cipherteks SEBELUM dekripsi dilakukan.
Kunci AES dan kunci HMAC dipisahkan agar tidak memakai satu kunci untuk
dua fungsi kriptografi yang berbeda.

Instal dependensi:
    pip install pycryptodome
"""

from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

ITERASI_KDF = 600_000
PANJANG_SALT = 16
PANJANG_NONCE = 8
PANJANG_TAG = 32


def turunkan_kunci(passphrase: str, salt: bytes) -> tuple[bytes, bytes]:
    """Menurunkan kunci AES-256 dan kunci HMAC-SHA256 yang terpisah."""
    material_kunci = PBKDF2(
        passphrase, salt, dkLen=64, count=ITERASI_KDF, hmac_hash_module=SHA256
    )
    return material_kunci[:32], material_kunci[32:]


def buat_tag(kunci_hmac: bytes, data: bytes) -> bytes:
    """Menghasilkan tag HMAC-SHA256 untuk data yang akan disimpan."""
    return HMAC.new(kunci_hmac, data, digestmod=SHA256).digest()


def enkripsi_file(data: bytes, passphrase: str) -> bytes:
    salt = get_random_bytes(PANJANG_SALT)
    nonce = get_random_bytes(PANJANG_NONCE)
    kunci_aes, kunci_hmac = turunkan_kunci(passphrase, salt)

    cipher = AES.new(kunci_aes, AES.MODE_CTR, nonce=nonce)
    cipherteks = cipher.encrypt(data)
    data_terautentikasi = salt + nonce + cipherteks
    tag = buat_tag(kunci_hmac, data_terautentikasi)

    # Format arsip: salt || nonce || cipherteks || tag HMAC
    return data_terautentikasi + tag


def dekripsi_file(arsip_terenkripsi: bytes, passphrase: str) -> bytes:
    ukuran_minimum = PANJANG_SALT + PANJANG_NONCE + PANJANG_TAG
    if len(arsip_terenkripsi) < ukuran_minimum:
        raise ValueError("Format arsip CTR-HMAC tidak valid.")

    data_terautentikasi = arsip_terenkripsi[:-PANJANG_TAG]
    tag = arsip_terenkripsi[-PANJANG_TAG:]
    salt = data_terautentikasi[:PANJANG_SALT]
    nonce = data_terautentikasi[PANJANG_SALT : PANJANG_SALT + PANJANG_NONCE]
    cipherteks = data_terautentikasi[PANJANG_SALT + PANJANG_NONCE :]
    kunci_aes, kunci_hmac = turunkan_kunci(passphrase, salt)

    try:
        HMAC.new(kunci_hmac, data_terautentikasi, digestmod=SHA256).verify(tag)
    except ValueError as error:
        raise ValueError("Autentikasi HMAC gagal: arsip atau passphrase salah.") from error

    cipher = AES.new(kunci_aes, AES.MODE_CTR, nonce=nonce)
    return cipher.decrypt(cipherteks)


if __name__ == "__main__":
    dokumen_asli = b"Data CTR dapat memiliki panjang berapa pun."
    passphrase = "K@t4S4ndi-Kuat-2026!"

    print("=" * 60)
    print("ENKRIPSI FILE DENGAN AES-256-CTR + HMAC-SHA256")
    print("=" * 60)
    arsip = enkripsi_file(dokumen_asli, passphrase)
    print(f"Arsip terenkripsi: {arsip.hex()[:80]}...")
    hasil = dekripsi_file(arsip, passphrase)
    print(f"Berhasil dipulihkan: {hasil == dokumen_asli}")

    print("\nPERCOBAAN SETELAH CIPHERTEKS DIMANIPULASI")
    arsip_dimanipulasi = bytearray(arsip)
    arsip_dimanipulasi[PANJANG_SALT + PANJANG_NONCE] ^= 0x01
    try:
        dekripsi_file(bytes(arsip_dimanipulasi), passphrase)
    except ValueError as error:
        print(f"Ditolak sebelum dekripsi -> ValueError: {error}")