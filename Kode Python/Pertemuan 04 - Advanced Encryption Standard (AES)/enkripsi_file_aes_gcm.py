"""
Pertemuan 4 - Advanced Encryption Standard (AES)
Studi kasus nyata: mengenkripsi & mendekripsi "file" (di sini disimulasikan
dengan bytes di memori) menggunakan AES-256 dalam mode GCM (Galois/Counter
Mode) -- mode AEAD yang direkomendasikan NIST SP 800-38D, dipakai luas pada
TLS 1.3, penyimpanan cloud terenkripsi, dsb.

Kunci AES-256 diturunkan dari kata sandi (passphrase) pengguna dengan
PBKDF2-HMAC-SHA256 (NIST SP 800-132) -- BUKAN memakai passphrase langsung
sebagai kunci.

Instal dependensi:
    pip install pycryptodome
"""

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

ITERASI_KDF = 600_000  # rekomendasi OWASP (2023) untuk PBKDF2-HMAC-SHA256


def turunkan_kunci(passphrase: str, salt: bytes) -> bytes:
    """Menurunkan kunci AES-256 (32 byte) dari passphrase pengguna."""
    return PBKDF2(passphrase, salt, dkLen=32, count=ITERASI_KDF, hmac_hash_module=SHA256)


def enkripsi_file(data: bytes, passphrase: str) -> bytes:
    salt = get_random_bytes(16)
    nonce = get_random_bytes(12)  # 96-bit nonce, ukuran standar rekomendasi NIST SP 800-38D
    kunci = turunkan_kunci(passphrase, salt)

    cipher = AES.new(kunci, AES.MODE_GCM, nonce=nonce)
    cipherteks, tag = cipher.encrypt_and_digest(data)

    # Format arsip terenkripsi: salt || nonce || tag || cipherteks
    return salt + nonce + tag + cipherteks


def dekripsi_file(arsip_terenkripsi: bytes, passphrase: str) -> bytes:
    salt, nonce, tag, cipherteks = (
        arsip_terenkripsi[:16],
        arsip_terenkripsi[16:28],
        arsip_terenkripsi[28:44],
        arsip_terenkripsi[44:],
    )
    kunci = turunkan_kunci(passphrase, salt)

    cipher = AES.new(kunci, AES.MODE_GCM, nonce=nonce)
    # verify() akan melempar ValueError bila tag tidak cocok -> data dimanipulasi
    return cipher.decrypt_and_verify(cipherteks, tag)


if __name__ == "__main__":
    dokumen_asli = (
        b"LAPORAN KEUANGAN RAHASIA\n"
        b"Pendapatan Q3 2026: Rp 4.850.000.000\n"
        b"Proyeksi Q4 2026: Rp 5.200.000.000"
    )
    passphrase = "K@t4S4ndi-Kuat-2026!"

    print("=" * 60)
    print("ENKRIPSI FILE DENGAN AES-256-GCM")
    print("=" * 60)
    print(f"Dokumen asli ({len(dokumen_asli)} byte):\n{dokumen_asli.decode()}\n")

    arsip = enkripsi_file(dokumen_asli, passphrase)
    print(f"Arsip terenkripsi ({len(arsip)} byte, format salt|nonce|tag|cipherteks):")
    print(arsip.hex()[:80] + "...\n")

    print("=" * 60)
    print("DEKRIPSI DENGAN PASSPHRASE YANG BENAR")
    print("=" * 60)
    hasil = dekripsi_file(arsip, passphrase)
    print(f"Berhasil dipulihkan: {hasil == dokumen_asli}")
    print(hasil.decode())

    print()
    print("=" * 60)
    print("PERCOBAAN DEKRIPSI DENGAN PASSPHRASE SALAH")
    print("=" * 60)
    try:
        dekripsi_file(arsip, "passphrase-yang-salah")
    except ValueError as e:
        print(f"Ditolak sebagaimana mestinya -> ValueError: {e}")

    print()
    print("=" * 60)
    print("PERCOBAAN DEKRIPSI SETELAH CIPHERTEKS DIMANIPULASI (integritas GCM)")
    print("=" * 60)
    arsip_dimanipulasi = bytearray(arsip)
    arsip_dimanipulasi[-1] ^= 0x01  # ubah 1 bit terakhir cipherteks
    print(f"Arsip dimanipulasi ({len(arsip_dimanipulasi)} byte):")
    print(arsip_dimanipulasi.hex())  
    
    try:
        dekripsi_file(bytes(arsip_dimanipulasi), passphrase)
    except ValueError as e:
        print(f"Ditolak sebagaimana mestinya -> ValueError: {e}")
