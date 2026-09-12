"""
Pertemuan 6 - Kriptografi Kunci-Publik: RSA & Elliptic Curve Cryptography
RSA versi PRAKTIK (aman dipakai): kunci 2048-bit + skema padding OAEP untuk
enkripsi dan PSS untuk tanda tangan digital -- sesuai rekomendasi NIST SP 800-56B
dan PKCS#1 v2.2 (RFC 8017).

Instal dependensi:
    pip install pycryptodome
"""

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pss
from Crypto.Hash import SHA256


def buat_pasangan_kunci(ukuran_bit: int = 2048):
    return RSA.generate(ukuran_bit)


def enkripsi_oaep(pesan: bytes, kunci_publik) -> bytes:
    cipher = PKCS1_OAEP.new(kunci_publik, hashAlgo=SHA256)
    return cipher.encrypt(pesan)


def dekripsi_oaep(cipherteks: bytes, kunci_privat) -> bytes:
    cipher = PKCS1_OAEP.new(kunci_privat, hashAlgo=SHA256)
    return cipher.decrypt(cipherteks)


def tanda_tangan_pss(pesan: bytes, kunci_privat) -> bytes:
    h = SHA256.new(pesan)
    return pss.new(kunci_privat).sign(h)


def verifikasi_pss(pesan: bytes, tanda_tangan: bytes, kunci_publik) -> bool:
    h = SHA256.new(pesan)
    try:
        pss.new(kunci_publik).verify(h, tanda_tangan)
        return True
    except (ValueError, TypeError):
        return False


if __name__ == "__main__":
    print("=" * 65)
    print("MEMBANGKITKAN PASANGAN KUNCI RSA-2048")
    print("=" * 65)
    kunci_bob = buat_pasangan_kunci(2048)
    print(f"Ukuran kunci      : {kunci_bob.size_in_bits()} bit")
    print(f"Kunci publik Bob  : {kunci_bob.publickey().export_key()[:60].decode()}...")

    print()
    print("=" * 65)
    print("ENKRIPSI DENGAN OAEP PADDING (Alice -> Bob)")
    print("=" * 65)
    pesan = b"Kunci sesi AES: 7f3a9c2e8b1d4f60"
    cipherteks_1 = enkripsi_oaep(pesan, kunci_bob.publickey())
    cipherteks_2 = enkripsi_oaep(pesan, kunci_bob.publickey())
    print(f"Pesan asli        : {pesan.decode()}")
    print(f"Cipherteks #1 (60 byte pertama, hex): {cipherteks_1.hex()[:60]}...")
    print(f"Cipherteks #2 (60 byte pertama, hex): {cipherteks_2.hex()[:60]}...")
    print(f"Kedua cipherteks identik? {cipherteks_1 == cipherteks_2}  <- OAEP bersifat probabilistik (acak)")

    hasil = dekripsi_oaep(cipherteks_1, kunci_bob)
    print(f"\nBob mendekripsi   : {hasil.decode()}")
    print(f"Berhasil dipulihkan? {hasil == pesan}")

    print()
    print("=" * 65)
    print("TANDA TANGAN DIGITAL DENGAN PSS (Bob menandatangani pesan)")
    print("=" * 65)
    dokumen = b"Saya menyetujui transfer dana sebesar Rp 50.000.000"
    signature = tanda_tangan_pss(dokumen, kunci_bob)
    print(f"Dokumen           : {dokumen.decode()}")
    print(f"Tanda tangan (hex): {signature.hex()[:60]}...")

    print(f"\nVerifikasi dengan kunci publik Bob (dokumen ASLI)   : "
          f"{verifikasi_pss(dokumen, signature, kunci_bob.publickey())}")
    dokumen_diubah = b"Saya menyetujui transfer dana sebesar Rp 99.999.999"
    print(f"Verifikasi dengan kunci publik Bob (dokumen DIUBAH) : "
          f"{verifikasi_pss(dokumen_diubah, signature, kunci_bob.publickey())}")
