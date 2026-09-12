"""
Pertemuan 3 - Kriptografi Simetris: Stream & Block Cipher
Demo DES (Data Encryption Standard) dalam mode CBC.

DES memiliki kunci efektif 56-bit dan sudah dapat dipecahkan dengan brute
force. File ini hanya untuk pembelajaran; gunakan AES untuk sistem nyata.

Instal dependensi:
    pip install pycryptodome
"""

from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

PANJANG_KUNCI = 8
PANJANG_IV = DES.block_size


def enkripsi_des(plainteks: bytes, kunci: bytes) -> tuple[bytes, bytes]:
    """Mengenkripsi plainteks DES-CBC dan mengembalikan IV serta cipherteks."""
    iv = get_random_bytes(PANJANG_IV)
    cipher = DES.new(kunci, DES.MODE_CBC, iv=iv)
    return iv, cipher.encrypt(pad(plainteks, DES.block_size))


def dekripsi_des(cipherteks: bytes, kunci: bytes, iv: bytes) -> bytes:
    """Mendekripsi cipherteks DES-CBC dan menghapus padding."""
    cipher = DES.new(kunci, DES.MODE_CBC, iv=iv)
    return unpad(cipher.decrypt(cipherteks), DES.block_size)


if __name__ == "__main__":
    plainteks = b"Contoh block cipher DES dalam mode CBC."
    kunci = get_random_bytes(PANJANG_KUNCI)

    print("=" * 65)
    print("DEMONSTRASI DES-CBC - HISTORIS, JANGAN DIGUNAKAN DI PRODUKSI")
    print("=" * 65)
    iv, cipherteks = enkripsi_des(plainteks, kunci)
    hasil_dekripsi = dekripsi_des(cipherteks, kunci, iv)

    print(f"Plainteks : {plainteks.decode()}")
    print(f"Kunci     : {kunci.hex()} ({len(kunci) * 8} bit)")
    print(f"IV        : {iv.hex()}")
    print(f"Cipherteks: {cipherteks.hex()}")
    print(f"Dekripsi berhasil? {hasil_dekripsi == plainteks}")
    print("DES tidak aman karena panjang kunci efektifnya hanya 56 bit.")