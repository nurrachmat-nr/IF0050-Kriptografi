"""
Pertemuan 3 - Kriptografi Simetris: Stream & Block Cipher
Demo Blowfish dalam mode CBC.

Blowfish mendukung kunci 32 hingga 448 bit. Namun ukuran bloknya hanya 64 bit,
sehingga AES lebih direkomendasikan untuk sistem baru.

Instal dependensi:
    pip install pycryptodome
"""

from Crypto.Cipher import Blowfish
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

PANJANG_KUNCI = 32
PANJANG_IV = Blowfish.block_size


def enkripsi_blowfish(plainteks: bytes, kunci: bytes) -> tuple[bytes, bytes]:
    """Mengenkripsi plainteks Blowfish-CBC dan mengembalikan IV serta cipherteks."""
    iv = get_random_bytes(PANJANG_IV)
    cipher = Blowfish.new(kunci, Blowfish.MODE_CBC, iv=iv)
    return iv, cipher.encrypt(pad(plainteks, Blowfish.block_size))


def dekripsi_blowfish(cipherteks: bytes, kunci: bytes, iv: bytes) -> bytes:
    """Mendekripsi cipherteks Blowfish-CBC dan menghapus padding."""
    cipher = Blowfish.new(kunci, Blowfish.MODE_CBC, iv=iv)
    return unpad(cipher.decrypt(cipherteks), Blowfish.block_size)


if __name__ == "__main__":
    plainteks = b"Contoh block cipher Blowfish dalam mode CBC."
    kunci = get_random_bytes(PANJANG_KUNCI)

    print("=" * 65)
    print("DEMONSTRASI BLOWFISH-CBC")
    print("=" * 65)
    iv, cipherteks = enkripsi_blowfish(plainteks, kunci)
    hasil_dekripsi = dekripsi_blowfish(cipherteks, kunci, iv)

    print(f"Plainteks : {plainteks.decode()}")
    print(f"Kunci     : {kunci.hex()} ({len(kunci) * 8} bit)")
    print(f"IV        : {iv.hex()}")
    print(f"Cipherteks: {cipherteks.hex()}")
    print(f"Dekripsi berhasil? {hasil_dekripsi == plainteks}")
    print("Blowfish adalah algoritma lama; AES lebih sesuai untuk aplikasi baru.")