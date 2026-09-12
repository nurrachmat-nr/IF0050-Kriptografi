"""
Pertemuan 3 - Kriptografi Simetris: Stream & Block Cipher
Demo 3DES (Triple DES) dalam mode CBC.

3DES menerapkan DES tiga kali. Walaupun lebih kuat daripada DES, 3DES sudah
usang dan lambat; gunakan AES untuk sistem nyata.

Instal dependensi:
    pip install pycryptodome
"""

from Crypto.Cipher import DES3
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

PANJANG_KUNCI = 24
PANJANG_IV = DES3.block_size


def bangkitkan_kunci_3des() -> bytes:
    """Membuat kunci 3DES tiga-kunci dengan bit paritas yang benar."""
    while True:
        try:
            return DES3.adjust_key_parity(get_random_bytes(PANJANG_KUNCI))
        except ValueError:
            pass


def enkripsi_3des(plainteks: bytes, kunci: bytes) -> tuple[bytes, bytes]:
    """Mengenkripsi plainteks 3DES-CBC dan mengembalikan IV serta cipherteks."""
    iv = get_random_bytes(PANJANG_IV)
    cipher = DES3.new(kunci, DES3.MODE_CBC, iv=iv)
    return iv, cipher.encrypt(pad(plainteks, DES3.block_size))


def dekripsi_3des(cipherteks: bytes, kunci: bytes, iv: bytes) -> bytes:
    """Mendekripsi cipherteks 3DES-CBC dan menghapus padding."""
    cipher = DES3.new(kunci, DES3.MODE_CBC, iv=iv)
    return unpad(cipher.decrypt(cipherteks), DES3.block_size)


if __name__ == "__main__":
    plainteks = b"Contoh block cipher Triple DES dalam mode CBC."
    kunci = bangkitkan_kunci_3des()

    print("=" * 65)
    print("DEMONSTRASI 3DES-CBC - USANG, JANGAN DIGUNAKAN DI PRODUKSI")
    print("=" * 65)
    iv, cipherteks = enkripsi_3des(plainteks, kunci)
    hasil_dekripsi = dekripsi_3des(cipherteks, kunci, iv)

    print(f"Plainteks : {plainteks.decode()}")
    print(f"Kunci     : {kunci.hex()} ({len(kunci) * 8} bit termasuk paritas)")
    print(f"IV        : {iv.hex()}")
    print(f"Cipherteks: {cipherteks.hex()}")
    print(f"Dekripsi berhasil? {hasil_dekripsi == plainteks}")
    print("3DES memiliki blok 64-bit dan telah digantikan oleh AES.")