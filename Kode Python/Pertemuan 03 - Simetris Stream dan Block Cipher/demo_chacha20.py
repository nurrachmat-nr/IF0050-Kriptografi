"""
Pertemuan 3 - Kriptografi Simetris: Stream & Block Cipher
Demo ChaCha20, stream cipher modern rancangan Daniel J. Bernstein.

ChaCha20 tidak memberi integritas sendiri. Untuk aplikasi nyata gunakan
ChaCha20-Poly1305, yaitu mode AEAD yang juga menyertakan autentikasi.

Instal dependensi:
    pip install pycryptodome
"""

from Crypto.Cipher import ChaCha20
from Crypto.Random import get_random_bytes

PANJANG_KUNCI = 32
PANJANG_NONCE = 12


def enkripsi_chacha20(plainteks: bytes, kunci: bytes) -> tuple[bytes, bytes]:
    """Mengenkripsi plaintext dan mengembalikan nonce beserta cipherteks."""
    nonce = get_random_bytes(PANJANG_NONCE)
    cipher = ChaCha20.new(key=kunci, nonce=nonce)
    return nonce, cipher.encrypt(plainteks)


def dekripsi_chacha20(cipherteks: bytes, kunci: bytes, nonce: bytes) -> bytes:
    """Mendekripsi cipherteks dengan kunci dan nonce asli."""
    cipher = ChaCha20.new(key=kunci, nonce=nonce)
    return cipher.decrypt(cipherteks)


if __name__ == "__main__":
    plainteks = b"Pesan rahasia untuk demonstrasi ChaCha20."
    kunci = get_random_bytes(PANJANG_KUNCI)

    print("=" * 65)
    print("DEMONSTRASI CHACHA20")
    print("=" * 65)
    nonce, cipherteks = enkripsi_chacha20(plainteks, kunci)
    hasil_dekripsi = dekripsi_chacha20(cipherteks, kunci, nonce)

    print(f"Plainteks : {plainteks.decode()}")
    print(f"Nonce     : {nonce.hex()}")
    print(f"Cipherteks: {cipherteks.hex()}")
    print(f"Dekripsi berhasil? {hasil_dekripsi == plainteks}")
    print("Nonce tidak rahasia, tetapi tidak boleh dipakai ulang dengan kunci sama.")