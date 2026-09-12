"""
Pertemuan 3 - Kriptografi Simetris: Stream & Block Cipher
Demo: mengapa mode operasi ECB (Electronic Codebook) BERBAHAYA
dibandingkan CBC (Cipher Block Chaining), menggunakan AES-128.

Instal dependensi:
    pip install pycryptodome
"""

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes


def enkripsi_ecb(plainteks: bytes, kunci: bytes) -> bytes:
    cipher = AES.new(kunci, AES.MODE_ECB)
    return cipher.encrypt(pad(plainteks, AES.block_size))


def enkripsi_cbc(plainteks: bytes, kunci: bytes, iv: bytes) -> bytes:
    cipher = AES.new(kunci, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(plainteks, AES.block_size))


def dekripsi_cbc(cipherteks: bytes, kunci: bytes, iv: bytes) -> bytes:
    cipher = AES.new(kunci, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(cipherteks), AES.block_size)


def tampilkan_per_blok(nama: str, data: bytes, ukuran_blok: int = 16) -> None:
    blok = [data[i:i + ukuran_blok].hex() for i in range(0, len(data), ukuran_blok)]
    print(f"{nama}:")
    for i, b in enumerate(blok):
        tanda = "  <-- identik dengan blok lain!" if blok.count(b) > 1 else ""
        print(f"  Blok {i + 1}: {b}{tanda}")


if __name__ == "__main__":
    kunci = get_random_bytes(16)   # AES-128
    iv = get_random_bytes(16)

    # Plainteks SENGAJA berisi blok 16-byte yang berulang, meniru pola
    # berulang pada data nyata (mis. area kosong pada gambar bitmap).
    blok_berulang = b"SERANGAN=BERULANG"[:16]
    plainteks = blok_berulang * 4  # 4 blok identik, total 64 byte

    print("=" * 65)
    print("PLAINTEKS (4 blok 16-byte yang identik)")
    print("=" * 65)
    tampilkan_per_blok("Plainteks", plainteks)

    print()
    print("=" * 65)
    print("MODE ECB -- setiap blok dienkripsi independen")
    print("=" * 65)
    cipherteks_ecb = enkripsi_ecb(plainteks, kunci)
    tampilkan_per_blok("Cipherteks (ECB)", cipherteks_ecb)
    print("\n>> Pola plainteks yang berulang TERLIHAT pada cipherteks!")
    print(">> Ini sebabnya ECB tidak boleh dipakai untuk data nyata (\"ECB penguin problem\").")

    print()
    print("=" * 65)
    print("MODE CBC -- setiap blok di-XOR dengan cipherteks blok sebelumnya")
    print("=" * 65)
    cipherteks_cbc = enkripsi_cbc(plainteks, kunci, iv)
    tampilkan_per_blok("Cipherteks (CBC)", cipherteks_cbc)
    print("\n>> Meskipun plainteks-nya identik, seluruh blok cipherteks CBC berbeda.")

    # Pembuktian dekripsi CBC berhasil mengembalikan plainteks semula
    hasil_dekripsi = dekripsi_cbc(cipherteks_cbc, kunci, iv)
    print(f"\nDekripsi CBC berhasil? {hasil_dekripsi == plainteks}")
