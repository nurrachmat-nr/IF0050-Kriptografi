"""
Pertemuan 1 - Pengantar Kriptografi & Lanskap Keamanan Siber
Demo: mengilustrasikan dua layanan dasar kriptografi secara praktis.

1) INTEGRITY  (integritas data)   -> fungsi hash SHA-256 (modul hashlib, bawaan Python)
2) CONFIDENTIALITY (kerahasiaan)  -> enkripsi simetris Fernet (paket 'cryptography')

Catatan: modul 'cryptography' bukan bawaan Python. Instal dengan:
    pip install cryptography
Kita SENGAJA memakai pustaka kriptografi yang sudah teruji (bukan menulis
algoritma sendiri) -- ini adalah praktik terbaik: "don't roll your own crypto".
"""

import hashlib
from cryptography.fernet import Fernet


def bagian_1_integritas():
    print("=" * 60)
    print("BAGIAN 1: INTEGRITAS DATA DENGAN FUNGSI HASH (SHA-256)")
    print("=" * 60)

    pesan_asli = b"Transfer Rp 1.000.000 ke rekening 1234567890"
    pesan_diubah = b"Transfer Rp 9.000.000 ke rekening 1234567890"

    hash_asli = hashlib.sha256(pesan_asli).hexdigest()
    hash_diubah = hashlib.sha256(pesan_diubah).hexdigest()

    print(f"Pesan asli   : {pesan_asli.decode()}")
    print(f"SHA-256      : {hash_asli}")
    print()
    print(f"Pesan diubah : {pesan_diubah.decode()}")
    print(f"SHA-256      : {hash_diubah}")
    print()

    if hash_asli == hash_diubah:
        print("Hasil hash SAMA -> pesan diyakini utuh (tidak berubah).")
    else:
        print("Hasil hash BERBEDA -> pesan telah dimanipulasi (integritas gagal)!")
    print()


def bagian_2_kerahasiaan():
    print("=" * 60)
    print("BAGIAN 2: KERAHASIAAN DENGAN ENKRIPSI SIMETRIS (Fernet/AES)")
    print("=" * 60)

    # Kunci rahasia dibangkitkan sekali, lalu disimpan aman oleh pengirim & penerima
    kunci = Fernet.generate_key()
    f = Fernet(kunci)

    plainteks = b"Nomor kartu: 4532-1111-2222-3333"
    cipherteks = f.encrypt(plainteks)

    print(f"Kunci (K)    : {kunci.decode()}")
    print(f"Plainteks    : {plainteks.decode()}")
    print(f"Cipherteks   : {cipherteks.decode()[:60]}...")

    # Eve menyadap cipherteks tetapi tidak memiliki kunci -> tidak bisa membaca isi pesan
    hasil_dekripsi = f.decrypt(cipherteks)
    print(f"Dekripsi (Bob, punya K): {hasil_dekripsi.decode()}")
    print()


if __name__ == "__main__":
    bagian_1_integritas()
    bagian_2_kerahasiaan()
