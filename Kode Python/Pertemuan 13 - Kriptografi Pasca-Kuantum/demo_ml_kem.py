"""
Pertemuan 13 - Kriptografi Pasca-Kuantum & Tren Keamanan Siber Masa Depan
Demo NYATA algoritma ML-KEM-768 (Module-Lattice-Based Key-Encapsulation
Mechanism) -- distandarkan resmi NIST sebagai FIPS 203 pada Agustus 2024.
Sebelumnya dikenal dengan nama CRYSTALS-Kyber.

ML-KEM menggantikan peran Diffie-Hellman/ECDH (Pertemuan 5 & 6) untuk
menyepakati kunci rahasia bersama -- namun keamanannya berbasis masalah
kisi (lattice problem), yang diyakini TAHAN terhadap komputer kuantum,
berbeda dengan DH/RSA/ECC yang rentan terhadap algoritma Shor.

Instal dependensi:
    pip install kyber-py
"""

from kyber_py.ml_kem import ML_KEM_512, ML_KEM_768, ML_KEM_1024


def jalankan_pertukaran_kunci(skema, nama: str):
    ek, dk = skema.keygen()  # ek = encapsulation key (publik), dk = decapsulation key (privat)
    kunci_bersama_pengirim, cipherteks = skema.encaps(ek)
    kunci_bersama_penerima = skema.decaps(dk, cipherteks)

    print(f"\n--- {nama} ---")
    print(f"Ukuran kunci publik (ek)   : {len(ek)} byte")
    print(f"Ukuran kunci privat (dk)   : {len(dk)} byte")
    print(f"Ukuran ciphertext (encaps) : {len(cipherteks)} byte")
    print(f"Ukuran kunci rahasia hasil : {len(kunci_bersama_pengirim)} byte")
    print(f"Kedua pihak sepakat?       : {kunci_bersama_pengirim == kunci_bersama_penerima}")
    return len(ek)


if __name__ == "__main__":
    print("=" * 65)
    print("ML-KEM (FIPS 203, Agustus 2024) -- STANDAR RESMI PERTUKARAN KUNCI")
    print("PASCA-KUANTUM PERTAMA DARI NIST")
    print("=" * 65)

    jalankan_pertukaran_kunci(ML_KEM_512, "ML-KEM-512 (setara AES-128)")
    ukuran_768 = jalankan_pertukaran_kunci(ML_KEM_768, "ML-KEM-768 (setara AES-192, direkomendasikan umum)")
    jalankan_pertukaran_kunci(ML_KEM_1024, "ML-KEM-1024 (setara AES-256)")

    print()
    print("=" * 65)
    print("PERBANDINGAN DENGAN SKEMA KLASIK (Pertemuan 5 & 6)")
    print("=" * 65)
    perbandingan = [
        ("ECDH P-256 (klasik)", 65, "RENTAN terhadap algoritma Shor pada komputer kuantum"),
        ("ML-KEM-768 (pasca-kuantum)", ukuran_768, "Diyakini TAHAN terhadap komputer kuantum (berbasis lattice)"),
    ]
    for nama, ukuran, catatan in perbandingan:
        print(f"{nama:<28} : kunci publik {ukuran:>5} byte -- {catatan}")

    print()
    print(">> Kunci ML-KEM jauh LEBIH BESAR daripada ECDH -- inilah salah satu")
    print(">> tantangan migrasi pasca-kuantum: trade-off ukuran data vs keamanan")
    print(">> jangka panjang terhadap ancaman komputer kuantum.")
