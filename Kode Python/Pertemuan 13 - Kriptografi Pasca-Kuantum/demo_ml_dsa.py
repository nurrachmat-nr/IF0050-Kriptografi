"""
Pertemuan 13 - Kriptografi Pasca-Kuantum & Tren Keamanan Siber Masa Depan
Demo NYATA algoritma ML-DSA-65 (Module-Lattice-Based Digital Signature
Algorithm) -- distandarkan resmi NIST sebagai FIPS 204 pada Agustus 2024.
Sebelumnya dikenal dengan nama CRYSTALS-Dilithium.

ML-DSA menggantikan peran RSA/ECDSA (Pertemuan 6 & 9) untuk tanda tangan
digital -- keamanannya berbasis masalah kisi (lattice), diyakini TAHAN
terhadap komputer kuantum.

Instal dependensi:
    pip install dilithium-py
"""

from dilithium_py.ml_dsa import ML_DSA_44, ML_DSA_65, ML_DSA_87


def jalankan_tanda_tangan(skema, nama: str, dokumen: bytes):
    pk, sk = skema.keygen()  # pk = kunci publik, sk = kunci privat
    tanda_tangan = skema.sign(sk, dokumen)

    valid_asli = skema.verify(pk, dokumen, tanda_tangan)
    valid_diubah = skema.verify(pk, dokumen.replace(b"250", b"999"), tanda_tangan)

    print(f"\n--- {nama} ---")
    print(f"Ukuran kunci publik   : {len(pk)} byte")
    print(f"Ukuran kunci privat   : {len(sk)} byte")
    print(f"Ukuran tanda tangan   : {len(tanda_tangan)} byte")
    print(f"Verifikasi (dokumen asli) : {valid_asli}")
    print(f"Verifikasi (dokumen diubah): {valid_diubah}")
    return len(tanda_tangan)


if __name__ == "__main__":
    dokumen = b"Kontrak kerja sama senilai Rp 250.000.000, berlaku hingga 2027"

    print("=" * 65)
    print("ML-DSA (FIPS 204, Agustus 2024) -- STANDAR RESMI TANDA TANGAN")
    print("DIGITAL PASCA-KUANTUM PERTAMA DARI NIST")
    print("=" * 65)

    jalankan_tanda_tangan(ML_DSA_44, "ML-DSA-44 (tingkat keamanan setara AES-128)", dokumen)
    ukuran_65 = jalankan_tanda_tangan(ML_DSA_65, "ML-DSA-65 (setara AES-192, direkomendasikan umum)", dokumen)
    jalankan_tanda_tangan(ML_DSA_87, "ML-DSA-87 (setara AES-256)", dokumen)

    print()
    print("=" * 65)
    print("PERBANDINGAN UKURAN TANDA TANGAN: KLASIK vs. PASCA-KUANTUM")
    print("=" * 65)
    perbandingan = [
        ("RSA-2048 (klasik)", 256, "Signing/verifying CEPAT, namun RENTAN algoritma Shor"),
        ("ECDSA P-256 (klasik)", 64, "Tanda tangan SANGAT RINGKAS, namun RENTAN algoritma Shor"),
        ("ML-DSA-65 (pasca-kuantum)", ukuran_65, "Diyakini TAHAN komputer kuantum, namun tanda tangan JAUH lebih besar"),
    ]
    for nama, ukuran, catatan in perbandingan:
        print(f"{nama:<28} : {ukuran:>5} byte -- {catatan}")

    print()
    print(">> Tanda tangan ML-DSA-65 lebih dari 50x lebih besar dibanding ECDSA --")
    print(">> inilah mengapa migrasi PQC memerlukan perencanaan matang, terutama")
    print(">> pada protokol dengan keterbatasan bandwidth (IoT, sistem tertanam).")
