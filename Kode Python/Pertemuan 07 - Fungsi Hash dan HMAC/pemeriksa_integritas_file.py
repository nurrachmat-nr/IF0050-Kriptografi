"""
Pertemuan 7 - Fungsi Hash & Integritas Data (SHA-2/SHA-3, HMAC)
Studi kasus nyata: pemeriksa integritas file (mirip file checksum yang
disertakan pada unduhan software) menggunakan SHA-256 dan SHA3-256.

Juga mendemonstrasikan properti AVALANCHE EFFECT: perubahan sekecil apa
pun pada input (bahkan 1 karakter) menghasilkan nilai hash yang berbeda
secara drastis dan tidak dapat diprediksi.
"""

import hashlib


def hitung_hash(data: bytes, algoritma: str = "sha256") -> str:
    h = hashlib.new(algoritma)
    h.update(data)
    return h.hexdigest()


def verifikasi_integritas(data: bytes, hash_rujukan: str, algoritma: str = "sha256") -> bool:
    return hitung_hash(data, algoritma) == hash_rujukan


def hitung_persentase_bit_berbeda(hash1: str, hash2: str) -> float:
    """Menghitung berapa persen bit yang berbeda antara dua nilai hash (hex)."""
    b1 = bin(int(hash1, 16))[2:].zfill(len(hash1) * 4)
    b2 = bin(int(hash2, 16))[2:].zfill(len(hash2) * 4)
    berbeda = sum(c1 != c2 for c1, c2 in zip(b1, b2))
    return berbeda / len(b1) * 100


if __name__ == "__main__":
    dokumen_asli = b"Installer-Aplikasi-v2.5.0.exe (simulasi konten biner file)"

    print("=" * 65)
    print("PEMERIKSA INTEGRITAS FILE (mis. verifikasi hasil unduhan)")
    print("=" * 65)
    hash_sha256 = hitung_hash(dokumen_asli, "sha256")
    hash_sha3 = hitung_hash(dokumen_asli, "sha3_256")
    print(f"File asli    : {dokumen_asli.decode()}")
    print(f"SHA-256      : {hash_sha256}")
    print(f"SHA3-256     : {hash_sha3}")

    print("\n--- Skenario: pengguna mengunduh file, lalu memverifikasi ---")
    file_diterima_utuh = dokumen_asli
    file_diterima_rusak = dokumen_asli[:-1] + b"X"  # 1 byte terakhir berubah (mis. korup saat transfer)

    print(f"File diterima UTUH   -> valid? {verifikasi_integritas(file_diterima_utuh, hash_sha256)}")
    print(f"File diterima RUSAK  -> valid? {verifikasi_integritas(file_diterima_rusak, hash_sha256)}")

    print()
    print("=" * 65)
    print("AVALANCHE EFFECT: PERUBAHAN 1 KARAKTER -> HASH BERUBAH DRASTIS")
    print("=" * 65)
    pesan_a = "Transfer Rp 1.000.000 ke rekening 1234567890"
    pesan_b = "Transfer Rp 1.000.000 ke rekening 1234567891"  # hanya digit terakhir berbeda

    hash_a = hitung_hash(pesan_a.encode(), "sha256")
    hash_b = hitung_hash(pesan_b.encode(), "sha256")
    persen_beda = hitung_persentase_bit_berbeda(hash_a, hash_b)

    print(f"Pesan A : {pesan_a}")
    print(f"Hash A  : {hash_a}")
    print(f"Pesan B : {pesan_b}  (hanya 1 digit berbeda)")
    print(f"Hash B  : {hash_b}")
    print(f"\nPersentase bit yang berbeda antara Hash A dan Hash B: {persen_beda:.1f}%")
    print("(Idealnya mendekati 50% -- inilah avalanche effect yang menjamin")
    print(" fungsi hash sangat peka terhadap perubahan sekecil apa pun.)")
