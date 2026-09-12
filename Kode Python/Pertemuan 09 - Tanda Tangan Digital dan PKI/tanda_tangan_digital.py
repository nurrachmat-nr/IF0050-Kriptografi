"""
Pertemuan 9 - Tanda Tangan Digital & Public Key Infrastructure (PKI)
Alur lengkap tanda tangan digital: hash pesan -> enkripsi hash dengan
kunci PRIVAT pengirim (signing) -> verifikasi dengan kunci PUBLIK
pengirim (verification).

Instal dependensi:
    pip install pycryptodome
"""

from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Hash import SHA256


def tandatangani(dokumen: bytes, kunci_privat_pengirim) -> bytes:
    """Signing: S = Enkripsi_privat( Hash(dokumen) )"""
    h = SHA256.new(dokumen)
    return pss.new(kunci_privat_pengirim).sign(h)


def verifikasi(dokumen: bytes, signature: bytes, kunci_publik_pengirim) -> bool:
    """Verification: bandingkan hash dokumen dengan hasil dekripsi signature."""
    h = SHA256.new(dokumen)
    try:
        pss.new(kunci_publik_pengirim).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False


if __name__ == "__main__":
    print("=" * 65)
    print("SIMULASI: BOB MENANDATANGANI DOKUMEN UNTUK ALICE")
    print("=" * 65)
    kunci_bob = RSA.generate(2048)  # Bob memiliki pasangan kunci privat & publik

    dokumen = (
        b"Memorandum Kesepahaman antara PT Solusi Express dan Universitas MDP\n"
        b"Tanggal: 10 September 2026\n"
        b"Nilai kontrak: Rp 250.000.000"
    )

    # --- Bob menandatangani dengan KUNCI PRIVATnya ---
    signature = tandatangani(dokumen, kunci_bob)
    print(f"Dokumen         : {dokumen.decode()!r}")
    print(f"Tanda tangan (60 byte pertama, hex): {signature.hex()[:60]}...")
    print(f"Ukuran tanda tangan: {len(signature)} byte")

    # --- Alice memverifikasi dengan KUNCI PUBLIK Bob ---
    print()
    print("=" * 65)
    print("ALICE MEMVERIFIKASI TANDA TANGAN DENGAN KUNCI PUBLIK BOB")
    print("=" * 65)
    valid = verifikasi(dokumen, signature, kunci_bob.publickey())
    print(f"Dokumen tidak berubah -> valid? {valid}")

    print()
    print("=" * 65)
    print("SKENARIO SERANGAN: DOKUMEN DIUBAH SETELAH DITANDATANGANI")
    print("=" * 65)
    dokumen_dipalsukan = dokumen.replace(b"250.000.000", b"999.999.999")
    valid_palsu = verifikasi(dokumen_dipalsukan, signature, kunci_bob.publickey())
    print(f"Dokumen yang sudah diubah nilainya -> valid? {valid_palsu}")
    print(">> Perubahan SEKECIL APAPUN pada dokumen membuat verifikasi GAGAL,")
    print(">> membuktikan tanda tangan digital menjamin integritas SEKALIGUS")
    print(">> autentikasi pengirim (hanya Bob yang punya kunci privatnya).")

    print()
    print("=" * 65)
    print("SKENARIO SERANGAN: PENYERANG MENGAKU SEBAGAI BOB")
    print("=" * 65)
    kunci_penyerang = RSA.generate(2048)  # penyerang punya kunci sendiri, BUKAN kunci privat Bob
    signature_palsu = tandatangani(dokumen, kunci_penyerang)
    valid_penyerang = verifikasi(dokumen, signature_palsu, kunci_bob.publickey())
    print(f"Tanda tangan dari penyerang, diverifikasi dengan kunci publik Bob -> valid? {valid_penyerang}")
    print(">> Verifikasi GAGAL karena penyerang tidak memiliki kunci PRIVAT Bob.")
