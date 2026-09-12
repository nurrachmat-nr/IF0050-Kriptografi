"""
Pertemuan 6 - Kriptografi Kunci-Publik: RSA & Elliptic Curve Cryptography
Demo Elliptic Curve Cryptography (ECC): pembangkitan kunci, tanda tangan
digital ECDSA, serta perbandingan UKURAN KUNCI dengan RSA pada tingkat
keamanan yang setara (~128-bit security level).

Kurva yang dipakai: NIST P-256 (secp256r1) -- kurva standar yang dipakai
luas di TLS 1.3, Signal, dan banyak sistem modern lainnya.

Instal dependensi:
    pip install pycryptodome
"""

from Crypto.PublicKey import ECC, RSA
from Crypto.Signature import DSS
from Crypto.Hash import SHA256


def buat_pasangan_kunci_ecc(kurva: str = "P-256"):
    return ECC.generate(curve=kurva)


def tanda_tangan_ecdsa(pesan: bytes, kunci_privat) -> bytes:
    h = SHA256.new(pesan)
    return DSS.new(kunci_privat, "fips-186-3").sign(h)


def verifikasi_ecdsa(pesan: bytes, tanda_tangan: bytes, kunci_publik) -> bool:
    h = SHA256.new(pesan)
    try:
        DSS.new(kunci_publik, "fips-186-3").verify(h, tanda_tangan)
        return True
    except ValueError:
        return False


if __name__ == "__main__":
    print("=" * 65)
    print("PEMBANGKITAN KUNCI ECC (kurva P-256 / secp256r1)")
    print("=" * 65)
    kunci = buat_pasangan_kunci_ecc("P-256")
    titik_publik = kunci.public_key().pointQ
    print(f"Kunci privat (d)         : {hex(int(kunci.d))[:40]}...  (1 bilangan bulat, 256-bit)")
    print(f"Kunci publik (titik Q)   : x={hex(int(titik_publik.x))[:24]}...")
    print(f"                           y={hex(int(titik_publik.y))[:24]}...")

    print()
    print("=" * 65)
    print("TANDA TANGAN DIGITAL DENGAN ECDSA")
    print("=" * 65)
    dokumen = b"Kontrak digital No. 2026/VII/PKS-001 disetujui oleh Direktur"
    signature = tanda_tangan_ecdsa(dokumen, kunci)
    print(f"Dokumen        : {dokumen.decode()}")
    print(f"Tanda tangan   : {signature.hex()}")
    print(f"Ukuran tanda tangan: {len(signature)} byte")

    valid_asli = verifikasi_ecdsa(dokumen, signature, kunci.public_key())
    valid_diubah = verifikasi_ecdsa(dokumen.replace(b"disetujui", b"DITOLAK "), signature, kunci.public_key())
    print(f"\nVerifikasi (dokumen asli)  : {valid_asli}")
    print(f"Verifikasi (dokumen diubah): {valid_diubah}")

    print()
    print("=" * 65)
    print("PERBANDINGAN UKURAN KUNCI: RSA-2048 vs ECC P-256")
    print("=" * 65)
    print("(Keduanya diperkirakan setara ~112-128 bit tingkat keamanan)")
    kunci_rsa = RSA.generate(2048)
    ukuran_pub_rsa = len(kunci_rsa.publickey().export_key())
    ukuran_pub_ecc = len(kunci.public_key().export_key(format="DER"))
    print(f"Ukuran kunci publik RSA-2048 (format PEM/DER) : {ukuran_pub_rsa} byte")
    print(f"Ukuran kunci publik ECC P-256 (format DER)    : {ukuran_pub_ecc} byte")
    print(f"ECC lebih ringkas sekitar {ukuran_pub_rsa / ukuran_pub_ecc:.1f}x dibanding RSA-2048")
    print(">> Inilah alasan ECC lebih disukai pada perangkat terbatas sumber")
    print(">> daya (IoT, kartu pintar) dan protokol modern seperti TLS 1.3.")
