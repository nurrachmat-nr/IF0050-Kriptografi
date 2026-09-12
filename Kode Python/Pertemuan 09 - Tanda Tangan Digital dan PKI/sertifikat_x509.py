"""
Pertemuan 9 - Tanda Tangan Digital & Public Key Infrastructure (PKI)
Membuat & memverifikasi sertifikat digital X.509 sederhana menggunakan
pustaka 'cryptography' -- format sertifikat yang sama dipakai HTTPS/TLS.

Studi kasus ini mensimulasikan sebuah Certificate Authority (CA) yang
menerbitkan sertifikat untuk sebuah domain (rantai kepercayaan sederhana:
Root CA -> Sertifikat domain).

Instal dependensi:
    pip install cryptography
"""

import datetime

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding


def buat_kunci_rsa():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def buat_sertifikat_root_ca(kunci_ca):
    """CA menerbitkan sertifikatnya SENDIRI (self-signed) sebagai akar kepercayaan."""
    subjek = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "ID"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Universitas MDP Root CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, "MDP Root CA"),
    ])
    return (
        x509.CertificateBuilder()
        .subject_name(subjek)
        .issuer_name(issuer)  # issuer == subjek -> SELF-SIGNED (akar kepercayaan)
        .public_key(kunci_ca.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(kunci_ca, hashes.SHA256())
    )


def buat_sertifikat_domain(kunci_domain, nama_domain, kunci_ca, sertifikat_ca):
    """CA menandatangani sertifikat untuk domain -- inilah RANTAI KEPERCAYAAN."""
    subjek = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "ID"),
        x509.NameAttribute(NameOID.COMMON_NAME, nama_domain),
    ])
    return (
        x509.CertificateBuilder()
        .subject_name(subjek)
        .issuer_name(sertifikat_ca.subject)  # diterbitkan OLEH CA, bukan self-signed
        .public_key(kunci_domain.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(nama_domain)]), critical=False)
        .sign(kunci_ca, hashes.SHA256())  # DITANDATANGANI dengan kunci PRIVAT CA
    )


if __name__ == "__main__":
    print("=" * 65)
    print("MEMBANGUN RANTAI KEPERCAYAAN (CHAIN OF TRUST) SEDERHANA")
    print("=" * 65)
    kunci_ca = buat_kunci_rsa()
    sertifikat_ca = buat_sertifikat_root_ca(kunci_ca)
    print(f"1. Root CA diterbitkan (self-signed)")
    print(f"   Subject = Issuer : {sertifikat_ca.subject.rfc4514_string()}")

    kunci_domain = buat_kunci_rsa()
    sertifikat_domain = buat_sertifikat_domain(kunci_domain, "kriptografi.mdp.ac.id", kunci_ca, sertifikat_ca)
    print(f"\n2. Sertifikat domain diterbitkan OLEH Root CA")
    print(f"   Subject : {sertifikat_domain.subject.rfc4514_string()}")
    print(f"   Issuer  : {sertifikat_domain.issuer.rfc4514_string()}")
    print(f"   Berlaku hingga : {sertifikat_domain.not_valid_after_utc.date()}")

    print()
    print("=" * 65)
    print("VERIFIKASI: APAKAH SERTIFIKAT DOMAIN BENAR DITANDATANGANI CA INI?")
    print("=" * 65)
    try:
        kunci_ca.public_key().verify(
            sertifikat_domain.signature,
            sertifikat_domain.tbs_certificate_bytes,
            padding.PKCS1v15(),
            sertifikat_domain.signature_hash_algorithm,
        )
        print("Tanda tangan sertifikat SAH -- diterbitkan oleh Root CA ini.")
    except Exception:
        print("Tanda tangan TIDAK SAH.")

    # Simulasi CA yang BERBEDA (bukan penerbit asli) mencoba "mengklaim" sertifikat ini
    print()
    kunci_ca_lain = buat_kunci_rsa()
    try:
        kunci_ca_lain.public_key().verify(
            sertifikat_domain.signature,
            sertifikat_domain.tbs_certificate_bytes,
            padding.PKCS1v15(),
            sertifikat_domain.signature_hash_algorithm,
        )
        print("(Tidak seharusnya sampai sini)")
    except Exception:
        print("Diverifikasi dengan kunci publik CA LAIN -> GAGAL (sebagaimana mestinya).")
        print(">> Inilah cara browser memvalidasi sertifikat HTTPS: hanya sertifikat")
        print(">> yang ditandatangani oleh CA tepercaya yang akan diterima.")
