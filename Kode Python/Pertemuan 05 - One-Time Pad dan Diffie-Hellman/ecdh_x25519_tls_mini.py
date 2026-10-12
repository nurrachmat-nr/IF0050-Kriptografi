"""
Pertemuan 5 - One-Time Pad & Pertukaran Kunci (Diffie-Hellman)
Studi Kasus 9: Mini "handshake" ala TLS 1.3 dengan ECDH X25519.

Alur yang dipakai browser setiap kali membuka situs HTTPS:
  1. Klien & server membangkitkan kunci X25519 EFEMERAL (baru tiap sesi).
  2. Bertukar kunci publik (32 byte) lewat jaringan terbuka.
  3. Menghitung rahasia bersama ECDH yang sama.
  4. Menurunkan kunci sesi dengan HKDF-SHA256.
  5. Mengenkripsi data aplikasi dengan AES-256-GCM.
Karena kunci privat efemeral dihapus setelah sesi, rekaman lama tetap aman
walaupun kunci server bocor kelak (Perfect Forward Secrecy).

Catatan: ini penyederhanaan untuk edukasi -- TLS asli juga mengautentikasi
server dengan sertifikat (Pertemuan 9-10) dan memakai key schedule lengkap.

Instal dependensi:
    pip install cryptography
"""

import os
import time

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def publik_bytes(kunci_privat: X25519PrivateKey) -> bytes:
    return kunci_privat.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def turunkan_kunci_sesi(rahasia: bytes, transkrip: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=b"mini-tls13 kunci sesi" + transkrip).derive(rahasia)


def sesi(nomor: int, pesan: bytes) -> tuple[bytes, bytes, bytes]:
    t0 = time.perf_counter()
    klien, server = X25519PrivateKey.generate(), X25519PrivateKey.generate()
    pub_klien, pub_server = publik_bytes(klien), publik_bytes(server)
    transkrip = pub_klien + pub_server                 # "ClientHello" + "ServerHello"

    rahasia_klien = klien.exchange(server.public_key())
    rahasia_server = server.exchange(klien.public_key())
    kunci_klien = turunkan_kunci_sesi(rahasia_klien, transkrip)
    kunci_server = turunkan_kunci_sesi(rahasia_server, transkrip)

    nonce = os.urandom(12)
    ct = AESGCM(kunci_klien).encrypt(nonce, pesan, transkrip)
    pt = AESGCM(kunci_server).decrypt(nonce, ct, transkrip)
    durasi = (time.perf_counter() - t0) * 1000

    print(f"--- Sesi {nomor} ---")
    print(f"ClientHello key_share : {pub_klien.hex()[:32]}...")
    print(f"ServerHello key_share : {pub_server.hex()[:32]}...")
    print(f"Rahasia ECDH sama?    : {rahasia_klien == rahasia_server}")
    print(f"Kunci sesi (HKDF)     : {kunci_klien.hex()[:32]}...")
    print(f"Server menerima       : {pt.decode()}")
    print(f"Waktu handshake+data  : {durasi:.2f} ms\n")
    return kunci_klien, ct, nonce


if __name__ == "__main__":
    print("=" * 65)
    print("MINI HANDSHAKE TLS 1.3 DENGAN X25519 + HKDF + AES-256-GCM")
    print("=" * 65)
    k1, _, _ = sesi(1, b"GET /nilai-kriptografi HTTP/1.1")
    k2, _, _ = sesi(2, b"GET /nilai-kriptografi HTTP/1.1")
    print(f"Kunci sesi 1 == sesi 2? {k1 == k2}  -> setiap sesi punya kunci baru (PFS)")
    print("Ukuran kunci publik X25519: 32 byte vs DH klasik 2048-bit: 256 byte")
