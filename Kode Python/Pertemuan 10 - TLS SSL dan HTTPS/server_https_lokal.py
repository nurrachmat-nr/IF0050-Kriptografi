"""
Pertemuan 10 - Keamanan Protokol Jaringan: TLS/SSL & HTTPS
Studi kasus: menjalankan server HTTPS lokal dengan sertifikat SELF-SIGNED,
lalu membuktikan langsung mengapa browser/klien menolak sertifikat yang
tidak diterbitkan oleh CA tepercaya -- dan bagaimana ia diterima setelah
CA-nya ditambahkan ke daftar tepercaya klien.

Instal dependensi:
    pip install cryptography
"""

import datetime
import http.server
import ssl
import socket
import threading
import time

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

HOST, PORT = "127.0.0.1", 8443


def buat_sertifikat_self_signed(nama_domain: str):
    kunci = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subjek = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, nama_domain)])
    sertifikat = (
        x509.CertificateBuilder()
        .subject_name(subjek)
        .issuer_name(issuer)
        .public_key(kunci.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=30))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(nama_domain)]), critical=False)
        .sign(kunci, hashes.SHA256())
    )
    return kunci, sertifikat


def jalankan_server(cert_path: str, key_path: str):
    handler = http.server.SimpleHTTPRequestHandler
    server = http.server.HTTPServer((HOST, PORT), handler)
    konteks = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    konteks.load_cert_chain(certfile=cert_path, keyfile=key_path)
    server.socket = konteks.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


if __name__ == "__main__":
    print("=" * 65)
    print("MEMBANGKITKAN SERTIFIKAT SELF-SIGNED & MENJALANKAN SERVER HTTPS")
    print("=" * 65)
    kunci, sertifikat = buat_sertifikat_self_signed("localhost")

    with open("_server.key", "wb") as f:
        f.write(kunci.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    with open("_server.crt", "wb") as f:
        f.write(sertifikat.public_bytes(serialization.Encoding.PEM))

    thread_server = threading.Thread(target=jalankan_server, args=("_server.crt", "_server.key"), daemon=True)
    thread_server.start()
    time.sleep(0.5)
    print(f"Server HTTPS lokal berjalan di https://{HOST}:{PORT} (sertifikat self-signed)\n")

    print("=" * 65)
    print("PERCOBAAN 1: KLIEN DENGAN VALIDASI STANDAR (seperti browser)")
    print("=" * 65)
    konteks_ketat = ssl.create_default_context()
    try:
        with socket.create_connection((HOST, PORT), timeout=5) as sock:
            with konteks_ketat.wrap_socket(sock, server_hostname="localhost"):
                print("Koneksi BERHASIL (seharusnya tidak, karena sertifikat self-signed!)")
    except ssl.SSLCertVerificationError as e:
        print(f"Koneksi DITOLAK sebagaimana mestinya:")
        print(f"  ssl.SSLCertVerificationError: {e.reason}")

    print()
    print("=" * 65)
    print("PERCOBAAN 2: KLIEN YANG SECARA EKSPLISIT MEMPERCAYAI CA INI")
    print("=" * 65)
    konteks_percaya = ssl.create_default_context()
    konteks_percaya.load_verify_locations("_server.crt")  # menambahkan CA ke trust store klien
    with socket.create_connection((HOST, PORT), timeout=5) as sock:
        with konteks_percaya.wrap_socket(sock, server_hostname="localhost") as tls_sock:
            print(f"Koneksi BERHASIL setelah sertifikat ditambahkan ke trust store klien.")
            print(f"Versi TLS: {tls_sock.version()}, Cipher: {tls_sock.cipher()[0]}")

    print("\n>> Inilah sebabnya sertifikat self-signed TIDAK COCOK untuk situs publik:")
    print(">> setiap pengunjung harus mempercayainya secara manual satu per satu.")
