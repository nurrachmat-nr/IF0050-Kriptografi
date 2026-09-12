"""
Pertemuan 10 - Keamanan Protokol Jaringan: TLS/SSL & HTTPS
Studi kasus nyata: memeriksa koneksi TLS ke server HTTPS SUNGGUHAN
(situs web Universitas MDP) -- versi protokol, cipher suite yang
dinegosiasikan, dan detail sertifikat digital (menghubungkan langsung
ke materi PKI pada Pertemuan 9).

Hanya memakai modul bawaan Python (socket, ssl) -- tidak perlu instalasi
tambahan.
"""

import socket
import ssl


def periksa_koneksi_tls(host: str, port: int = 443) -> None:
    konteks = ssl.create_default_context()  # memvalidasi sertifikat via trust store OS

    with socket.create_connection((host, port), timeout=8) as sock:
        with konteks.wrap_socket(sock, server_hostname=host) as tls_sock:
            print(f"Terhubung ke {host}:{port}")
            print(f"  Versi protokol dinegosiasikan : {tls_sock.version()}")

            cipher_name, protokol_cipher, kekuatan_bit = tls_sock.cipher()
            print(f"  Cipher suite                  : {cipher_name}")
            print(f"  Kekuatan kunci simetris        : {kekuatan_bit}-bit")

            sertifikat = tls_sock.getpeercert()
            subjek = dict(x[0] for x in sertifikat["subject"])
            penerbit = dict(x[0] for x in sertifikat["issuer"])
            print(f"\n  --- Sertifikat Digital Server (lihat Pertemuan 9) ---")
            print(f"  Subject (pemilik) : {subjek.get('commonName', '-')}")
            print(f"  Issuer (penerbit) : {penerbit.get('commonName', penerbit.get('organizationName', '-'))}")
            print(f"  Berlaku hingga    : {sertifikat['notAfter']}")
            print(f"  Subject Alt Names : {[n[1] for n in sertifikat.get('subjectAltName', [])][:5]}")


if __name__ == "__main__":
    print("=" * 65)
    print("INSPEKSI KONEKSI TLS KE SERVER HTTPS SUNGGUHAN")
    print("=" * 65)
    try:
        periksa_koneksi_tls("www.mdp.ac.id")
    except Exception as e:
        print(f"Koneksi gagal ({e}). Pastikan perangkat terhubung ke internet.")

    print()
    print("=" * 65)
    print("PERCOBAAN: MENOLAK SERTIFIKAT YANG TIDAK VALID (self-signed)")
    print("=" * 65)
    print("ssl.create_default_context() SECARA OTOMATIS menolak sertifikat")
    print("yang tidak diterbitkan oleh CA tepercaya (self-signed, kedaluwarsa,")
    print("atau nama domain tidak cocok) -- inilah alasan peringatan merah")
    print("'Your connection is not private' muncul di browser saat sertifikat")
    print("bermasalah. JANGAN PERNAH mengabaikan peringatan tersebut begitu saja.")
