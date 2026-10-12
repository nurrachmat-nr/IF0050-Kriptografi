"""
Pertemuan 5 - One-Time Pad & Pertukaran Kunci (Diffie-Hellman)
Studi Kasus 6: Serangan Man-in-the-Middle (MITM) dan pertahanannya.

Bagian A - DH tanpa autentikasi: Eve mengganti kunci publik Alice dan Bob
           dengan miliknya, lalu membaca & MENGUBAH pesan terenkripsi AES-GCM.
Bagian B - DH terautentikasi: setiap kunci publik ditandatangani (Ed25519,
           dibahas di Pertemuan 9). Kunci sisipan Eve langsung ketahuan.

Parameter P = 23, G = 5 sama dengan contoh di slide (a = 6, b = 15, e = 3)
agar angka dapat dicocokkan. Rahasia DH diturunkan menjadi kunci AES-128
dengan SHA-256 -- hanya untuk demo; TLS memakai HKDF.

Instal dependensi:
    pip install pycryptodome
"""

import hashlib

from Crypto.Cipher import AES
from Crypto.PublicKey import ECC
from Crypto.Signature import eddsa

P, G = 23, 5


class Pihak:
    def __init__(self, nama: str, privat: int):
        self.nama, self.privat = nama, privat
        self.publik = pow(G, privat, P)

    def rahasia(self, publik_lawan: int) -> int:
        return pow(publik_lawan, self.privat, P)


def kunci_aes(rahasia_dh: int) -> bytes:
    return hashlib.sha256(str(rahasia_dh).encode()).digest()[:16]


def kirim(kunci: bytes, teks: str) -> tuple[bytes, bytes, bytes]:
    c = AES.new(kunci, AES.MODE_GCM)
    ct, tag = c.encrypt_and_digest(teks.encode())
    return c.nonce, ct, tag


def terima(kunci: bytes, paket: tuple[bytes, bytes, bytes]) -> str:
    nonce, ct, tag = paket
    return AES.new(kunci, AES.MODE_GCM, nonce=nonce).decrypt_and_verify(ct, tag).decode()


if __name__ == "__main__":
    alice, bob, eve = Pihak("Alice", 6), Pihak("Bob", 15), Pihak("Eve", 3)

    print("=" * 65)
    print("A. DIFFIE-HELLMAN TANPA AUTENTIKASI")
    print("=" * 65)
    print(f"Alice kirim A={alice.publik} -> dicegat Eve, Bob menerima E={eve.publik}")
    print(f"Bob   kirim B={bob.publik} -> dicegat Eve, Alice menerima E={eve.publik}")

    k_alice = alice.rahasia(eve.publik)          # Alice mengira ini kunci bersama Bob
    k_bob = bob.rahasia(eve.publik)              # Bob mengira ini kunci bersama Alice
    k_eve_a, k_eve_b = eve.rahasia(alice.publik), eve.rahasia(bob.publik)
    print(f"Kunci Alice = {k_alice} | Eve<->Alice = {k_eve_a}")
    print(f"Kunci Bob   = {k_bob} | Eve<->Bob   = {k_eve_b}")
    print(f"Seharusnya (tanpa Eve) = {alice.rahasia(bob.publik)}")

    paket = kirim(kunci_aes(k_alice), "Transfer dana penelitian Rp 5 juta ke rek 1234")
    dibaca_eve = terima(kunci_aes(k_eve_a), paket)
    print(f"\nEve membaca  : {dibaca_eve}")
    dipalsukan = dibaca_eve.replace("1234", "6666")
    diterima_bob = terima(kunci_aes(k_bob), kirim(kunci_aes(k_eve_b), dipalsukan))
    print(f"Bob menerima : {diterima_bob}")
    print(">> AES-GCM lolos verifikasi di sisi Bob -- enkripsi kuat tidak menolong")
    print(">> bila kuncinya disepakati dengan pihak yang salah.")

    print("\n" + "=" * 65)
    print("B. DIFFIE-HELLMAN TERAUTENTIKASI (kunci publik ditandatangani)")
    print("=" * 65)
    # Kunci identitas jangka panjang Alice; kunci verifikasinya sudah dimiliki Bob
    # sebelumnya (mis. lewat sertifikat X.509 -- Pertemuan 9).
    identitas_alice = ECC.generate(curve="Ed25519")
    verifikasi_alice = identitas_alice.public_key()
    tanda_tangan = eddsa.new(identitas_alice, "rfc8032").sign(str(alice.publik).encode())

    for label, nilai in [("A asli dari Alice", alice.publik), ("E sisipan Eve   ", eve.publik)]:
        try:
            eddsa.new(verifikasi_alice, "rfc8032").verify(str(nilai).encode(), tanda_tangan)
            print(f"Bob memeriksa {label} = {nilai:>2}: tanda tangan VALID -> lanjut")
        except ValueError:
            print(f"Bob memeriksa {label} = {nilai:>2}: tanda tangan TIDAK VALID -> koneksi diputus")
