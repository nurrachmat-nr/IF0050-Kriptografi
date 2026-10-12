"""
Pertemuan 5 - One-Time Pad & Pertukaran Kunci (Diffie-Hellman)
Studi Kasus 3: OTP menjamin KERAHASIAAN, tetapi TIDAK menjamin INTEGRITAS.

Penyerang yang tahu format pesan dapat mengubah isi cipherteks tanpa
mengetahui kunci:
    C' = C XOR (P_lama XOR P_baru)  ->  dekripsi(C') = P_baru

Solusi: tambahkan MAC (mis. HMAC-SHA256, Pertemuan 7) dengan kunci terpisah,
dan verifikasi MAC sebelum pesan diproses. Tidak perlu library tambahan.
"""

import hashlib
import hmac
import secrets


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def ubah_cipherteks(c: bytes, posisi: int, lama: bytes, baru: bytes) -> bytes:
    """Serangan bit-flipping: penyerang TIDAK memegang kunci."""
    delta = xor_bytes(lama, baru)
    bagian = xor_bytes(c[posisi:posisi + len(delta)], delta)
    return c[:posisi] + bagian + c[posisi + len(delta):]


if __name__ == "__main__":
    pesan = b"TRANSFER Rp0100000 KE REK 1234567"
    kunci_otp = secrets.token_bytes(len(pesan))
    kunci_mac = secrets.token_bytes(32)          # kunci MAC TERPISAH dari OTP
    c = xor_bytes(pesan, kunci_otp)

    print("=" * 65)
    print("SERANGAN MALLEABILITY TERHADAP OTP")
    print("=" * 65)
    print(f"Pesan asli Bank      : {pesan.decode()}")

    # Penyerang tahu format: nominal mulai pada posisi 11, rekening pada posisi 26
    c_palsu = ubah_cipherteks(c, 11, b"0100000", b"9900000")
    c_palsu = ubah_cipherteks(c_palsu, 26, b"1234567", b"6666666")
    print(f"Diterima & didekripsi: {xor_bytes(c_palsu, kunci_otp).decode()}")
    print(">> Kunci OTP tetap rahasia, tetapi isi pesan berhasil diubah!\n")

    print("=" * 65)
    print("PERTAHANAN: OTP + HMAC-SHA256 (encrypt-then-MAC)")
    print("=" * 65)
    tag = hmac.new(kunci_mac, c, hashlib.sha256).digest()
    for label, cipher in [("Cipherteks asli ", c), ("Cipherteks palsu", c_palsu)]:
        tag_hitung = hmac.new(kunci_mac, cipher, hashlib.sha256).digest()
        sah = hmac.compare_digest(tag, tag_hitung)
        print(f"{label}: tag cocok? {sah} -> {'DIPROSES' if sah else 'DITOLAK'}")
