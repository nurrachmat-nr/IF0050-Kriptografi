"""
Pertemuan 7 - Fungsi Hash & Integritas Data (SHA-2/SHA-3, HMAC)
Mengapa "H(kunci || pesan)" TIDAK CUKUP untuk autentikasi pesan, dan
mengapa HMAC (Hash-based Message Authentication Code, RFC 2104) adalah
solusi yang benar.

HMAC(K, M) = H( (K' XOR opad) || H( (K' XOR ipad) || M ) )
Namun pada praktiknya, cukup memakai modul hmac bawaan Python -- JANGAN
mengimplementasikan sendiri konstruksi ini untuk kebutuhan produksi.
"""

import hashlib
import hmac


def mac_naif(kunci: bytes, pesan: bytes) -> str:
    """CARA YANG SALAH: sekadar menggabungkan kunci dan pesan lalu di-hash."""
    return hashlib.sha256(kunci + pesan).hexdigest()


def hmac_benar(kunci: bytes, pesan: bytes) -> str:
    """CARA YANG BENAR: memakai konstruksi HMAC standar (RFC 2104)."""
    return hmac.new(kunci, pesan, hashlib.sha256).hexdigest()


if __name__ == "__main__":
    kunci_rahasia = b"kunci-rahasia-server"
    pesan_asli = b"jumlah=100000&tujuan=rekening-A"

    print("=" * 65)
    print("HMAC: AUTENTIKASI PESAN YANG BENAR")
    print("=" * 65)
    tag = hmac_benar(kunci_rahasia, pesan_asli)
    print(f"Pesan       : {pesan_asli.decode()}")
    print(f"HMAC-SHA256 : {tag}")

    # Verifikasi HARUS memakai hmac.compare_digest -- bukan `==` biasa --
    # untuk mencegah serangan timing (timing attack).
    tag_diterima = hmac_benar(kunci_rahasia, pesan_asli)
    valid = hmac.compare_digest(tag, tag_diterima)
    print(f"Verifikasi (compare_digest, tahan timing attack): {valid}")

    print()
    print("=" * 65)
    print("MENGAPA cara naif H(kunci || pesan) BERBAHAYA:")
    print("LENGTH EXTENSION ATTACK pada fungsi hash Merkle-Damgard (SHA-256)")
    print("=" * 65)
    mac_tidak_aman = mac_naif(kunci_rahasia, pesan_asli)
    print(f"mac_naif(kunci, pesan) = H(kunci || pesan) = {mac_tidak_aman}")
    print()
    print("Penyerang yang TIDAK TAHU kunci, tetapi TAHU mac_naif(kunci, pesan)")
    print("dan panjang kunci, dapat menghitung mac_naif(kunci, pesan + tambahan)")
    print("TANPA pernah mengetahui kunci rahasia -- karena struktur internal")
    print("SHA-256 (Merkle-Damgard) memungkinkan hash 'dilanjutkan'.")
    print()
    print("(Serangan ini memerlukan pustaka khusus seperti 'hashpumpy' untuk")
    print(" didemonstrasikan penuh -- di sini cukup dipahami secara konsep.)")
    print()
    print(">> HMAC KEBAL terhadap length extension attack karena kunci")
    print(">> dicampur dua kali (ipad & opad), bukan hanya di awal pesan.")
    print(">> Kesimpulan: SELALU gunakan modul hmac, JANGAN H(kunci + pesan).")
