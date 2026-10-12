"""
Pertemuan 5 - One-Time Pad & Pertukaran Kunci (Diffie-Hellman)
Studi Kasus 4: Kunci OTP dari PRNG biasa = OTP yang bisa dibobol.

random.random()/random.choice() memakai Mersenne Twister: deterministik,
ditentukan sepenuhnya oleh seed. Jika seed berasal dari jam sistem
(kebiasaan buruk yang sering dijumpai), ruang kunci efektif menyusut dari
26^n menjadi hanya "jumlah detik yang mungkin".

Skenario: aplikasi membangkitkan kunci dengan random.seed(waktu_unix).
Penyerang tahu pesan dikirim "sekitar satu jam terakhir" dan bahwa setiap
pesan diawali "PESAN". Tidak perlu library tambahan.
"""

import random
import secrets
import string
import time

ALPHABET = string.ascii_uppercase
A = ord("A")


def kunci_lemah(panjang: int, seed: int) -> str:
    rng = random.Random(seed)                       # TIDAK AMAN untuk kriptografi
    return "".join(rng.choice(ALPHABET) for _ in range(panjang))


def kunci_kuat(panjang: int) -> str:
    return "".join(secrets.choice(ALPHABET) for _ in range(panjang))  # CSPRNG


def enkripsi(p: str, k: str) -> str:
    return "".join(chr((ord(x) - A + ord(y) - A) % 26 + A) for x, y in zip(p, k))


def dekripsi(c: str, k: str) -> str:
    return "".join(chr((ord(x) - ord(y)) % 26 + A) for x, y in zip(c, k))


if __name__ == "__main__":
    plainteks = "PESANKIRIMSOALUJIANKEDOSENPENGAWAS"
    waktu_kirim = int(time.time()) - secrets.randbelow(3600)  # suatu saat < 1 jam lalu
    cipherteks = enkripsi(plainteks, kunci_lemah(len(plainteks), waktu_kirim))

    print("=" * 65)
    print("KUNCI OTP DARI random.seed(waktu)")
    print("=" * 65)
    print(f"Cipherteks disadap : {cipherteks}")

    mulai = time.perf_counter()
    sekarang = int(time.time())
    for percobaan, seed in enumerate(range(sekarang, sekarang - 3601, -1), start=1):
        tebakan = dekripsi(cipherteks, kunci_lemah(len(cipherteks), seed))
        if tebakan.startswith("PESAN"):
            durasi = time.perf_counter() - mulai
            print(f"Seed ditemukan     : {seed}  (setelah {percobaan:,} percobaan)")
            print(f"Plainteks terbongkar: {tebakan}")
            print(f"Waktu serangan     : {durasi:.3f} detik")
            break

    print("\nPerbandingan ruang kunci untuk pesan ini:")
    print(f"  Kunci CSPRNG (secrets)   : 26^{len(plainteks)} ~ 10^{len(plainteks) * 1.415:.0f}")
    print("  Kunci random.seed(waktu) : ~3.600 kemungkinan (1 jam)")
    print(f"\nContoh kunci yang benar  : {kunci_kuat(len(plainteks))}")
