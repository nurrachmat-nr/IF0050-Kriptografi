"""
Pertemuan 5 - One-Time Pad & Pertukaran Kunci (Diffie-Hellman)
Simulasi protokol pertukaran kunci Diffie-Hellman (DH), 1976.

CATATAN PENTING: bilangan prima p di bawah ini SENGAJA dibuat kecil agar
mudah diikuti langkah demi langkah secara manual. Pada penerapan nyata,
p berukuran >= 2048 bit (lihat RFC 3526) -- bukan bilangan kecil seperti
di sini, yang HANYA untuk tujuan edukasi.
"""

import secrets

# Parameter publik (disepakati & diketahui semua pihak, termasuk Eve)
P = 23   # bilangan prima (modulus)
G = 5    # generator/akar primitif dari P


def bangkitkan_kunci_privat() -> int:
    return secrets.randbelow(P - 2) + 2  # acak dalam rentang [2, P-2]


def hitung_kunci_publik(privat: int) -> int:
    return pow(G, privat, P)  # G^privat mod P


def hitung_rahasia_bersama(kunci_publik_lawan: int, kunci_privat_sendiri: int) -> int:
    return pow(kunci_publik_lawan, kunci_privat_sendiri, P)


if __name__ == "__main__":
    print("=" * 65)
    print(f"PARAMETER PUBLIK (diketahui semua pihak, termasuk Eve): P={P}, G={G}")
    print("=" * 65)

    # --- Alice ---
    privat_alice = bangkitkan_kunci_privat()
    publik_alice = hitung_kunci_publik(privat_alice)

    # --- Bob ---
    privat_bob = bangkitkan_kunci_privat()
    publik_bob = hitung_kunci_publik(privat_bob)

    print(f"\nAlice : kunci privat a = {privat_alice}  (RAHASIA, tidak pernah dikirim)")
    print(f"Alice : kunci publik A = G^a mod P = {publik_alice}  (dikirim ke Bob secara terbuka)")
    print(f"\nBob   : kunci privat b = {privat_bob}  (RAHASIA, tidak pernah dikirim)")
    print(f"Bob   : kunci publik B = G^b mod P = {publik_bob}  (dikirim ke Alice secara terbuka)")

    # Alice & Bob menghitung rahasia bersama dari kunci publik lawan
    rahasia_alice = hitung_rahasia_bersama(publik_bob, privat_alice)   # B^a mod P
    rahasia_bob = hitung_rahasia_bersama(publik_alice, privat_bob)     # A^b mod P

    print(f"\nAlice menghitung : B^a mod P = {rahasia_alice}")
    print(f"Bob   menghitung : A^b mod P = {rahasia_bob}")
    print(f"\nKedua pihak memperoleh rahasia bersama yang SAMA? {rahasia_alice == rahasia_bob}")
    print(f"Kunci simetris bersama (mis. untuk AES) = {rahasia_alice}")

    print()
    print("=" * 65)
    print("SUDUT PANDANG EVE (penyadap pasif)")
    print("=" * 65)
    print(f"Eve HANYA melihat nilai publik: P={P}, G={G}, A={publik_alice}, B={publik_bob}")
    print("Untuk memperoleh rahasia bersama, Eve harus memecahkan:")
    print(f"  a sedemikian sehingga G^a mod P = {publik_alice}   <- Discrete Logarithm Problem")
    print("Pada P berukuran >= 2048 bit, persoalan ini SECARA KOMPUTASI MUSTAHIL")
    print("dipecahkan dengan algoritma & komputer yang ada saat ini.")

    # Brute force HANYA mungkin karena P sengaja dibuat sangat kecil (demo edukasi)
    for kandidat_a in range(1, P):
        if pow(G, kandidat_a, P) == publik_alice:
            print(f"\n(Demo P kecil) Eve brute-force menemukan a = {kandidat_a} "
                  f"({'cocok' if kandidat_a == privat_alice else 'kandidat lain (kolisi)'})")
            break
