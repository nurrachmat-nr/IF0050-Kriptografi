"""
Pertemuan 2 - Kriptografi Klasik & Kriptanalisis Dasar
Implementasi Vigenere Cipher: cipher substitusi polialfabetik
menggunakan kata kunci yang diulang sepanjang plainteks.

Rumus:
    Enkripsi : c_i = (p_i + k_(i mod m)) mod 26
    Dekripsi : p_i = (c_i - k_(i mod m)) mod 26
    m        = panjang kata kunci
"""

A = ord("A")


def _perluas_kunci(teks: str, kunci: str) -> str:
    """Mengulang kata kunci sepanjang teks, hanya menghitung posisi huruf alfabet."""
    kunci = kunci.upper()
    hasil = []
    j = 0
    for ch in teks:
        if ch.isalpha():
            hasil.append(kunci[j % len(kunci)])
            j += 1
        else:
            hasil.append(ch)
    return "".join(hasil)


def enkripsi(plainteks: str, kunci: str) -> str:
    plainteks = plainteks.upper()
    kunci_perluasan = _perluas_kunci(plainteks, kunci)
    hasil = []
    for p_ch, k_ch in zip(plainteks, kunci_perluasan):
        if p_ch.isalpha():
            p = ord(p_ch) - A
            k = ord(k_ch) - A
            c = (p + k) % 26
            hasil.append(chr(c + A))
        else:
            hasil.append(p_ch)
    return "".join(hasil)


def dekripsi(cipherteks: str, kunci: str) -> str:
    cipherteks = cipherteks.upper()
    kunci_perluasan = _perluas_kunci(cipherteks, kunci)
    hasil = []
    for c_ch, k_ch in zip(cipherteks, kunci_perluasan):
        if c_ch.isalpha():
            c = ord(c_ch) - A
            k = ord(k_ch) - A
            p = (c - k) % 26
            hasil.append(chr(p + A))
        else:
            hasil.append(c_ch)
    return "".join(hasil)


if __name__ == "__main__":
    plainteks = "KRIPTOGRAFI ITU MENARIK"
    kunci = "KUNCI"

    cipherteks = enkripsi(plainteks, kunci)
    hasil_dekripsi = dekripsi(cipherteks, kunci)

    print("=" * 60)
    print("ENKRIPSI & DEKRIPSI VIGENERE CIPHER")
    print("=" * 60)
    print(f"Plainteks   : {plainteks}")
    print(f"Kunci       : {kunci}")
    print(f"Cipherteks  : {cipherteks}")
    print(f"Dekripsi    : {hasil_dekripsi}")
    print(f"Berhasil?   : {hasil_dekripsi == plainteks}")

    print()
    print("Catatan: berbeda dari Caesar cipher, huruf plainteks yang sama")
    print("(mis. huruf 'I') dapat dienkripsi menjadi huruf cipherteks yang")
    print("berbeda-beda tergantung posisinya -- inilah sifat polialfabetik")
    print("yang membuat Vigenere lebih tahan terhadap analisis frekuensi")
    print("sederhana dibandingkan Caesar cipher.")
