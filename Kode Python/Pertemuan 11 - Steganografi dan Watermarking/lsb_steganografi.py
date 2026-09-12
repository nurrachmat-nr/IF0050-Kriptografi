"""
Pertemuan 11 - Steganografi & Digital Watermarking
Implementasi LSB (Least Significant Bit) Steganography: menyisipkan pesan
rahasia ke dalam bit-bit paling tidak signifikan dari piksel gambar --
perubahan warna yang dihasilkan tidak kasat mata oleh mata manusia.

Instal dependensi:
    pip install pillow
"""

from PIL import Image

PENANDA_AKHIR = "###END###"  # penanda batas akhir pesan tersembunyi


def teks_ke_biner(teks: str) -> str:
    return "".join(format(ord(c), "08b") for c in teks)


def biner_ke_teks(biner: str) -> str:
    chars = [biner[i:i + 8] for i in range(0, len(biner), 8)]
    return "".join(chr(int(c, 2)) for c in chars)


def sisipkan_pesan(gambar: Image.Image, pesan: str) -> Image.Image:
    pesan_biner = teks_ke_biner(pesan + PENANDA_AKHIR)
    gambar = gambar.convert("RGB")
    piksel = list(gambar.getdata())

    kapasitas_bit = len(piksel) * 3  # 1 bit LSB per kanal warna (R, G, B)
    if len(pesan_biner) > kapasitas_bit:
        raise ValueError(
            f"Pesan terlalu panjang: butuh {len(pesan_biner)} bit, "
            f"kapasitas gambar hanya {kapasitas_bit} bit."
        )

    idx_bit = 0
    piksel_baru = []
    for r, g, b in piksel:
        kanal = [r, g, b]
        for i in range(3):
            if idx_bit < len(pesan_biner):
                # Ganti bit paling tidak signifikan (LSB) dengan 1 bit pesan
                kanal[i] = (kanal[i] & ~1) | int(pesan_biner[idx_bit])
                idx_bit += 1
        piksel_baru.append(tuple(kanal))

    gambar_stego = Image.new("RGB", gambar.size)
    gambar_stego.putdata(piksel_baru)
    return gambar_stego


def ekstrak_pesan(gambar_stego: Image.Image) -> str:
    piksel = list(gambar_stego.convert("RGB").getdata())
    bit_terkumpul = []
    for r, g, b in piksel:
        for kanal in (r, g, b):
            bit_terkumpul.append(str(kanal & 1))

    biner = "".join(bit_terkumpul)
    teks = biner_ke_teks(biner)
    return teks.split(PENANDA_AKHIR)[0]


if __name__ == "__main__":
    # Gambar sampel dibangkitkan secara sintetis (gradasi warna 200x150 piksel)
    lebar, tinggi = 200, 150
    gambar_asli = Image.new("RGB", (lebar, tinggi))
    for y in range(tinggi):
        for x in range(lebar):
            gambar_asli.putpixel((x, y), (x % 256, y % 256, (x + y) % 256))

    pesan_rahasia = "Rapat direksi pukul 14:00 di ruang eksekutif lantai 9"

    print("=" * 65)
    print("PENYISIPAN PESAN DENGAN LSB STEGANOGRAPHY")
    print("=" * 65)
    kapasitas = lebar * tinggi * 3 // 8  # kapasitas dalam karakter (byte)
    print(f"Ukuran gambar     : {lebar}x{tinggi} piksel")
    print(f"Kapasitas maksimum: ~{kapasitas} karakter")
    print(f"Pesan disisipkan  : \"{pesan_rahasia}\" ({len(pesan_rahasia)} karakter)")

    gambar_stego = sisipkan_pesan(gambar_asli, pesan_rahasia)
    gambar_stego.save("gambar_stego.png")
    print("Gambar hasil (gambar_stego.png) disimpan -- secara visual TIDAK BERBEDA dari aslinya.")

    print()
    print("=" * 65)
    print("BUKTI: PERUBAHAN PIKSEL TIDAK KASAT MATA")
    print("=" * 65)
    p_asli = gambar_asli.getpixel((0, 0))
    p_stego = gambar_stego.getpixel((0, 0))
    print(f"Piksel (0,0) sebelum : RGB{p_asli}")
    print(f"Piksel (0,0) sesudah : RGB{p_stego}")
    print("(Selisih nilai warna maksimum hanya 1 dari 255 -- tidak terlihat mata manusia)")

    print()
    print("=" * 65)
    print("EKSTRAKSI PESAN DARI GAMBAR STEGO")
    print("=" * 65)
    pesan_hasil_ekstraksi = ekstrak_pesan(gambar_stego)
    print(f"Pesan berhasil diekstrak: \"{pesan_hasil_ekstraksi}\"")
    print(f"Sesuai pesan asli? {pesan_hasil_ekstraksi == pesan_rahasia}")
