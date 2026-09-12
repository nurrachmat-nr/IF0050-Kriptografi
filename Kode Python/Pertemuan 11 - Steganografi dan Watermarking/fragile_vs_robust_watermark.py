"""
Pertemuan 11 - Steganografi & Digital Watermarking
Membandingkan FRAGILE watermarking (LSB, rusak oleh gangguan sekecil apa
pun -- cocok untuk deteksi manipulasi) dengan ROBUST watermarking
sederhana berbasis rata-rata blok (bertahan terhadap noise ringan --
cocok untuk perlindungan hak cipta).

Instal dependensi:
    pip install pillow numpy
"""

import numpy as np
from PIL import Image

UKURAN_BLOK = 8       # blok 8x8 piksel per bit watermark (mirip prinsip domain-blok pada DCT)
KEKUATAN_ROBUST = 12   # seberapa besar rata-rata blok digeser untuk menyandikan bit


def buat_gambar_sampel(lebar=128, tinggi=128) -> Image.Image:
    arr = np.fromfunction(lambda y, x: (x * 2) % 256, (tinggi, lebar), dtype=int).astype(np.uint8)
    return Image.fromarray(arr, mode="L")  # grayscale, agar fokus pada konsep


# ---------- FRAGILE: LSB pada setiap piksel ----------
def watermark_fragile(gambar: Image.Image, bit_watermark: str) -> Image.Image:
    arr = np.array(gambar).copy()
    flat = arr.flatten()
    for i, bit in enumerate(bit_watermark):
        flat[i] = (int(flat[i]) & 0xFE) | int(bit)
    return Image.fromarray(flat.reshape(arr.shape))


def ekstrak_fragile(gambar: Image.Image, panjang_bit: int) -> str:
    flat = np.array(gambar).flatten()
    return "".join(str(flat[i] & 1) for i in range(panjang_bit))


# ---------- ROBUST: sandikan bit pada RATA-RATA tiap blok ----------
def watermark_robust(gambar: Image.Image, bit_watermark: str) -> Image.Image:
    arr = np.array(gambar).astype(int).copy()
    tinggi, lebar = arr.shape
    idx = 0
    for y in range(0, tinggi - UKURAN_BLOK + 1, UKURAN_BLOK):
        for x in range(0, lebar - UKURAN_BLOK + 1, UKURAN_BLOK):
            if idx >= len(bit_watermark):
                break
            blok = arr[y:y + UKURAN_BLOK, x:x + UKURAN_BLOK]
            rata2 = blok.mean()
            # Target ada di TENGAH tiap separuh interval (bukan tepat di batas)
            # agar tersedia margin +/- setengah KEKUATAN_ROBUST terhadap noise.
            target_mod = (1.5 if bit_watermark[idx] == "1" else 0.5) * KEKUATAN_ROBUST
            selisih = target_mod - (rata2 % (2 * KEKUATAN_ROBUST))
            arr[y:y + UKURAN_BLOK, x:x + UKURAN_BLOK] = np.clip(blok + selisih, 0, 255)
            idx += 1
    return Image.fromarray(arr.astype(np.uint8))


def ekstrak_robust(gambar: Image.Image, jumlah_bit: int) -> str:
    arr = np.array(gambar).astype(int)
    tinggi, lebar = arr.shape
    hasil, idx = [], 0
    for y in range(0, tinggi - UKURAN_BLOK + 1, UKURAN_BLOK):
        for x in range(0, lebar - UKURAN_BLOK + 1, UKURAN_BLOK):
            if idx >= jumlah_bit:
                break
            rata2 = arr[y:y + UKURAN_BLOK, x:x + UKURAN_BLOK].mean()
            hasil.append("1" if (rata2 % (2 * KEKUATAN_ROBUST)) >= KEKUATAN_ROBUST else "0")
            idx += 1
    return "".join(hasil)


def tambahkan_noise(gambar: Image.Image, kekuatan=3) -> Image.Image:
    """Simulasi gangguan ringan (mis. akibat kompresi/transmisi ulang)."""
    arr = np.array(gambar).astype(int)
    noise = np.random.randint(-kekuatan, kekuatan + 1, arr.shape)
    return Image.fromarray(np.clip(arr + noise, 0, 255).astype(np.uint8))


if __name__ == "__main__":
    np.random.seed(42)
    gambar = buat_gambar_sampel()
    watermark_asli = "1011001110"  # 10-bit watermark contoh (mis. ID pemilik hak cipta)

    print("=" * 65)
    print(f"WATERMARK YANG DISISIPKAN: {watermark_asli}")
    print("=" * 65)

    # --- Tanpa gangguan ---
    img_fragile = watermark_fragile(gambar, watermark_asli)
    img_robust = watermark_robust(gambar, watermark_asli)
    print(f"Fragile - tanpa gangguan -> diekstrak: {ekstrak_fragile(img_fragile, len(watermark_asli))}")
    print(f"Robust  - tanpa gangguan -> diekstrak: {ekstrak_robust(img_robust, len(watermark_asli))}")

    # --- Setelah gambar mengalami gangguan ringan (noise) ---
    print()
    print("=" * 65)
    print("SETELAH GAMBAR MENGALAMI GANGGUAN RINGAN (noise +/-3, mis. kompresi ulang)")
    print("=" * 65)
    img_fragile_noisy = tambahkan_noise(img_fragile)
    img_robust_noisy = tambahkan_noise(img_robust)

    hasil_fragile = ekstrak_fragile(img_fragile_noisy, len(watermark_asli))
    hasil_robust = ekstrak_robust(img_robust_noisy, len(watermark_asli))

    print(f"Fragile - setelah noise -> diekstrak: {hasil_fragile}  "
          f"({'RUSAK -- terdeteksi manipulasi!' if hasil_fragile != watermark_asli else 'utuh'})")
    print(f"Robust  - setelah noise -> diekstrak: {hasil_robust}  "
          f"({'tetap utuh -- watermark bertahan' if hasil_robust == watermark_asli else 'rusak'})")

    print()
    print(">> KESIMPULAN: Fragile watermarking SENGAJA dirancang mudah rusak")
    print(">> (cocok untuk deteksi manipulasi/tamper detection), sedangkan robust")
    print(">> watermarking dirancang bertahan dari gangguan wajar (cocok untuk")
    print(">> perlindungan hak cipta/copyright protection).")
