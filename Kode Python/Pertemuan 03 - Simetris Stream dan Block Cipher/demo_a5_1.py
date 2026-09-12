"""
Pertemuan 3 - Kriptografi Simetris: Stream & Block Cipher
Demo edukatif A5/1, stream cipher GSM generasi awal.

A5/1 dibangun dari tiga LFSR dengan majority clocking. Algoritma ini sudah
tidak aman dan tidak boleh digunakan untuk komunikasi nyata.
"""

import secrets

PANJANG_KUNCI_BIT = 64
PANJANG_FRAME_BIT = 22


def bit_ke(data: int, posisi: int) -> int:
    """Mengambil bit pada posisi tertentu, dihitung dari bit paling rendah."""
    return (data >> posisi) & 1


def mayoritas(bit_a: int, bit_b: int, bit_c: int) -> int:
    """Menghasilkan bit yang muncul setidaknya dua kali."""
    return 1 if bit_a + bit_b + bit_c >= 2 else 0


class A51:
    """Implementasi ringkas register A5/1 untuk demonstrasi pembelajaran."""

    def __init__(self, kunci: int, nomor_frame: int) -> None:
        self.r1 = 0
        self.r2 = 0
        self.r3 = 0

        for posisi in range(PANJANG_KUNCI_BIT):
            self._clock_semua()
            bit = bit_ke(kunci, posisi)
            self.r1 ^= bit
            self.r2 ^= bit
            self.r3 ^= bit

        for posisi in range(PANJANG_FRAME_BIT):
            self._clock_semua()
            bit = bit_ke(nomor_frame, posisi)
            self.r1 ^= bit
            self.r2 ^= bit
            self.r3 ^= bit

        for _ in range(100):
            self._clock_mayoritas()

    def _clock_r1(self) -> None:
        umpan_balik = bit_ke(self.r1, 13) ^ bit_ke(self.r1, 16) ^ bit_ke(self.r1, 17) ^ bit_ke(self.r1, 18)
        self.r1 = ((self.r1 << 1) & 0x7FFFF) | umpan_balik

    def _clock_r2(self) -> None:
        umpan_balik = bit_ke(self.r2, 20) ^ bit_ke(self.r2, 21)
        self.r2 = ((self.r2 << 1) & 0x3FFFFF) | umpan_balik

    def _clock_r3(self) -> None:
        umpan_balik = bit_ke(self.r3, 7) ^ bit_ke(self.r3, 20) ^ bit_ke(self.r3, 21) ^ bit_ke(self.r3, 22)
        self.r3 = ((self.r3 << 1) & 0x7FFFFF) | umpan_balik

    def _clock_semua(self) -> None:
        self._clock_r1()
        self._clock_r2()
        self._clock_r3()

    def _clock_mayoritas(self) -> None:
        nilai_mayoritas = mayoritas(bit_ke(self.r1, 8), bit_ke(self.r2, 10), bit_ke(self.r3, 10))
        if bit_ke(self.r1, 8) == nilai_mayoritas:
            self._clock_r1()
        if bit_ke(self.r2, 10) == nilai_mayoritas:
            self._clock_r2()
        if bit_ke(self.r3, 10) == nilai_mayoritas:
            self._clock_r3()

    def buat_keystream(self, jumlah_byte: int) -> bytes:
        """Membangkitkan keystream sejumlah byte yang diminta."""
        hasil = bytearray()
        for _ in range(jumlah_byte):
            nilai_byte = 0
            for posisi in range(8):
                self._clock_mayoritas()
                bit = bit_ke(self.r1, 18) ^ bit_ke(self.r2, 21) ^ bit_ke(self.r3, 22)
                nilai_byte |= bit << posisi
            hasil.append(nilai_byte)
        return bytes(hasil)


def xor_bytes(data_a: bytes, data_b: bytes) -> bytes:
    """Menerapkan XOR byte-per-byte antara dua data dengan panjang sama."""
    return bytes(nilai_a ^ nilai_b for nilai_a, nilai_b in zip(data_a, data_b, strict=True))


def enkripsi_a5_1(plainteks: bytes, kunci: int, nomor_frame: int) -> bytes:
    """Mengenkripsi atau mendekripsi dengan A5/1 dan operasi XOR."""
    keystream = A51(kunci, nomor_frame).buat_keystream(len(plainteks))
    return xor_bytes(plainteks, keystream)


if __name__ == "__main__":
    plainteks = b"Demo A5/1 untuk materi kuliah."
    kunci = secrets.randbits(PANJANG_KUNCI_BIT)
    nomor_frame = secrets.randbits(PANJANG_FRAME_BIT)

    print("=" * 65)
    print("DEMONSTRASI A5/1 - HISTORIS, JANGAN DIGUNAKAN DI PRODUKSI")
    print("=" * 65)
    cipherteks = enkripsi_a5_1(plainteks, kunci, nomor_frame)
    hasil_dekripsi = enkripsi_a5_1(cipherteks, kunci, nomor_frame)

    print(f"Plainteks    : {plainteks.decode()}")
    print(f"Kunci 64-bit : {kunci:016x}")
    print(f"Nomor frame : {nomor_frame}")
    print(f"Cipherteks  : {cipherteks.hex()}")
    print(f"Dekripsi berhasil? {hasil_dekripsi == plainteks}")
    print("A5/1 rentan terhadap serangan modern; gunakan ChaCha20-Poly1305 atau AES-GCM.")