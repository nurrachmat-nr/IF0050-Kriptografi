"""
Pertemuan 12 - Kriptografi Aplikatif: Password Hashing & Keamanan Blockchain
Implementasi blockchain sederhana untuk memahami PERAN FUNGSI HASH (Pertemuan 7)
dalam menjaga integritas rantai blok, serta mekanisme Proof-of-Work sederhana.

Hanya untuk tujuan edukasi -- blockchain produksi (Bitcoin, Ethereum, dst.)
jauh lebih kompleks (jaringan terdistribusi, konsensus, dsb).
"""

import hashlib
import time


class Blok:
    def __init__(self, index: int, data: str, hash_sebelumnya: str):
        self.index = index
        self.timestamp = time.time()
        self.data = data
        self.hash_sebelumnya = hash_sebelumnya
        self.nonce = 0
        self.hash = self.hitung_hash()

    def hitung_hash(self) -> str:
        isi = f"{self.index}{self.timestamp}{self.data}{self.hash_sebelumnya}{self.nonce}"
        return hashlib.sha256(isi.encode()).hexdigest()

    def tambang(self, kesulitan: int):
        """Proof-of-Work: cari nonce sehingga hash diawali N nol (mirip Bitcoin)."""
        target = "0" * kesulitan
        while not self.hash.startswith(target):
            self.nonce += 1
            self.hash = self.hitung_hash()


class Blockchain:
    def __init__(self, kesulitan: int = 4):
        self.kesulitan = kesulitan
        self.rantai = [self._buat_blok_genesis()]

    def _buat_blok_genesis(self) -> Blok:
        blok = Blok(0, "Blok Genesis", "0" * 64)
        blok.tambang(self.kesulitan)
        return blok

    def tambah_blok(self, data: str) -> Blok:
        blok_sebelumnya = self.rantai[-1]
        blok_baru = Blok(len(self.rantai), data, blok_sebelumnya.hash)
        blok_baru.tambang(self.kesulitan)
        self.rantai.append(blok_baru)
        return blok_baru

    def validasi(self) -> bool:
        """Integritas rantai bergantung PENUH pada sifat fungsi hash (Pertemuan 7)."""
        for i in range(1, len(self.rantai)):
            blok_ini, blok_sebelumnya = self.rantai[i], self.rantai[i - 1]
            if blok_ini.hash != blok_ini.hitung_hash():
                return False  # data blok ini telah diubah
            if blok_ini.hash_sebelumnya != blok_sebelumnya.hash:
                return False  # rantai ke blok sebelumnya terputus
        return True


if __name__ == "__main__":
    KESULITAN = 4  # hash harus diawali 4 digit nol -- makin besar, makin lama menambang

    print("=" * 65)
    print(f"MENAMBANG BLOCKCHAIN (Proof-of-Work, kesulitan={KESULITAN})")
    print("=" * 65)
    mulai = time.perf_counter()
    rantai = Blockchain(kesulitan=KESULITAN)
    rantai.tambah_blok("Alice mengirim 5 BTC ke Bob")
    rantai.tambah_blok("Bob mengirim 2 BTC ke Charlie")
    durasi = time.perf_counter() - mulai

    for blok in rantai.rantai:
        print(f"Blok #{blok.index} | nonce={blok.nonce:>7} | hash={blok.hash[:20]}...")
    print(f"\nWaktu menambang 3 blok: {durasi:.2f} detik")

    print()
    print("=" * 65)
    print("VALIDASI RANTAI: APAKAH SEMUA BLOK UTUH DAN TERHUBUNG?")
    print("=" * 65)
    print(f"Rantai valid? {rantai.validasi()}")

    print()
    print("=" * 65)
    print("SKENARIO SERANGAN: MENGUBAH DATA PADA BLOK #1 SECARA DIAM-DIAM")
    print("=" * 65)
    rantai.rantai[1].data = "Alice mengirim 500 BTC ke Bob"  # manipulasi!
    print(f"Data blok #1 diubah menjadi: \"{rantai.rantai[1].data}\"")
    print("(hash pada objek TIDAK dihitung ulang -- persis seperti penyerang")
    print(" yang mencoba mengubah data tanpa menambang ulang blok tersebut)")
    print(f"Rantai valid setelah manipulasi? {rantai.validasi()}")
    print(">> Manipulasi TERDETEKSI karena hash blok #1 tidak lagi cocok dengan isinya.")
    print(">> Untuk 'berhasil' memanipulasi, penyerang harus menambang ULANG blok #1")
    print(">> DAN seluruh blok setelahnya -- inilah yang membuat blockchain sulit diubah.")
