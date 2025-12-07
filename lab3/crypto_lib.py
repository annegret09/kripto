import os
import sys
# A cryptography könyvtár importjai az RSA műveletekhez
from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

# --- Lab2 Integráció ---
# Hozzáadjuk a lab2 könyvtárat az útvonalhoz, hogy be tudjuk importálni a tombtitkolo.py-t
current_dir = os.path.dirname(os.path.abspath(__file__))
lab2_path = os.path.join(current_dir, '..', 'lab2')
sys.path.append(lab2_path)

try:
    import tombtitkolo
except ImportError:
    print("Nem sikerült importálni.")

from utils import naplozas, Szin

class KriptoModul:
    """
    Ez az osztály fogja össze az összes kriptográfiai műveletet.
    - RSA (Aszimmetrikus): A 'cryptography' könyvtárat használja.
    - AES (Szimmetrikus): A 'tombtitkolo' modult (Lab2) használja.
    """

    @staticmethod
    def rsa_kulcspar_generalas():
        """
        Létrehoz egy RSA-2048 privát és publikus kulcspárt.
        A privát kulcsot titokban kell tartani!
        """
        privat_kulcs = rsa.generate_private_key(
            public_exponent=65537, # Szabványos érték
            key_size=2048,         # 2048 bites kulcshossz (biztonságos)
            backend=default_backend()
        )
        publikus_kulcs = privat_kulcs.public_key()
        return privat_kulcs, publikus_kulcs

    @staticmethod
    def publikus_kulcs_pemre(publikus_kulcs):
        """
        A publikus kulcsot PEM formátumú szöveggé alakítja.
        Ez szükséges ahhoz, hogy el tudjuk küldeni a hálózaton (JSON-ben).
        """
        pem = publikus_kulcs.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pem.decode('utf-8')

    @staticmethod
    def pem_publikus_kulcsra(pem_string):
        """
        A kapott PEM szöveget visszaalakítja használható kulcs objektummá.
        """
        try:
            return serialization.load_pem_public_key(
                pem_string.encode('utf-8'),
                backend=default_backend()
            )
        except Exception as e:
            naplozas("KRIPTO", f"Hiba a PEM kulcs betöltésekor: {e}", Szin.FAIL)
            return None

    @staticmethod
    def rsa_titkositas(publikus_kulcs, tiszta_adat_bytes):
        """
        Adat titkosítása RSA publikus kulccsal.
        Ezt használjuk a 'Secret A' és 'Secret B' elküldéséhez.
        OAEP paddinget használunk a biztonság érdekében.
        """
        titkositott = publikus_kulcs.encrypt(
            tiszta_adat_bytes,
            rsa_padding.OAEP(   
                mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return titkositott

    @staticmethod
    def rsa_visszafejtes(privat_kulcs, titkositott_adat_bytes):
        """
        Adat visszafejtése a saját RSA privát kulcsunkkal.
        Csak mi tudjuk elolvasni, amit a publikus kulcsunkkal titkosítottak.
        """
        tiszta = privat_kulcs.decrypt(
            titkositott_adat_bytes,
            rsa_padding.OAEP(
                mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return tiszta

    @staticmethod
    def random_titkos(hossz=16):
        """Véletlenszerű bájtok generálása, hogy ne legyen kiszámítható"""
        return os.urandom(hossz)

    @staticmethod
    def xor_bytes(a, b):
        """
        Két bájtsorozat XOR-ozása.
        Ezt használjuk a közös kulcs előállításához.
        """
        length = min(len(a), len(b))
        return bytes(x ^ y for x, y in zip(a[:length], b[:length]))

    @staticmethod
    def szimmetrikus_titkositas(kulcs, tiszta_szoveg, algoritmus="AES", mod="CBC"):
        """
        Szimmetrikus titkosítás a lab2 tombtitkolo moduljával.
        Ez végzi a tényleges üzenetküldés titkosítását.
        Visszatér: iv + titkosított_adat (bytes)
        """
        # 1. IV (Inicializációs Vektor) generálás
        # Ez biztosítja, hogy ugyanaz az üzenet kétszer elküldve másképp nézzen ki.
        blokk_meret = 16 # AES esetén 16 bájt
        iv = os.urandom(blokk_meret)
        
        # 2. Padding (Kiegészítés)
        # Az AES blokkokban dolgozik, ezért a szöveg hosszának 16 többszörösének kell lennie.
        # A tombtitkolo.pad függvényt használjuk erre.
        padded_data = tombtitkolo.pad(tiszta_szoveg.encode('utf-8'), blokk_meret, "schneier")
        
        # 3. Titkosítás
        # Kiválasztjuk a megfelelő blokk-titkosító függvényt a lab2-ből.
        if algoritmus == "AES":
            enc_block = tombtitkolo.aes_encrypt_block
        else:
            # Ha nem AES, akkor a saját (custom) algoritmust használjuk
            enc_block = tombtitkolo.custom_encrypt_block

        # Meghívjuk a megfelelő mód (CBC, ECB) titkosító függvényét
        if mod == "CBC":
            titkos_adat = tombtitkolo.cbc_encrypt(padded_data, enc_block, kulcs, blokk_meret, iv)
        elif mod == "ECB":
            titkos_adat = tombtitkolo.ecb_encrypt(padded_data, enc_block, kulcs, blokk_meret)
            iv = b"" # ECB-hez nem kell IV, de a protokollunk várhatja
        else:
            raise ValueError(f"Nem támogatott mód: {mod}")
            
        # Visszaadjuk az IV-t és a titkosított adatot összefűzve.
        return iv + titkos_adat

    @staticmethod
    def szimmetrikus_visszafejtes(kulcs, titkositott_csomag, algoritmus="AES", mod="CBC"):
        """
        Szimmetrikus visszafejtés a lab2 tombtitkolo moduljával.
        Bemenet: iv + titkosított_adat (bytes)
        """
        blokk_meret = 16
        
        if mod == "CBC":
            # Szétválasztjuk az IV-t és a titkosított szöveget
            iv = titkositott_csomag[:blokk_meret]
            ciphertext = titkositott_csomag[blokk_meret:]
            
            if algoritmus == "AES":
                dec_block = tombtitkolo.aes_decrypt_block
            else:
                dec_block = tombtitkolo.custom_decrypt_block
                
            # Visszafejtés CBC módban
            padded_data = tombtitkolo.cbc_decrypt(ciphertext, dec_block, kulcs, blokk_meret, iv)
            
        elif mod == "ECB":
            ciphertext = titkositott_csomag
            if algoritmus == "AES":
                dec_block = tombtitkolo.aes_decrypt_block
            else:
                dec_block = tombtitkolo.custom_decrypt_block
            
            padded_data = tombtitkolo.ecb_decrypt(ciphertext, dec_block, kulcs, blokk_meret)
            
        else:
            raise ValueError(f"Nem támogatott mód: {mod}")

        # 4. Padding eltávolítása
        # Levágjuk a végéről a kiegészítő bájtokat, hogy visszakapjuk az eredeti szöveget.
        try:
            tiszta_data = tombtitkolo.unpad(padded_data, "schneier")
            return tiszta_data.decode('utf-8')
        except Exception as e:
            naplozas("KRIPTO", f"Hiba a padding eltávolításakor: {e}", Szin.FAIL)
            return "[HIBÁS ADAT]"
