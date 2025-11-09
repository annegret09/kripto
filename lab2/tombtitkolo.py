from typing import Optional, Tuple
import json
import binascii
from Crypto.Cipher import AES

#Paddingok
def pad_zero(adat: bytes, blokk_b: int) -> bytes:
    pad = (-len(adat)) % blokk_b
    return adat + b'\x00' * pad

def unpad_zero(adat: bytes) -> bytes:
    return adat.rstrip(b'\x00')

def pad_desbit(adat: bytes, blokk_b: int) -> bytes:
    pad = (-len(adat)) % blokk_b
    if pad == 0:
        pad = blokk_b
    # első pad byte 0x80, a többi 0x00
    return adat + b'\x80' + b'\x00' * (pad - 1)

def unpad_desbit(adat: bytes) -> bytes:
    idx = adat.rfind(b'\x80')
    if idx == -1:
        # visszaadjuk az eredetit
        return adat
    return adat[:idx]

def pad_schneier(adat: bytes, blokk_b: int) -> bytes:
    pad = (-len(adat)) % blokk_b
    if pad == 0:
        pad = blokk_b
    return adat + bytes([pad]) * pad

def unpad_schneier(adat: bytes) -> bytes:
    if len(adat) == 0:
        return adat
    last = adat[-1]
    if last == 0 or last > len(adat):
        return adat
    return adat[:-last]

# padding kiválasztó
def pad(adat: bytes, blokk_b: int, mód: str) -> bytes:
    mód = mód.lower()
    if mód == "zero":
        return pad_zero(adat, blokk_b)
    if mód == "des":
        return pad_desbit(adat, blokk_b)
    return pad_schneier(adat, blokk_b)

def unpad(adat: bytes, mód: str) -> bytes:
    mód = mód.lower()
    if mód == "zero":
        return unpad_zero(adat)
    if mód == "des":
        return unpad_desbit(adat)
    return unpad_schneier(adat)

# XOR szamlalo
def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def inc_counter(counter: bytes) -> bytes:
    val = int.from_bytes(counter, 'big')
    val = (val + 1) % (1 << (8 * len(counter)))
    return val.to_bytes(len(counter), 'big')

# Saját-algoritmus 
# egyszerű oktatási blokk-primitive: XOR + rotation + pos-eltolás
def custom_encrypt_block(blokk: bytes, kulcs: bytes) -> bytes:
    out = bytearray(len(blokk))
    for i, b in enumerate(blokk):
        k = kulcs[i % len(kulcs)]
        c = b ^ k
        # 3 bit left rotation
        c = ((c << 3) | (c >> 5)) & 0xFF
        c ^= (i * 31 + k) & 0xFF
        out[i] = c
    return bytes(out)

def custom_decrypt_block(blokk: bytes, kulcs: bytes) -> bytes:
    out = bytearray(len(blokk))
    for i, b in enumerate(blokk):
        k = kulcs[i % len(kulcs)]
        c = b ^ ((i * 31 + k) & 0xFF)
        # 3 bit right rotation (inverse)
        c = ((c >> 3) | ((c << 5) & 0xFF)) & 0xFF
        c ^= k
        out[i] = c
    return bytes(out)

# AES
def aes_encrypt_block(blokk: bytes, kulcs: bytes) -> bytes:
    cipher = AES.new(kulcs, AES.MODE_ECB)
    return cipher.encrypt(blokk)

def aes_decrypt_block(blokk: bytes, kulcs: bytes) -> bytes:
    cipher = AES.new(kulcs, AES.MODE_ECB)
    return cipher.decrypt(blokk)

#  Módok implementációi 
def ecb_encrypt(adat: bytes, enc_block, kulcs: bytes, blokk_b: int) -> bytes:
    out = bytearray()
    for i in range(0, len(adat), blokk_b):
        out += enc_block(adat[i:i+blokk_b], kulcs)
    return bytes(out)

def ecb_decrypt(adat: bytes, dec_block, kulcs: bytes, blokk_b: int) -> bytes:
    out = bytearray()
    for i in range(0, len(adat), blokk_b):
        out += dec_block(adat[i:i+blokk_b], kulcs)
    return bytes(out)

def cbc_encrypt(adat: bytes, enc_block, kulcs: bytes, blokk_b: int, iv: bytes) -> bytes:
    out = bytearray()
    prev = iv
    for i in range(0, len(adat), blokk_b):
        x = xor_bytes(adat[i:i+blokk_b], prev)
        c = enc_block(x, kulcs)
        out += c
        prev = c
    return bytes(out)

def cbc_decrypt(adat: bytes, dec_block, kulcs: bytes, blokk_b: int, iv: bytes) -> bytes:
    out = bytearray()
    prev = iv
    for i in range(0, len(adat), blokk_b):
        blk = adat[i:i+blokk_b]
        p = xor_bytes(dec_block(blk, kulcs), prev)
        out += p
        prev = blk
    return bytes(out)

def cfb_encrypt(adat: bytes, enc_block, kulcs: bytes, blokk_b: int, iv: bytes) -> bytes:
    out = bytearray()
    prev = iv
    for i in range(0, len(adat), blokk_b):
        stream = enc_block(prev, kulcs)
        c = xor_bytes(adat[i:i+blokk_b], stream)
        out += c
        prev = c
    return bytes(out)

def cfb_decrypt(adat: bytes, enc_block, kulcs: bytes, blokk_b: int, iv: bytes) -> bytes:
    out = bytearray()
    prev = iv
    for i in range(0, len(adat), blokk_b):
        stream = enc_block(prev, kulcs)
        p = xor_bytes(adat[i:i+blokk_b], stream)
        out += p
        prev = adat[i:i+blokk_b]
    return bytes(out)

def ofb_encrypt(adat: bytes, enc_block, kulcs: bytes, blokk_b: int, iv: bytes) -> bytes:
    out = bytearray()
    state = iv
    for i in range(0, len(adat), blokk_b):
        state = enc_block(state, kulcs)
        out += xor_bytes(adat[i:i+blokk_b], state[:len(adat[i:i+blokk_b])])
    return bytes(out)

# OFB és CTR dekódolása megegyezik a titkosítással
ofb_decrypt = ofb_encrypt

def ctr_encrypt(adat: bytes, enc_block, kulcs: bytes, blokk_b: int, iv: bytes) -> bytes:
    out = bytearray()
    counter = iv
    for i in range(0, len(adat), blokk_b):
        stream = enc_block(counter, kulcs)
        out += xor_bytes(adat[i:i+blokk_b], stream[:len(adat[i:i+blokk_b])])
        counter = inc_counter(counter)
    return bytes(out)

ctr_decrypt = ctr_encrypt

# fájl titkosítása és visszafejtése 
def betolt_konfig(konfig_fajl: str) -> dict:
    with open(konfig_fajl, 'r', encoding='utf-8') as f:
        return json.load(f)

def titkosit_visszafejt_memoria(konfig: dict, adat: bytes) -> Tuple[bytes, bytes]:
    """
    Titkosítás és visszafejtés memóriában (nem ír fájlt).
    Visszaadja: (titkosított_bytes, visszafejtett_bytes)
    """
    blokk_bitek = konfig['blokkméret_bitek']
    if blokk_bitek % 8 != 0:
        raise ValueError("blokkméret_bitek-nek 8 többszörösnek kell lennie")
    blokk_b = blokk_bitek // 8

    algoritmus = konfig['algoritmus'].upper()
    kulcs = binascii.unhexlify(konfig['kulcs_hex'])
    mod = konfig['mód'].upper()
    padding = konfig.get('padding', 'schneier-ferguson').lower()

    iv = None
    if 'iv_hex' in konfig and konfig['iv_hex'] is not None:
        iv = binascii.unhexlify(konfig['iv_hex'])
        if len(iv) != blokk_b:
            raise ValueError("IV mérete nem egyezik a blokk méretével")

    # blokk-primitive kiválasztása
    if algoritmus == 'AES':
        if len(kulcs) not in (16,24,32):
            if len(kulcs) < 16:
                kulcs = kulcs.ljust(16, b'\x00')
            elif len(kulcs) < 24:
                kulcs = kulcs.ljust(24, b'\x00')
            else:
                kulcs = kulcs[:32]
        enc_block = aes_encrypt_block
        dec_block = aes_decrypt_block
    else:
        enc_block = custom_encrypt_block
        dec_block = custom_decrypt_block

    # padding
    adat_pad = pad(adat, blokk_b, padding)

    # titkosítás mód szerint
    if mod == 'ECB':
        titkos = ecb_encrypt(adat_pad, enc_block, kulcs, blokk_b)
    elif mod == 'CBC':
        if iv is None: raise ValueError("CBC módhoz IV szükséges")
        titkos = cbc_encrypt(adat_pad, enc_block, kulcs, blokk_b, iv)
    elif mod == 'CFB':
        if iv is None: raise ValueError("CFB módhoz IV szükséges")
        titkos = cfb_encrypt(adat_pad, enc_block, kulcs, blokk_b, iv)
    elif mod == 'OFB':
        if iv is None: raise ValueError("OFB módhoz IV szükséges")
        titkos = ofb_encrypt(adat_pad, enc_block, kulcs, blokk_b, iv)
    elif mod == 'CTR':
        if iv is None: raise ValueError("CTR módhoz IV szükséges")
        titkos = ctr_encrypt(adat_pad, enc_block, kulcs, blokk_b, iv)
    else:
        raise ValueError("Ismeretlen mód")

    # visszafejtés
    if mod == 'ECB':
        vissza_pad = ecb_decrypt(titkos, dec_block, kulcs, blokk_b)
    elif mod == 'CBC':
        vissza_pad = cbc_decrypt(titkos, dec_block, kulcs, blokk_b, iv)
    elif mod == 'CFB':
        vissza_pad = cfb_decrypt(titkos, enc_block, kulcs, blokk_b, iv)
    elif mod == 'OFB':
        vissza_pad = ofb_decrypt(titkos, enc_block, kulcs, blokk_b, iv)
    elif mod == 'CTR':
        vissza_pad = ctr_decrypt(titkos, enc_block, kulcs, blokk_b, iv)

    vissza = unpad(vissza_pad, padding)
    return titkos, vissza

def alk_titkosit_visszafejt(konfig: dict, bemenet_fajl: str, kiir_prefix: str) -> Tuple[str, str]:
    with open(bemenet_fajl, 'rb') as f:
        adat = f.read()
    
    titkos, vissza = titkosit_visszafejt_memoria(konfig, adat)
    
    algoritmus = konfig['algoritmus'].upper()
    mod = konfig['mód'].upper()
    
    # fájlok mentése
    titkos_fajl = f"{kiir_prefix}_{algoritmus}_{mod}.bin"
    with open(titkos_fajl, 'wb') as f:
        f.write(titkos)

    vissza_fajl = f"{kiir_prefix}_{algoritmus}_{mod}.dec"
    with open(vissza_fajl, 'wb') as f:
        f.write(vissza)

    return titkos_fajl, vissza_fajl
