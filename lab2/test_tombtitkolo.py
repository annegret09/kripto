import os
import json
import binascii
import pytest
from tombtitkolo import titkosit_visszafejt_memoria

@pytest.fixture(scope="session")
def bemeno_fajl():
    fajl = "kep.jpg"
    assert os.path.exists(fajl), "Nem található a kep.jpg fájl!"
    return fajl

@pytest.fixture(scope="session")
def sablon_konfig():
    with open("config.json", "r", encoding="utf-8") as f:
        return json.load(f)

ALGOK = [
    ("AES", "4145534b756c63733132333435363738"),
    ("CUSTOM", "53616a61744b756c6373313233343536")
]

MODOK = ["ECB", "CBC", "CFB", "OFB", "CTR"]
PADDINGOK = ["zero", "des", "schneier-ferguson"]

@pytest.mark.parametrize("alg,mod,padding", [
    (alg, mod, padnev) for alg, _ in ALGOK for mod in MODOK for padnev in PADDINGOK
])
def test_titkosit_visszafejt_memoria(bemeno_fajl, sablon_konfig, alg, mod, padding):
    """
    Teszteli a titkosítás és visszafejtés helyességét memóriában.
    Minden kombináció: 2 algoritmus × 5 mód × 3 padding = 30 teszt.
    """
    kulcs_hex = dict(ALGOK)[alg]
    
    # Konfiguráció összeállítása
    konfig = {
        "blokkméret_bitek": sablon_konfig["blokkméret_bitek"],
        "algoritmus": alg,
        "kulcs_hex": kulcs_hex,
        "mód": mod,
        "padding": padding
    }
    
    # IV hozzáadása ha szükséges
    if mod != "ECB":
        konfig["iv_hex"] = sablon_konfig.get("iv_hex")
    else:
        konfig["iv_hex"] = None

    # Bemenet olvasása
    with open(bemeno_fajl, "rb") as f:
        adat = f.read()

    # Titkosítás és visszafejtés memóriában
    titkos, vissza = titkosit_visszafejt_memoria(konfig, adat)
    
    # Ellenőrzés
    assert adat == vissza, f"Hiba: {alg} {mod} {padding} - visszafejtés nem egyezik!"
    assert len(titkos) > 0, f"Titkosított adat üres: {alg} {mod} {padding}"
