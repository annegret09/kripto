import json
import socket
from enum import Enum

class Szin:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

def naplozas(szereplo, uzenet, szin=Szin.ENDC):
    prefix = f"[{szereplo}]".ljust(15)
    print(f"{szin}{prefix} {uzenet}{Szin.ENDC}")

def json_kuldes(sock, adat_dict):
     try:
        uzenet = json.dumps(adat_dict) + "\n"
        sock.sendall(uzenet.encode('utf-8'))
    except Exception as e:
        naplozas("SOCKET", f"Hiba a JSON küldésekor: {e}", Szin.FAIL)

def json_fogadas(sock):
    try:
        f = sock.makefile('r')
        sor = f.readline()
        if not sor:
            return None
        return json.loads(sor.strip())
    except json.JSONDecodeError:
        naplozas("SOCKET", "Hiba: Nem valid JSON érkezett.", Szin.FAIL)
        return None
    except Exception as e:
        naplozas("SOCKET", f"Hiba a JSON fogadásakor: {e}", Szin.FAIL)
        return None
