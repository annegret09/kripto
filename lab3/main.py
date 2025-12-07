import time
import threading
from keyserver import KeyServer
from client import Kliens

def main():
    """
    Ez a főprogram, ami szimulálja a teljes rendszer működését.
    Kliens-szerver kommunikácció
    """

    # 1. KeyServer indítása, ahol a kliensek megtalálják egymást.
    ks = KeyServer()
    ks.start()
    time.sleep(1)


    # Két klienst hozunk létre
    c1_port = 8001
    c2_port = 8002
    
    client1 = Kliens(kliens_id=c1_port, port=c1_port)
    client2 = Kliens(kliens_id=c2_port, port=c2_port)
    time.sleep(1)

    print("\n" + "="*50)
    print("--- 1. FÁZIS: Regisztráció a KeyServernél ---")
    print("="*50)
    # Publikus kulcsát a szerverre.
    client1.regisztracio_keyservernel()
    client2.regisztracio_keyservernel()
    time.sleep(0.5)

    print("\n" + "="*50)
    print("--- 2. FÁZIS: Kulcsok cseréje (KeyServeren át) ---")
    print("="*50)
    # Meg kell szerezniük a másik publikus kulcsát, Keyserverről ID alapján
    client1.partner_kulcsanak_lekerese(c2_port)
    client2.partner_kulcsanak_lekerese(c1_port)
    time.sleep(0.5)

    print("\n" + "="*50)
    print("--- 3. FÁZIS: Handshake (P2P Kézfogás) ---")
    print("="*50)
    # Itt történik a titkosított csatorna felépítése.
    # 1. Megegyeznek az algoritmusban (AES-CBC).
    # 2. Kicserélik a titkos kulcs darabjait RSA-val védve.
    # 3. Kiszámolják a közös kulcsot.
    
    # A Client 1 kapcsolatot kezd a Client 2 felé.
    success = client1.kapcsolat_es_handshake(partner_id=c2_port, partner_port=c2_port)
    
    if success:
        time.sleep(1)
        print("\n" + "="*50)
        print("--- 4. FÁZIS: Titkosított kommunikáció (Kétirányú) ---")
        print("="*50)

        msg1 = "Bla" * 150
        msg2 = "LALA" * 150
        
        # 1. KÖR: C1 küld C2-nek
        print("\n[TESZT] C1 küld C2-nek:")
        client1.uzenet_kuldes(msg1)
        time.sleep(0.5)
        
        # 2. KÖR: C2 válaszol C1-nek
        print("\n[TESZT] C2 küld C1-nek:")
        client2.uzenet_kuldes(msg2)
        time.sleep(0.5)
        
        # 3. KÖR: C1 újra küld 
        print("\n[TESZT] C1 küld C2-nek (2. kör - Hosszú üzenet ismétlése):")
        client1.uzenet_kuldes("Második kör: " + msg1)
        time.sleep(0.5)

        # 4. KÖR: C2 újra válaszol
        print("\n[TESZT] C2 küld C1-nek (2. kör - Hosszú üzenet ismétlése):")
        client2.uzenet_kuldes("Második kör: " + msg2)
        time.sleep(1)

    print("\n" + "="*50)
    print("--- Leállítás ---")
    print("="*50)

    client1.stop()
    client2.stop()
    ks.stop()

if __name__ == "__main__":
    main()
