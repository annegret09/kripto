import socket
import threading
import time
from utils import naplozas, json_kuldes, json_fogadas, Szin
from crypto_lib import KriptoModul
from keyserver import KEYSERVER_HOST, KEYSERVER_PORT

class Kliens:
    def __init__(self, kliens_id, port):
        # A kliens egyedi azonosítója
        self.id = str(kliens_id)
        # A port, amin a kliens a saját P2P szerverét futtatja, masok is elérjék
        self.port = port
        self.host = 'localhost'
        # Naplózáshoz
        self.log_nev = f"KLIENS-{self.id}"
        
        # 1. LÉPÉS: RSA kulcspár generálása indításkor
        # Ez a titkos (privát) és a nyilvános (publikus) kulcs.
        # A privát kulcsot SOHA nem adjuk ki, ezzel fejtjük meg, amit nekünk küldtek.
        # A publikus kulcsot feltöltjük a KeyServerre, ezzel titkosítanak nekünk mások.
        self.privat_kulcs, self.publikus_kulcs = KriptoModul.rsa_kulcspar_generalas()
        
        # A támogatott szimmetrikus algoritmusok listája 
        self.tamogatott_algoritmusok = ["AES-CBC", "AES-ECB"] 
        
        # Itt tároljuk majd a partner adatait, ha kommunikálunk valakivel
        self.partner_publikus_kulcsa = None      # A partner RSA publikus kulcsa (titkosításhoz)
        self.egyeztetett_szimmetrikus_kulcs = None # AES-hez
        self.egyeztetett_algoritmus = None       # mód
        self.running = True   
        
        # Az aktív TCP kapcsolat a partnerrel. Ezen megy az adat.
        self.active_connection = None
        
        naplozas(self.log_nev, f"Inicializálva a {self.port} porton.", Szin.OKBLUE)
        
        # Elindítjuk a saját szerverünket, hogy más kliensek tudjanak csatlakozni hozzánk.
        self._szerver_inditasa_p2p_hez()

    def _szerver_inditasa_p2p_hez(self):
        thread = threading.Thread(target=self._p2p_listen_loop)
        thread.daemon = True # Ha a főprogram leáll, ez a szál is leáll
        thread.start()

    def _p2p_listen_loop(self):
        """
        Ez a ciklus folyamatosan fut a háttérben és várja a bejövő kapcsolatokat.
        Ez teszi lehetővé, hogy a kliens "szerverként" is viselkedjen.
        """
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            # Beállítjuk, hogy újra lehessen használni a portot 
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((self.host, self.port))
            s.listen()
            
            while self.running:
                try:
                    # Itt várakozunk, amíg valaki nem csatlakozik
                    conn, addr = s.accept()
                    # Ha valaki csatlakozott, egy ÚJ szálat indítunk a kezelésére.
                    # Így egyszerre több kapcsolatot is tudnánk fogadni
                    handler = threading.Thread(target=self._handle_incoming_p2p, args=(conn, addr))
                    handler.start()
                except OSError:
                    # Ha a socketet bezárják, kilépünk a ciklusból
                    break

    def _handle_incoming_p2p(self, conn, addr):
        """
        Ez a függvény kezeli le, ha valaki csatlakozott hozzánk.
        Eldönti, hogy ez egy új kézfogás vagy más.
        """
        naplozas(self.log_nev, f"Kapcsolat fogadva: {addr}")
        
        # Elolvassuk az első üzenetet, amit a csatlakozó fél küldött
        request = json_fogadas(conn)
        if not request:
            conn.close()
            return

        req_type = request.get("tipus")
        
        # Ha a kapcsolat célja a kézfogás indítása:
        if req_type == "HANDSHAKE_INIT":
            # Meghívjuk a kézfogást kezelő logikát 
            success = self._folyamat_handshake_fogadasa(conn, request)
            if success:
                # Ha sikeres volt a kézfogás, elmentjük a kapcsolatot
                self.active_connection = conn
                # És átlépünk az üzenetfigyelő módba ezen a kapcsolaton
                self._uzenet_figyelo_loop(conn)
        else:
            naplozas(self.log_nev, f"Váratlan üzenet: {req_type}", Szin.WARNING)
            conn.close()

    # --- KeyServer Kommunikáció ---

    def regisztracio_keyservernel(self):
        """
        Felküldi a saját publikus kulcsunkat a KeyServernek.
        Így mások megtalálhatnak minket az ID-nk alapján.
        """
        try:
            # Csatlakozunk a KeyServerhez
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((KEYSERVER_HOST, KEYSERVER_PORT))
                
                # PEM formátumra (szöveges) alakítjuk a kulcsot a küldéshez
                pem = KriptoModul.publikus_kulcs_pemre(self.publikus_kulcs)
                
                # Összeállítjuk a kérést
                req = {
                    "tipus": "REGISZTRACIO",
                    "kliens_id": self.id,
                    "publikus_kulcs": pem
                }
                json_kuldes(s, req)
                
                # Várjuk a nyugtázást
                resp = json_fogadas(s)
                naplozas(self.log_nev, f"Regisztráció: {resp.get('uzenet')}", Szin.OKGREEN)
        except Exception as e:
            naplozas(self.log_nev, f"Regisztrációs hiba: {e}", Szin.FAIL)

    def partner_kulcsanak_lekerese(self, partner_id):
        """
        Lekéri egy másik kliens publikus kulcsát a KeyServerről az ID alapján.
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((KEYSERVER_HOST, KEYSERVER_PORT))
                req = {
                    "tipus": "KULCS_LEKERES",
                    "kliens_id": self.id,
                    "cel_kliens_id": str(partner_id)
                }
                json_kuldes(s, req)
                resp = json_fogadas(s)
                
                if resp and resp.get("status") == "OK":
                    # Ha megkaptuk, visszaalakítjuk szövegből kulcs objektummá
                    pem = resp.get("publikus_kulcs")
                    self.partner_publikus_kulcsa = KriptoModul.pem_publikus_kulcsra(pem)
                    naplozas(self.log_nev, f"Partner[{partner_id}] kulcsa letöltve.", Szin.OKGREEN)
                    return True
                return False
        except Exception:
             return False

    # --- Handshake -----
    # Ezt hívjuk meg, ha MI akarunk beszélgetni valakivel.

    def kapcsolat_es_handshake(self, partner_id, partner_port):
        # Ellenőrzés: Megvan-e a partner RSA kulcsa
        if not self.partner_publikus_kulcsa:
            naplozas(self.log_nev, "HIBA: Nincs partner kulcs!", Szin.FAIL)
            return False

        naplozas(self.log_nev, f"Handshake indítása -> Kliens[{partner_id}]", Szin.HEADER)
        
        try:
            # Létrehozunk egy socketet és csatlakozunk a partnerhez
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((self.host, partner_port))

            # 1. LÉPÉS: Elküldjük, milyen algoritmusokat támogatunk (pl. AES-CBC)
            req = {
                "tipus": "HANDSHAKE_INIT",
                "kuldo_id": self.id,
                "algoritmusok": self.tamogatott_algoritmusok
            }
            json_kuldes(sock, req)

            # 2. LÉPÉS: Várjuk a választ.
            # A partner választ egy algoritmust, és küld egy titkosított "Secret B"-t.
            resp = json_fogadas(sock)
            if not resp or resp.get("tipus") != "HANDSHAKE_RESPONSE":
                return False

            self.egyeztetett_algoritmus = resp.get("valasztott_algoritmus")
            enc_secret_b_hex = resp.get("titkositott_secret_b")
            
            # A kapott Secret B-t a SAJÁT privát kulcsunkkal fejtjük meg.
            secret_b = KriptoModul.rsa_visszafejtes(self.privat_kulcs, bytes.fromhex(enc_secret_b_hex))
            
            # 3. LÉPÉS: Generálunk egy saját "Secret A"-t.
            secret_a = KriptoModul.random_titkos(16)
            
            # Ezt titkosítjuk a PARTNER publikus kulcsával 
            enc_secret_a = KriptoModul.rsa_titkositas(self.partner_publikus_kulcsa, secret_a)
            
            # Elküldjük a titkosított Secret A-t a partnernek.
            req_finish = {
                "tipus": "HANDSHAKE_FINISH",
                "titkositott_secret_a": enc_secret_a.hex()
            }
            json_kuldes(sock, req_finish)
            
            # 4. LÉPÉS: Közös kulcs kiszámítása.
            # Mindkét félnek megvan most már a Secret A és a Secret B.
            # A közös kulcs ezek XOR összege lesz.
            self.egyeztetett_szimmetrikus_kulcs = KriptoModul.xor_bytes(secret_a, secret_b)
            naplozas(self.log_nev, f"Kézfogás KÉSZ. Algo: {self.egyeztetett_algoritmus}", Szin.OKGREEN)
            
            # Elmentjük a kapcsolatot, hogy ezen küldjünk üzeneteket
            self.active_connection = sock
            
            # Elindítjuk a figyelő szálat ezen a kapcsolaton is
            threading.Thread(target=self._uzenet_figyelo_loop, args=(sock,), daemon=True).start()
            return True

        except Exception as e:
             naplozas(self.log_nev, f"Handshake hiba: {e}", Szin.FAIL)
             if sock: sock.close()
             return False

    # --- Handshake ---
    # Ezt hívja meg a _handle_incoming_p2p, ha valaki hozzánk csatlakozik.

    def _folyamat_handshake_fogadasa(self, conn, request):
        partner_algok = request.get("algoritmusok")
        partner_id = request.get("kuldo_id")
        
        # 1. LÉPÉS: Algoritmus választás.
        # Megnézzük, mi a közös a mi listánk és a partner listája között.
        kozos = next((a for a in self.tamogatott_algoritmusok if a in partner_algok), None)
        if not kozos:
             return False
        self.egyeztetett_algoritmus = kozos

        # 2. LÉPÉS: Secret B generálása.
        secret_b = KriptoModul.random_titkos(16)
        
        # Ellenőrizzük, megvan-e a partner kulcsa. Ha nincs, gyorsan lekérjük.
        if not self.partner_publikus_kulcsa:
             naplozas(self.log_nev, f"Partner kulcs hiányzik, lekérés...", Szin.WARNING)
             self.partner_kulcsanak_lekerese(partner_id)
        
        # Titkosítjuk a Secret B-t a PARTNER publikus kulcsával.
        enc_secret_b = KriptoModul.rsa_titkositas(self.partner_publikus_kulcsa, secret_b)
        
        # Elküldjük a választ: a választott algoritmust és a titkosított Secret B-t.
        resp = {
            "tipus": "HANDSHAKE_RESPONSE",
            "valasztott_algoritmus": self.egyeztetett_algoritmus,
            "titkositott_secret_b": enc_secret_b.hex()
        }
        json_kuldes(conn, resp)
        
        # 3. LÉPÉS: Várjuk a Secret A-t a partnertől.
        req_finish = json_fogadas(conn)
        if not req_finish or req_finish.get("tipus") != "HANDSHAKE_FINISH":
            return False
            
        # Megkaptuk a titkosított Secret A-t.
        enc_secret_a_hex = req_finish.get("titkositott_secret_a")
        # Visszafejtjük a SAJÁT privát kulcsunkkal.
        secret_a = KriptoModul.rsa_visszafejtes(self.privat_kulcs, bytes.fromhex(enc_secret_a_hex))
        
        # 4. LÉPÉS: Közös kulcs kiszámítása (XOR).
        self.egyeztetett_szimmetrikus_kulcs = KriptoModul.xor_bytes(secret_a, secret_b)
        naplozas(self.log_nev, f"Kézfogás (fogadó) KÉSZ.", Szin.OKGREEN)
        return True

    # --- Kommunikáció (Üzenetküldés és Fogadás) ---

    def _uzenet_figyelo_loop(self, sock):
        """
        Ez a ciklus folyamatosan figyeli az aktív kapcsolatot.
        Ha jön adat, azt megpróbálja visszafejteni.
        """
        while self.running:
            try:
                msg = json_fogadas(sock)
                if not msg: break # Ha megszakad a kapcsolat, kilépünk
                
                if msg.get("tipus") == "TITKOSITOTT_UZENET":
                    # Kinyerjük a hexadecimális titkosított adatot
                    adat_hex = msg.get("adat_hex")
                    titkos_csomag = bytes.fromhex(adat_hex)
                    
                    # Visszafejtjük a közös szimmetrikus kulccsal (AES)
                    tiszta = KriptoModul.szimmetrikus_visszafejtes(
                        self.egyeztetett_szimmetrikus_kulcs,
                        titkos_csomag,
                        algoritmus="AES", 
                        mod="CBC"
                    )
                    # Kiírjuk a titkosított adatot is, hogy lássuk a titkosítást
                    naplozas(self.log_nev, f"BEJÖVŐ ADAT (TITKOS): {adat_hex[:30]}...", Szin.WARNING)
                    naplozas(self.log_nev, f"      -> VISSZAFEJTVE: {tiszta[:40]}...", Szin.OKCYAN)
            except:
                break
        naplozas(self.log_nev, "Kapcsolat lezárult.", Szin.WARNING)

    def uzenet_kuldes(self, tiszta_szoveg):
        """
        Titkosított üzenet küldése a partnernek.
        """
        if not self.active_connection:
            return
        
        # 1. Titkosítjuk a szöveget a közös kulccsal (AES-CBC)
        # Ez visszaadja az IV-t és a titkosított adatot összefűzve.
        titkos_csomag = KriptoModul.szimmetrikus_titkositas(
            self.egyeztetett_szimmetrikus_kulcs,
            tiszta_szoveg,
            algoritmus="AES",
            mod="CBC"
        )
        
        # 2. Becsomagoljuk JSON-be és elküldjük
        req = {
            "tipus": "TITKOSITOTT_UZENET",
            "adat_hex": titkos_csomag.hex() # Hex stringként küldjük a bináris adatot
        }
        json_kuldes(self.active_connection, req)
        
        # Kiírjuk, mit küldünk valójában
        naplozas(self.log_nev, f"KIMENŐ ADAT (TITKOS): {titkos_csomag.hex()[:30]}...", Szin.WARNING)
        naplozas(self.log_nev, f"      -> EREDETI: {tiszta_szoveg[:40]}...", Szin.OKBLUE)

    def stop(self):
        """Leállítja a klienst és a szálakat."""
        self.running = False
        # Egy "kamu" csatlakozással felébresztjük a listen loop-ot, hogy kilépjen
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((self.host, self.port))
        except: pass
        
        if self.active_connection:
            try: self.active_connection.close()
            except: pass
