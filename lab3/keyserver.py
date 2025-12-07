import socket
import threading
from utils import naplozas, json_kuldes, json_fogadas, Szin

KEYSERVER_HOST = 'localhost'
KEYSERVER_PORT = 8000

class KeyServer:
    """
    A KeyServer egy központi "telefonkönyv".
    A kliensek itt regisztrálják a publikus kulcsaikat, és innen kérik le másokét.
    NEM végez titkosítást, csak tárolja a kulcsokat.
    """
    def __init__(self, port=KEYSERVER_PORT):
        self.host = KEYSERVER_HOST
        self.port = port
        # Adattároló: { "kliens_id": "PEM_formátumú_publikus_kulcs" }
        self.kulcs_adatbazis = {}
        self.running = True
        naplozas("KEYSERVER", f"Szerver inicializálva a {self.port} porton.", Szin.HEADER)

    def start(self):
        """Elindítja a szervert egy külön szálban, hogy ne blokkolja a főprogramot."""
        server_thread = threading.Thread(target=self._listen_loop)
        server_thread.daemon = True
        server_thread.start()

    def _listen_loop(self):
        """
        A szerver fő ciklusa.
        Folyamatosan várja a bejövő kapcsolatokat a megadott porton.
        """
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
     
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((self.host, self.port))
            s.listen()
            naplozas("KEYSERVER", "Várakozás kliensekre...", Szin.HEADER)
            
            while self.running:
                try:
                    # Blokkoló hívás: itt áll a program, amíg valaki nem csatlakozik
                    conn, addr = s.accept()
                    # Minden klienst külön szálban szolgálunk ki
                    client_handler = threading.Thread(target=self._handle_client, args=(conn, addr))
                    client_handler.start()
                except OSError:
                    break

    def _handle_client(self, conn, addr):
        """
        Egy kliens kérésének feldolgozása.
        """
        with conn:
            # JSON üzenet beolvasása
            request = json_fogadas(conn)
            if not request:
                return

            req_type = request.get("tipus")
            client_id = str(request.get("kliens_id"))

            # 1. ESET: Regisztráció
            # A kliens elküldi az ID-ját és a publikus kulcsát.
            if req_type == "REGISZTRACIO":
                pem_key = request.get("publikus_kulcs")
                # Eltároljuk az adatbázisban
                self.kulcs_adatbazis[client_id] = pem_key
                naplozas("KEYSERVER", f"Regisztráció: Kliens[{client_id}]", Szin.OKGREEN)
                # Visszaigazolást küldünk
                json_kuldes(conn, {"status": "OK", "uzenet": "Sikeres regisztráció"})

            # 2. ESET: Kulcs lekérése
            # A kliens elküldi, kinek a kulcsára kíváncsi (cel_kliens_id).
            elif req_type == "KULCS_LEKERES":
                target_id = str(request.get("cel_kliens_id"))
                # Megkeressük az adatbázisban
                target_key = self.kulcs_adatbazis.get(target_id)
                
                if target_key:
                    # Ha megvan, elküldjük
                    json_kuldes(conn, {"status": "OK", "publikus_kulcs": target_key})
                else:
                    # Ha nincs, hibaüzenetet küldünk
                    naplozas("KEYSERVER", f"HIBA: Kliens[{target_id}] nem található.", Szin.WARNING)
                    json_kuldes(conn, {"status": "ERROR", "uzenet": "Kliens nem található"})

    def stop(self):
        """Leállítja a szervert."""
        self.running = False
        # Ébresztő hívás a socketnek, hogy kilépjen az accept()-ből
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((self.host, self.port))
        except:
            pass
        naplozas("KEYSERVER", "Szerver leállítva.", Szin.HEADER)
