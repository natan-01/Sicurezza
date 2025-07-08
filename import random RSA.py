# LIBRERIE NECESSARIE
import random      # Per generare numeri casuali
import math        # Operazioni matematiche
import sympy       # Per verificare se un numero è primo
import socket      # Per la comunicazione di rete
import threading   # Per gestire thread multipli
import json        # Per serializzare/deserializzare dati
import time        # Per timestamp e timeout
import sys         # Funzioni di sistema
import hashlib     # Per hash SHA-256
import pickle      # Per serializzare oggetti Python
import os          # Per operazioni sui file
from typing import Dict, Optional, Tuple  # Type hints


class RSAKeyGenerator:
    def __init__(self, bits=1024):
        self.bits = bits          # Dimensione della chiave in bits (default 1024)
    
    def _is_prime(self, n: int) -> bool:
        return sympy.isprime(n)     # Usa sympy per verificare se n è primo

    def generate_prime(self):
        """Genera un numero primo casuale di dimensione specificata"""
        while True:
            p = random.getrandbits(self.bits) # Genera numero casuale di self.bits bits
            p |= (1 << (self.bits - 1)) | 1 # Imposta MSB e LSB a 1 (numero dispari)
            if self._is_prime(p):       # Verifica se è primo
                return p

    def gcd(self, a, b):
        """Algoritmo di Euclide per calcolare il massimo comune divisore"""
        while b != 0:
            a, b = b, a % b
        return a

    def egcd(self, a, b):
        """Algoritmo di Euclide esteso - versione iterativa per evitare ricorsione"""
        old_a, old_b = a, b
        x0, x1 = 1, 0
        y0, y1 = 0, 1
        
        while b != 0:
            quotient = a // b
            a, b = b, a % b
            x0, x1 = x1, x0 - quotient * x1
            y0, y1 = y1, y0 - quotient * y1
        
        return (a, x0, y0)

    def modinv(self, a, m):
        """Calcola l'inverso modulare di a modulo m"""
        g, x, y = self.egcd(a, m)    # Usa Euclide esteso
        if g != 1:  # Se gcd != 1, inverso non esiste
            raise Exception('Modulo inverso non esiste')
        else:
            return x % m    # Ritorna l'inverso modulare

    def modular_exponentiation(self, base, exponent, modulus):
        """Esponenziazione modulare """
        if modulus == 1:
            return 0
        
        result = 1
        base = base % modulus
        
        while exponent > 0:
            if exponent % 2 == 1:       # Se esponente è dispari
                result = (result * base) % modulus  # Moltiplica risultato per base
            exponent = exponent >> 1    # Dimezza esponente (shift right)
            base = (base * base) % modulus  # Quadra la base
        
        return result

    def encrypt(self, message, public_key):
        """Cifra un messaggio usando la chiave pubblica RSA"""
        e, n = public_key   # Estrae esponente e modulo
        
        if message >= n:    # Verifica che messaggio < n
            raise ValueError(f"Il messaggio ({message}) deve essere minore di n ({n})")
        
        if message < 0: # Verifica che messaggio >= 0
            raise ValueError("Il messaggio deve essere un numero positivo")
        
        ciphertext = self.modular_exponentiation(message, e, n)  # Cifra: msg^e mod n
        return ciphertext

    def decrypt(self, ciphertext, private_key):
        """Decifra un messaggio usando la chiave privata RSA"""
        d, n = private_key  # Estrae esponente privato e modulo
        message = self.modular_exponentiation(ciphertext, d, n) # Decifra: cipher^d mod n
        return message

    def string_to_number(self, text):
        """Converte una stringa in un numero intero"""
        text_bytes = text.encode('utf-8')
        number = int.from_bytes(text_bytes, byteorder='big')
        return number

    def number_to_string(self, number):
        """Converte un numero intero in una stringa"""
        if number == 0:
            return ""
        
        byte_length = (number.bit_length() + 7) // 8
        text_bytes = number.to_bytes(byte_length, byteorder='big')
        text = text_bytes.decode('utf-8')
        return text
    """METODI PER STRINGHE LUNGHE"""
    def encrypt_string(self, text, public_key):
        """Cifra una stringa usando RSA"""
        e, n = public_key
        message_number = self.string_to_number(text)        # Converte stringa in numero
        
        if message_number >= n:                             # Se troppo grande
            return self._encrypt_large_string(text, public_key)  # Usa metodo per stringhe grandi
        
        ciphertext = self.encrypt(message_number, public_key)    # Cifra normalmente
        return [ciphertext]                                 # Ritorna lista con un elemento

def decrypt_string(self, ciphertext_blocks, private_key):
    """Decifra una lista di blocchi cifrati"""
    if len(ciphertext_blocks) == 1:                     # Se un solo blocco
        decrypted_number = self.decrypt(ciphertext_blocks[0], private_key)
        return self.number_to_string(decrypted_number)
    else:                                               # Se blocchi multipli
        return self._decrypt_large_string(ciphertext_blocks, private_key)

"""Metodi per stringhe grandi (divise in blocchi)"""
def _encrypt_large_string(self, text, public_key):
    """Cifra stringhe troppo grandi dividendole in blocchi"""
    e, n = public_key
    max_bytes = (n.bit_length() - 1) // 8 - 1          # Calcola dimensione massima blocco
    text_bytes = text.encode('utf-8')                   # Converte in bytes
    
    ciphertext_blocks = []
    for i in range(0, len(text_bytes), max_bytes):      # Divide in blocchi
        block = text_bytes[i:i + max_bytes]             # Estrae blocco
        block_number = int.from_bytes(block, byteorder='big')  # Converte in numero
        encrypted_block = self.encrypt(block_number, public_key)  # Cifra blocco
        ciphertext_blocks.append(encrypted_block)       # Aggiunge alla lista
    
    return ciphertext_blocks

    def _decrypt_large_string(self, ciphertext_blocks, private_key):
        """Decifra blocchi multipli"""
        decrypted_bytes = b''                               # Bytes decrittati
        
        for encrypted_block in ciphertext_blocks:           # Per ogni blocco cifrato
            decrypted_number = self.decrypt(encrypted_block, private_key)  # Decifra
            
            if decrypted_number == 0:                       # Se numero è 0
                block_bytes = b'\x00'                       # Byte nullo
            else:
                byte_length = (decrypted_number.bit_length() + 7) // 8
                block_bytes = decrypted_number.to_bytes(byte_length, byteorder='big')
            
            decrypted_bytes += block_bytes                   # Concatena bytes
        
        return decrypted_bytes.decode('utf-8')              # Decodifica UTF-8

    """Genera chiavi"""
    def find_random_coprime_e(self, phi):
        """Trova un esponente pubblico 'e' casuale che sia coprimo con phi"""
        max_attempts = 1000
        attempts = 0
        
        while attempts < max_attempts:
            e = random.randint(3, phi - 1)                  # Genera e casuale
            
            if self.gcd(e, phi) == 1:                       # Se coprimo con phi
                return e
            
            attempts += 1
        
        # Fallback a valori sicuri noti
        safe_values = [65537, 257, 17, 5, 3]
        
        for e in safe_values:                               # Prova valori sicuri
            if e < phi and self.gcd(e, phi) == 1:
                return e
        
        raise Exception("Impossibile trovare un esponente pubblico valido")

    def generate_keys(self):
        """Genera una coppia di chiavi RSA"""
        print("🔑 Generando chiavi RSA...")
        p = self.generate_prime()                           # Genera primo p
        q = self.generate_prime()                           # Genera primo q
        
        while q == p:                                       # Assicura che p != q
            q = self.generate_prime()
        
        n = p * q                                           # Calcola modulo n
        phi = (p - 1) * (q - 1)                            # Calcola φ(n)
        
        e = self.find_random_coprime_e(phi)                 # Trova esponente pubblico
        
        if self.gcd(e, phi) != 1:                          # Verifica che e sia coprimo con φ
            raise Exception(f"Errore: e={e} non è coprimo con phi={phi}")
        
        d = self.modinv(e, phi)                             # Calcola esponente privato
        
        if (e * d) % phi != 1:                             # Verifica che e*d ≡ 1 (mod φ)
            raise Exception("Errore nella verifica: (e * d) % phi != 1")
        
        public_key = (e, n)                                 # Chiave pubblica
        private_key = (d, n)                                # Chiave privata
        
        print("✅ Chiavi generate con successo!")
        return public_key, private_key


class RSAAuthenticator:
    """
    Sistema di autenticazione passwordless usando RSA con persistenza
    """
    
    def __init__(self, rsa_generator, storage_file="users.pkl"):
        self.rsa = rsa_generator
        self.storage_file = storage_file
        self.registered_users: Dict[str, Tuple[int, int]] = {}  # username -> (e, n)
        self.authenticated_users: Dict[str, float] = {}  # username -> timestamp
        self.session_timeout = 3600  # 1 ora in secondi
        self.lock = threading.Lock()  # Per thread safety
        
        # Carica utenti registrati da file
        self.load_users()
        
    def load_users(self):
        """Carica gli utenti registrati dal file di storage"""
        try:
            if os.path.exists(self.storage_file):
                with open(self.storage_file, 'rb') as f:
                    self.registered_users = pickle.load(f)
                print(f"📂 Caricati {len(self.registered_users)} utenti registrati")
            else:
                print("📂 Nessun file utenti esistente, creando nuovo database")
        except Exception as e:
            print(f"⚠️ Errore nel caricamento utenti: {e}")
            self.registered_users = {}
    
    def save_users(self):
        """Salva gli utenti registrati nel file di storage"""
        try:
            with open(self.storage_file, 'wb') as f:
                pickle.dump(self.registered_users, f)
        except Exception as e:
            print(f"⚠️ Errore nel salvataggio utenti: {e}")
    
    def register_user(self, username: str, public_key: Tuple[int, int]) -> bool:
        """Registra un nuovo utente associando username alla chiave pubblica"""
        with self.lock:
            if username in self.registered_users:
                return False
            
            self.registered_users[username] = public_key
            self.save_users()  # Salva immediatamente
            print(f"✅ Utente '{username}' registrato con successo")
            return True
    
    def user_exists(self, username: str) -> bool:
        """Controlla se un utente è già registrato"""
        with self.lock:
            return username in self.registered_users
    
    def generate_challenge(self) -> int:
        """Genera un challenge casuale per l'autenticazione"""
        return random.randint(10**10, 10**15)
    
    def create_challenge_for_user(self, username: str) -> Optional[Tuple[int, int]]:
        """Crea un challenge cifrato per un utente specifico"""
        with self.lock:
            if username not in self.registered_users:
                return None
            
            challenge = self.generate_challenge()
            user_public_key = self.registered_users[username]
            
            # Cifra il challenge con la chiave pubblica dell'utente
            encrypted_challenge = self.rsa.encrypt(challenge, user_public_key)
            
            return encrypted_challenge, challenge
    
    def verify_challenge_response(self, username: str, original_challenge: int, 
                                response: int) -> bool:
        """Verifica che il client abbia decrittato correttamente il challenge"""
        if response == original_challenge:
            # Autenticazione successful - registra la sessione
            with self.lock:
                self.authenticated_users[username] = time.time()
            return True
        return False
    
    def sign_message(self, message: str, private_key: Tuple[int, int]) -> int:
        """Firma un messaggio usando la chiave privata"""
        message_hash = hashlib.sha256(message.encode()).hexdigest()
        message_number = int(message_hash[:32], 16)  # Primi 32 char dell'hash
        
        # Firma = messaggio^d mod n
        signature = self.rsa.encrypt(message_number, private_key)
        return signature
    
    def verify_signature(self, message: str, signature: int, 
                        public_key: Tuple[int, int]) -> bool:
        """Verifica la firma di un messaggio"""
        try:
            message_hash = hashlib.sha256(message.encode()).hexdext()
            expected_number = int(message_hash[:32], 16)
            
            # Verifica: firma^e mod n dovrebbe dare il messaggio originale
            decrypted_signature = self.rsa.decrypt(signature, public_key) # Modifica qui
            
            return decrypted_signature == expected_number
        except:
            return False
    
    def is_user_authenticated(self, username: str) -> bool:
        """Controlla se un utente è attualmente autenticato"""
        with self.lock:
            if username not in self.authenticated_users:
                return False
            
            # Controlla timeout della sessione
            auth_time = self.authenticated_users[username]
            if time.time() - auth_time > self.session_timeout:
                del self.authenticated_users[username]
                return False
            
            return True
    
    def logout_user(self, username: str):
        """Effettua il logout di un utente"""
        with self.lock:
            if username in self.authenticated_users:
                del self.authenticated_users[username]
    
    def get_user_public_key(self, username: str) -> Optional[Tuple[int, int]]:
        """Ottiene la chiave pubblica di un utente"""
        with self.lock:
            return self.registered_users.get(username)


class ClientHandler:
    """Gestisce la connessione di un singolo client"""
    
    def __init__(self, client_socket, client_address, server):
        self.client_socket = client_socket
        self.client_address = client_address
        self.server = server
        self.rsa = server.rsa
        self.authenticator = server.authenticator
        self.client_public_key = None
        self.current_user = None
        self.authenticated = False
        self.running = True
        
    def handle_client(self):
        """Gestisce l'intera sessione del client"""
        try:
            print(f"🔗 Nuovo client connesso da {self.client_address}")
            
            # Scambio delle chiavi pubbliche
            self.exchange_public_keys()
            
            # Processo di autenticazione
            if self.handle_authentication():
                print(f"🔐 Autenticazione completata per utente: {self.current_user} da {self.client_address}")
                
                # Notifica agli altri client della nuova connessione
                self.server.broadcast_user_list()
                
                # Avvia la chat crittografata
                self.start_encrypted_chat()
            else:
                print(f"❌ Autenticazione fallita per {self.client_address}")
                
        except Exception as e:
            print(f"❌ Errore con client {self.client_address}: {e}")
        finally:
            self.cleanup()
    
    def exchange_public_keys(self):
        """Scambia le chiavi pubbliche con il client"""
        try:
            # Invia la propria chiave pubblica
            key_data = {
                'e': self.server.public_key[0],
                'n': self.server.public_key[1]
            }
            self.send_json_message(key_data)
            
            # Ricevi la chiave pubblica del client
            client_key_data = self.receive_json_message()
            self.client_public_key = (client_key_data['e'], client_key_data['n'])
            print(f"🔑 Chiave pubblica client ricevuta da {self.client_address}")
            
        except Exception as e:
            print(f"❌ Errore nello scambio chiavi con {self.client_address}: {e}")
            raise
    
    def handle_authentication(self) -> bool:
        """Gestisce il processo di autenticazione completo"""
        try:
            while not self.authenticated:
                # Ricevi richiesta di autenticazione
                auth_request = self.receive_json_message()
                if not auth_request:
                    return False
                    
                action = auth_request.get('action')
                
                if action == 'register':
                    if self.handle_registration(auth_request):
                        continue  # Dopo registrazione, attendi login
                    else:
                        return False
                        
                elif action == 'login':
                    return self.handle_login(auth_request)
                    
                else:
                    self.send_json_message({
                        'status': 'error', 
                        'message': 'Azione non valida. Usa "register" o "login"'
                    })
                    
        except Exception as e:
            print(f"❌ Errore nell'autenticazione con {self.client_address}: {e}")
            return False
        
        return False
    
    def handle_registration(self, request) -> bool:
        """Gestisce la registrazione di un nuovo utente"""
        username = request.get('username')
        
        if not username:
            self.send_json_message({'status': 'error', 'message': 'Username mancante'})
            return False
        
        # Usa la chiave pubblica del client per la registrazione
        if self.authenticator.register_user(username, self.client_public_key):
            self.send_json_message({
                'status': 'success', 
                'message': f'Utente {username} registrato con successo! Ora puoi fare login.'
            })
            return True
        else:
            self.send_json_message({
                'status': 'error', 
                'message': 'Utente già esistente'
            })
            return False
    
    def handle_login(self, request) -> bool:
        """Gestisce il processo di login con challenge-response"""
        username = request.get('username')
        
        if not username:
            self.send_json_message({'status': 'error', 'message': 'Username mancante'})
            return False
        
        # Controlla se l'utente esiste
        if not self.authenticator.user_exists(username):
            self.send_json_message({'status': 'error', 'message': 'Utente non registrato'})
            return False
        
        # Genera e invia challenge
        result = self.authenticator.create_challenge_for_user(username)
        if not result:
            self.send_json_message({'status': 'error', 'message': 'Errore nella generazione del challenge'})
            return False
        
        encrypted_challenge, original_challenge = result
        
        # Invia challenge cifrato
        challenge_message = {
            'status': 'challenge',
            'encrypted_challenge': encrypted_challenge,
            'message': 'Decritta il challenge con la tua chiave privata'
        }
        self.send_json_message(challenge_message)
        
        # Ricevi risposta al challenge
        response_message = self.receive_json_message()
        if not response_message:
            return False
            
        challenge_response = response_message.get('challenge_response')
        
        if challenge_response is None:
            self.send_json_message({'status': 'error', 'message': 'Risposta al challenge mancante'})
            return False
        
        # Verifica risposta
        if self.authenticator.verify_challenge_response(username, original_challenge, challenge_response):
            self.current_user = username
            self.authenticated = True
            
            # Aggiungi il client alla lista dei client connessi
            self.server.add_authenticated_client(self)
            
            self.send_json_message({
                'status': 'authenticated', 
                'message': f'Benvenuto {username}! Autenticazione completata.'
            })
            return True
        else:
            self.send_json_message({'status': 'error', 'message': 'Challenge response non valido'})
            return False
    
    def start_encrypted_chat(self):
        """Avvia la chat crittografata dopo l'autenticazione"""
        print(f"💬 Chat attiva per {self.current_user} da {self.client_address}")
        
        # Thread per ricevere messaggi da questo client
        receive_thread = threading.Thread(target=self.receive_messages)
        receive_thread.daemon = True
        receive_thread.start()
        
        # Mantieni il thread attivo
        try:
            receive_thread.join()
        except:
            pass
    
    def receive_messages(self):
        """Thread per ricevere e processare messaggi del client"""
        try:
            while self.running:
                # Ricevi il messaggio cifrato
                message_data = self.receive_json_message()
                
                if not message_data:
                    break
                
                encrypted_blocks = message_data.get('blocks', [])
                signature = message_data.get('signature')
                message_type = message_data.get('type', 'broadcast')  # default broadcast
                target_user = message_data.get('target')  # per messaggi privati
                
                # Decifra il messaggio
                decrypted_message = self.rsa.decrypt_string(encrypted_blocks, self.server.private_key)
                
                # Verifica la firma se presente
                signature_valid = False
                if signature:
                    signature_valid = self.authenticator.verify_signature(
                        decrypted_message, signature, self.client_public_key
                    )
                
                if decrypted_message.lower() == 'quit':
                    print(f"📨 {self.current_user} ha lasciato la chat")
                    self.running = False
                    break
                
                # Gestisci il messaggio in base al tipo
                if message_type == 'private' and target_user:
                    # Messaggio privato
                    self.server.send_private_message(
                        self.current_user, target_user, decrypted_message, signature_valid
                    )
                else:
                    # Messaggio broadcast (default)
                    self.server.broadcast_message(
                        self.current_user, decrypted_message, signature_valid, exclude_sender=True
                    )
                
        except Exception as e:
            if self.running:
                print(f"❌ Errore nella ricezione da {self.current_user}: {e}")
            self.running = False
    
    def send_message_to_client(self, sender: str, message: str, signature_valid: bool = False, message_type: str = "broadcast"):
        """Invia un messaggio cifrato al client"""
        try:
            # Cifra il messaggio con la chiave pubblica del client
            encrypted_blocks = self.rsa.encrypt_string(message, self.client_public_key)
            
            # Firma il messaggio con la chiave privata del server
            signature = self.authenticator.sign_message(message, self.server.private_key)
            
            # Prepara i dati da inviare
            message_data = {
                'blocks': encrypted_blocks,
                'signature': signature,
                'sender': sender,
                'signature_valid': signature_valid,
                'type': message_type
            }
            
            # Invia il messaggio
            self.send_json_message(message_data)
            
        except Exception as e:
            print(f"❌ Errore nell'invio messaggio a {self.current_user}: {e}")
    
    def send_json_message(self, data):
        """Invia un messaggio JSON"""
        try:
            message = json.dumps(data).encode('utf-8')
            self.client_socket.send(len(message).to_bytes(4, 'big'))
            self.client_socket.send(message)
        except:
            self.running = False
    
    def receive_json_message(self):
        """Riceve un messaggio JSON"""
        try:
            length_bytes = self.client_socket.recv(4)
            if not length_bytes:
                return None
                
            length = int.from_bytes(length_bytes, 'big')
            message = self.client_socket.recv(length).decode('utf-8')
            return json.loads(message)
        except:
            return None
    
    def cleanup(self):
        """Pulisce le risorse del client"""
        self.running = False
        try:
            if self.current_user:
                self.authenticator.logout_user(self.current_user)
                self.server.remove_authenticated_client(self)
                self.server.broadcast_user_list()
            if self.client_socket:
                self.client_socket.close()
            print(f"🧹 Connessione chiusa per {self.current_user or 'client non autenticato'} da {self.client_address}")
        except:
            pass


class AuthenticatedRSAServer:
    def __init__(self, host='localhost', port=12345):
        self.host = host
        self.port = port
        self.rsa = RSAKeyGenerator()
        self.public_key, self.private_key = self.rsa.generate_keys()
        self.authenticator = RSAAuthenticator(self.rsa)
        self.socket = None
        self.running = True
        self.authenticated_clients = []  # Lista dei client autenticati
        self.clients_lock = threading.Lock()  # Per thread safety
        
    def start_server(self):
        """Avvia il server multi-client con autenticazione"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind((self.host, self.port))
            self.socket.listen(5)  # Accetta fino a 5 connessioni in coda
            
            print(f"🌐 Server multi-client avviato su {self.host}:{self.port}")
            print(f"📋 Chiave pubblica server: e={self.public_key[0]}, n={self.public_key[1]}")
            print("⏳ In attesa di connessioni...")
            
            while self.running:
                try:
                    client_socket, client_address = self.socket.accept()
                    
                    # Crea un handler per questo client
                    client_handler = ClientHandler(client_socket, client_address, self)
                    
                    # Avvia il thread per gestire questo client
                    client_thread = threading.Thread(target=client_handler.handle_client)
                    client_thread.daemon = True
                    client_thread.start()
                    
                except Exception as e:
                    if self.running:
                        print(f"❌ Errore nell'accettazione client: {e}")
                        
        except Exception as e:
            print(f"❌ Errore del server: {e}")
        finally:
            self.cleanup()
    
    def add_authenticated_client(self, client_handler):
        """Aggiunge un client alla lista dei client autenticati"""
        with self.clients_lock:
            self.authenticated_clients.append(client_handler)
        print(f"👥 Client attivi: {len(self.authenticated_clients)}")
    
    def remove_authenticated_client(self, client_handler):
        """Rimuove un client dalla lista dei client autenticati"""
        with self.clients_lock:
            if client_handler in self.authenticated_clients:
                self.authenticated_clients.remove(client_handler)
        print(f"👥 Client attivi: {len(self.authenticated_clients)}")
    
    def broadcast_message(self, sender: str, message: str, signature_valid: bool = False, exclude_sender: bool = False):
        """Invia un messaggio a tutti i client connessi"""
        with self.clients_lock:
            clients_to_notify = self.authenticated_clients.copy()
        
        for client in clients_to_notify:
            try:
                if exclude_sender and client.current_user == sender:
                    continue
                    
                client.send_message_to_client(sender, message, signature_valid, "broadcast")
            except:
                # Se c'è un errore, rimuovi il client dalla lista
                self.remove_authenticated_client(client)
    
    def send_private_message(self, sender: str, target_user: str, message: str, signature_valid: bool = False):
        """Invia un messaggio privato a un utente specifico"""
        target_client = None
        
        with self.clients_lock:
            for client in self.authenticated_clients:
                if client.current_user == target_user:
                    target_client = client
                    break
        
        if target_client:
            try:
                private_msg = f"(Privato da {sender}): {message}"
                target_client.send_message_to_client(sender, private_msg, signature_valid, "private")
                
                # Conferma al mittente
                sender_client = None
                for client in self.authenticated_clients:
                    if client.current_user == sender:
                        sender_client = client
                        break
                
                if sender_client:
                    confirm_msg = f"Messaggio privato inviato a {target_user}: {message}"
                    sender_client.send_message_to_client("Sistema", confirm_msg, True, "system")
                    
            except:
                # Errore nell'invio
                pass
        else:
            # Utente target non trovato
            sender_client = None
            with self.clients_lock:
                for client in self.authenticated_clients:
                    if client.current_user == sender:
                        sender_client = client
                        break
            
            if sender_client:
                error_msg = f"Utente {target_user} non trovato o non connesso"
                sender_client.send_message_to_client("Sistema", error_msg, True, "error")
    
    def broadcast_user_list(self):
        """Invia la lista degli utenti connessi a tutti i client"""
        with self.clients_lock:
            user_list = [client.current_user for client in self.authenticated_clients if client.current_user]
        
        if user_list:
            users_message = f"Utenti connessi: {', '.join(user_list)}"
            self.broadcast_message("Sistema", users_message, True)
    
    def cleanup(self):
        """Pulisce le risorse del server"""
        self.running = False
        try:
            with self.clients_lock:
                for client in self.authenticated_clients:
                    client.cleanup()
                self.authenticated_clients.clear()
            
            if self.socket:
                self.socket.close()
            print("🧹 Server chiuso correttamente")
        except Exception as e:
            print(f"❌ Errore durante la chiusura del server: {e}")


class RSAClient:
    """Client RSA per connettersi al server multi-client"""
    
    def __init__(self, host='localhost', port=12345, username=None):
        self.host = host
        self.port = port
        self.rsa = RSAKeyGenerator()
        self.username = username
        # Inizializza keys_file basandosi sull'username, se fornito.
        self.keys_file = f"{username}_keys.pkl" if username else None 
        
        #  Tenta di caricare le chiavi all'inizializzazione.
        if self.username and self.load_keys(): 
            print(f"🔑 Chiavi esistenti caricate per {self.username}")
        else:
            self.public_key, self.private_key = self.rsa.generate_keys()
            print(f"🔑 Nuove chiavi generate")
            
        self.server_public_key = None
        self.socket = None
        self.authenticated = False
        self.running = True
        
        print(f"🔑 Chiavi client:")
        print(f"   Pubblica: e={self.public_key[0]}, n={self.public_key[1]}")    
        
    def load_keys(self):
        """Carica le chiavi dal file se esistono"""
        try:
            # Controlla se keys_file è stato impostato prima di tentare il caricamento.
            if self.keys_file and os.path.exists(self.keys_file): 
                with open(self.keys_file, 'rb') as f:
                    keys_data = pickle.load(f)
                    self.public_key = keys_data['public_key']
                    self.private_key = keys_data['private_key']
                    return True
        except Exception as e:
            print(f"⚠️ Errore nel caricamento chiavi: {e}")
        return False
    
    def save_keys(self):
        """Salva le chiavi su file"""
        try:
            # Controlla se keys_file è stato impostato prima di tentare il salvataggio.
            if self.keys_file: 
                keys_data = {
                    'public_key': self.public_key,
                    'private_key': self.private_key
                }
                with open(self.keys_file, 'wb') as f:
                    pickle.dump(keys_data, f)
                print(f"💾 Chiavi salvate in {self.keys_file}")
        except Exception as e:
            print(f"⚠️ Errore nel salvataggio chiavi: {e}")
            
    def handle_registration(self) -> bool:
        """Gestisce la registrazione con salvataggio delle chiavi"""
        username = input("📝 Inserisci username per registrazione: ").strip()
        
        if not username:
            print("❌ Username non può essere vuoto")
            return False
        
        # Imposta username e file delle chiavi qui, dopo che l'utente lo ha inserito.
        self.username = username
        self.keys_file = f"{username}_keys.pkl"
        
        # Invia richiesta di registrazione
        registration_request = {
            'action': 'register',
            'username': username
        }
        
        self.send_json_message(registration_request)
        
        # Ricevi risposta
        response = self.receive_json_message()
        if response and response.get('status') == 'success':
            print(f"✅ {response.get('message')}")
            # Salva le chiavi solo dopo che la registrazione ha successo.
            self.save_keys() 
            return True
        else:
            print(f"❌ Errore registrazione: {response.get('message', 'Errore sconosciuto')}")
            return False
    
    def handle_login(self) -> bool:
        """Gestisce il processo di login con caricamento chiavi"""
        if not self.username:
            self.username = input("👤 Inserisci username: ").strip()
            
            if not self.username:
                print("❌ Username non può essere vuoto")
                return False
            
            #  Prova a caricare le chiavi per questo utente prima di tentare il login.
            self.keys_file = f"{self.username}_keys.pkl"
            if not self.load_keys():
                print("❌ Nessuna chiave trovata per questo utente. Devi prima registrarti.")
                return False
        
        # Invia richiesta login
        login_request = {
            'action': 'login',
            'username': self.username
        }
        
        self.send_json_message(login_request)
        
        # Ricevi challenge o errore
        response = self.receive_json_message()
        
        if not response:
            print("❌ Nessuna risposta dal server")
            return False
        
        if response.get('status') == 'error':
            print(f"❌ Errore login: {response.get('message')}")
            return False
        
        if response.get('status') == 'challenge':
            # Decritta il challenge
            encrypted_challenge = response.get('encrypted_challenge')
            print("🔓 Challenge ricevuto, decrittando...")
            
            try:
                # Decritta il challenge con la chiave privata
                decrypted_challenge = self.rsa.decrypt(encrypted_challenge, self.private_key)
                
                # Invia la risposta
                challenge_response = {
                    'challenge_response': decrypted_challenge
                }
                
                self.send_json_message(challenge_response)
                
                # Ricevi conferma autenticazione
                auth_response = self.receive_json_message()
                
                if auth_response and auth_response.get('status') == 'authenticated':
                    self.authenticated = True
                    # L'username è già impostato correttamente, non serve riassegnarlo qui
                    # self.username = username 
                    print(f"✅ {auth_response.get('message')}")
                    return True
                else:
                    print(f"❌ {auth_response.get('message', 'Autenticazione fallita')}")
                    return False
                    
            except Exception as e:
                print(f"❌ Errore nella decrittazione del challenge: {e}")
                return False
        
        return False   
        
    def connect_to_server(self):
        """Si connette al server"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))
            print(f"🔗 Connesso al server {self.host}:{self.port}")
            
            # Scambio delle chiavi pubbliche
            self.exchange_public_keys()
            
            # Processo di autenticazione
            if self.handle_authentication():
                print("✅ Autenticazione completata!")
                
                # Avvia thread per ricevere messaggi
                receive_thread = threading.Thread(target=self.receive_messages)
                receive_thread.daemon = True
                receive_thread.start()
                
                # Avvia chat interattiva
                self.start_interactive_chat()
            else:
                print("❌ Autenticazione fallita!")
                
        except Exception as e:
            print(f"❌ Errore di connessione: {e}")
        finally:
            self.cleanup()
    
    def exchange_public_keys(self):
        """Scambia le chiavi pubbliche con il server"""
        try:
            # Ricevi la chiave pubblica del server
            server_key_data = self.receive_json_message()
            self.server_public_key = (server_key_data['e'], server_key_data['n'])
            print(f"🔑 Chiave pubblica server ricevuta")
            
            # Invia la propria chiave pubblica
            key_data = {
                'e': self.public_key[0],
                'n': self.public_key[1]
            }
            self.send_json_message(key_data)
            
        except Exception as e:
            print(f"❌ Errore nello scambio chiavi: {e}")
            raise
    
    def handle_authentication(self) -> bool:
        """Gestisce il processo di autenticazione"""
        while not self.authenticated:
            print("\n🔐 === AUTENTICAZIONE ===")
            print("1. Registrazione nuovo utente")
            print("2. Login utente esistente")
            print("3. Esci")
            
            choice = input("Scegli un'opzione (1-3): ").strip()
            
            if choice == '1':
                # handle_registration ora gestisce l'impostazione di self.username e self.keys_file
                if self.handle_registration(): 
                    print("✅ Registrazione completata! Ora puoi fare login.")
                    continue
                else:
                    return False
                    
            elif choice == '2':
                #  handle_login ora gestisce l'impostazione di self.username e il caricamento delle chiavi
                return self.handle_login() 
                
            elif choice == '3':
                return False
                
            else:
                print("❌ Opzione non valida")
        
        return self.authenticated
    
    
    def start_interactive_chat(self):
        """Avvia la chat interattiva"""
        print("\n💬 === CHAT CRITTOGRAFATA ===")
        print("Comandi disponibili:")
        print("  /private <username> <messaggio> - Invia messaggio privato")
        print("  /quit - Esci dalla chat")
        print("  Qualsiasi altro testo - Messaggio broadcast")
        print("=" * 50)
        
        try:
            while self.running:
                message = input().strip()
                
                if not message:
                    continue
                
                if message.lower() in ['/quit', 'quit']:
                    self.send_encrypted_message('quit')
                    break
                
                # Gestisci comandi speciali
                if message.startswith('/private '):
                    self.handle_private_message(message)
                else:
                    # Messaggio broadcast normale
                    self.send_encrypted_message(message)
                    
        except KeyboardInterrupt:
            print("\n👋 Disconnessione in corso...")
        except Exception as e:
            print(f"❌ Errore nella chat: {e}")
    
    def handle_private_message(self, command):
        """Gestisce i messaggi privati"""
        try:
            parts = command.split(' ', 2)
            if len(parts) < 3:
                print("❌ Formato corretto: /private <username> <messaggio>")
                return
            
            target_user = parts[1]
            message = parts[2]
            
            self.send_encrypted_message(message, message_type='private', target_user=target_user)
            
        except Exception as e:
            print(f"❌ Errore nell'invio messaggio privato: {e}")
    
    def send_encrypted_message(self, message, message_type='broadcast', target_user=None):
        """Invia un messaggio cifrato al server"""
        try:
            # Cifra il messaggio con la chiave pubblica del server
            encrypted_blocks = self.rsa.encrypt_string(message, self.server_public_key)
            
            # Firma il messaggio con la propria chiave privata
            authenticator = RSAAuthenticator(self.rsa)
            signature = authenticator.sign_message(message, self.private_key)
            
            # Prepara i dati
            message_data = {
                'blocks': encrypted_blocks,
                'signature': signature,
                'type': message_type
            }
            
            if target_user:
                message_data['target'] = target_user
            
            # Invia al server
            self.send_json_message(message_data)
            
        except Exception as e:
            print(f"❌ Errore nell'invio messaggio: {e}")
    
    def receive_messages(self):
        """Thread per ricevere messaggi dal server"""
        try:
            while self.running:
                message_data = self.receive_json_message()
                
                if not message_data:
                    break
                
                encrypted_blocks = message_data.get('blocks', [])
                signature = message_data.get('signature')
                sender = message_data.get('sender', 'Sconosciuto')
                signature_valid = message_data.get('signature_valid', False)
                message_type = message_data.get('type', 'broadcast')
                
                # Decritta il messaggio
                decrypted_message = self.rsa.decrypt_string(encrypted_blocks, self.private_key)
                
                # Mostra il messaggio
                signature_indicator = "✅" if signature_valid else "⚠️"
                
                if message_type == 'private':
                    print(f"\n🔒 {signature_indicator} {decrypted_message}")
                elif message_type in ['system', 'error']:
                    print(f"\n📢 {signature_indicator} {sender}: {decrypted_message}")
                else:
                    print(f"\n💬 {signature_indicator} {sender}: {decrypted_message}")
                
        except Exception as e:
            if self.running:
                print(f"❌ Errore nella ricezione messaggi: {e}")
        finally:
            self.running = False
    
    def send_json_message(self, data):
        """Invia un messaggio JSON"""
        try:
            message = json.dumps(data).encode('utf-8')
            self.socket.send(len(message).to_bytes(4, 'big'))
            self.socket.send(message)
        except:
            self.running = False
    
    def receive_json_message(self):
        """Riceve un messaggio JSON"""
        try:
            length_bytes = self.socket.recv(4)
            if not length_bytes:
                return None
                
            length = int.from_bytes(length_bytes, 'big')
            message = self.socket.recv(length).decode('utf-8')
            return json.loads(message)
        except:
            return None
    
    def cleanup(self):
        """Pulisce le risorse del client"""
        self.running = False
        try:
            if self.socket:
                self.socket.close()
            print("🧹 Connessione chiusa")
        except:
            pass


def run_server():
    """Avvia il server"""
    server = AuthenticatedRSAServer()
    try:
        server.start_server()
    except KeyboardInterrupt:
        print("\n👋 Arresto server...")
        server.cleanup()


def run_client():
    """Avvia il client con username opzionale"""
    print("Vuoi caricare un utente esistente?")
    username = input("Username (lascia vuoto per nuovo utente): ").strip()
    
    # Passa l'username al costruttore del client.
    # Il costruttore ora gestirà il caricamento o la generazione delle chiavi.
    client = RSAClient(username=username if username else None) 
    try:
        client.connect_to_server()
    except KeyboardInterrupt:
        print("\n👋 Disconnessione client...")
        client.cleanup()
        
if __name__ == "__main__":
    print("🚀 === SISTEMA CHAT RSA MULTI-CLIENT ===")
    print("1. Avvia Server")
    print("2. Avvia Client")
    print("3. Esci")
    
    while True:
        choice = input("\nScegli un'opzione (1-3): ").strip()
        
        if choice == '1':
            print("🌐 Avvio server...")
            run_server()
            break
        elif choice == '2':
            print("👤 Avvio client...")
            run_client()
            break
        elif choice == '3':
            print("👋 Arrivederci!")
            break
        else:
            print("❌ Opzione non valida. Riprova.")