
-----

# 🛡️ Chat Sicura con Crittografia RSA

Questo progetto implementa un'applicazione di chat client-server sicura che utilizza la crittografia asimmetrica **RSA** per garantire la **confidenzialità**, l'**integrità** e l'**autenticazione** dei messaggi. L'architettura è basata su un server multi-threaded in grado di gestire più client contemporaneamente.

-----

## 🏗️ 1. Architettura Generale

L'applicazione si basa su un'architettura **client-server**. Il server è progettato per essere robusto e scalabile, utilizzando il multi-threading per gestire connessioni multiple e simultanee.

Quando un client si connette, il server avvia un thread dedicato (`ClientHandler`) che gestisce l'intero ciclo di vita della comunicazione con quel client: dallo scambio iniziale delle chiavi, passando per l'autenticazione, fino alla gestione dei messaggi di chat.

#### Flusso di base:

1.  Il **Server** si avvia, genera la propria coppia di chiavi RSA e si mette in ascolto di nuove connessioni.
2.  Un **Client** si connette e il server crea un thread dedicato per gestirlo.
3.  Il thread `handle_client` si occupa di tutte le interazioni successive:
      * Scambio di chiavi pubbliche.
      * Autenticazione dell'utente (registrazione o login).
      * Gestione della sessione di chat crittografata.

<!-- end list -->

```
SERVER AVVIATO
        ↓
┌─────────────────────┐
│ Genera chiavi RSA   │
└─────────────────────┘
        ↓
┌─────────────────────┐
│ In ascolto di       │
│ connessioni...      │
└─────────────────────┘
        ↓
┌─────────────────────┐
│ Nuovo client si     │
│ connette            │
└─────────────────────┘
        ↓
┌─────────────────────┐
│ Il Server accetta   │
│ la connessione      │
└─────────────────────┘
        ↓
┌─────────────────────┐
│ Viene avviato un    │
│ Thread dedicato per │
│ il client           │
└─────────────────────┘
        ↓
┌─────────────────────┐
│ 1. Scambio chiavi   │
│    pubbliche        │
└─────────────────────┘
        ↓
┌─────────────────────┐
│ 2. Autenticazione   │
│    utente           │
└─────────────────────┘
        ↓
┌─────────────────────┐
│ 3. Sessione di chat │
│    crittografata    │
└─────────────────────┘
        ↓
┌─────────────────────┐
│ Fine sessione       │
└─────────────────────┘
```

-----

## 🔑 2. Generazione delle Chiavi RSA

La sicurezza del sistema si fonda sull'algoritmo **RSA**. Le coppie di chiavi (pubblica e privata) vengono generate seguendo i passaggi matematici standard:

1.  **Generazione dei Primi**: Vengono generati due numeri primi grandi e distinti, $p$ e $q$.
2.  **Calcolo del Modulo**: Si calcola il modulo $n = p \\times q$, che farà parte sia della chiave pubblica che di quella privata.
3.  **Funzione Totiente di Eulero**: Si calcola $\\phi(n) = (p-1)(q-1)$, necessaria per trovare gli esponenti.
4.  **Esponente Pubblico (e)**: Si sceglie un numero intero $e$ tale che sia coprimo con $\\phi(n)$ e $1 \< e \< \\phi(n)$.
5.  **Esponente Privato (d)**: Si calcola l'esponente privato $d$ come l'inverso moltiplicativo modulare di $e$ rispetto a $\\phi(n)$.

Il risultato è una **chiave pubblica ($e, n$)**, che può essere condivisa, e una **chiave privata ($d, n$)**, che deve rimanere segreta.

```
AVVIO GENERAZIONE CHIAVI
        ↓
┌─────────────────────┐
│ generate_prime()    │ ← Genera primo p
└─────────────────────┘
        ↓
┌─────────────────────┐
│ generate_prime()    │ ← Genera primo q (≠ p)
└─────────────────────┘
        ↓
┌─────────────────────┐
│ n = p × q           │ ← Calcola modulo
└─────────────────────┘
        ↓
┌─────────────────────┐
│ φ(n) = (p-1)(q-1)   │ ← Calcola funzione di Eulero
└─────────────────────┘
        ↓
┌─────────────────────┐
│find_random_coprime_e│ ← Trova esponente pubblico e
└─────────────────────┘
        ↓
┌─────────────────────┐
│ modinv(e, φ)        │ ← Calcola esponente privato d
└─────────────────────┘
        ↓
┌─────────────────────┐
│ public_key = (e,n)  │
│ private_key = (d,n) │
└─────────────────────┘
```

-----

## 🔐 3. Processo di Autenticazione

Per garantire che solo gli utenti autorizzati possano accedere, è stato implementato un meccanismo di autenticazione basato su un modello **challenge-response**.

#### Flusso di Autenticazione:

1.  **Scambio di Chiavi Pubbliche**: Appena connesso, il client scambia la propria chiave pubblica con quella del server.
2.  **Scelta Utente**: L'utente può scegliere se registrarsi o effettuare il login.
3.  **Registrazione**: L'utente fornisce un nome utente. Il server salva la sua chiave pubblica associandola a quel nome.
4.  **Login**:
    1.  Il server genera una "challenge", ovvero un messaggio casuale.
    2.  Cripta la challenge con la chiave pubblica dell'utente e la invia al client.
    3.  Il client, e solo lui, può decriptare la challenge usando la sua chiave privata.
    4.  Il client invia la challenge decriptata al server.
    5.  Il server verifica che la risposta corrisponda. Se sì, l'utente è autenticato.

<!-- end list -->

```
CLIENT CONNESSO
        ↓
┌─────────────────────┐
│exchange_public_keys │ ← Scambio chiavi pubbliche
└─────────────────────┘
        ↓
┌─────────────────────┐
│ Scelta utente:      │
│ 1. Register         │
│ 2. Login            │
└─────────────────────┘
        ├────────────────>──────────┐
        ↓                           ↓
 ┌─────────┐                  ┌──────────────┐
 │REGISTER │                  │    LOGIN     │
 └─────────┘                  └──────────────┘
        ↓                           ↓
┌─────────────────────┐ ┌─────────────────────┐
│ register_user()     │ │create_challenge_for_│
│ Salva chiave pub    │ │user()               │
└─────────────────────┘ └─────────────────────┘
        ↓                           ↓
┌─────────────────────┐ ┌─────────────────────┐
│ "Registrazione OK"  │ │ encrypt(challenge,  │
│ Torna al login      │ │ user_public_key)    │
└─────────────────────┘ └─────────────────────┘
                                    ↓
                            ┌─────────────────────┐
                            │ Client decritta     │
                            │ con private_key     │
                            └─────────────────────┘
                                    ↓
                            ┌─────────────────────┐
                            │verify_challenge_    │
                            │response()           │
                            └─────────────────────┘
                                    ↓
                            ┌─────────────────────┐
                            │ AUTENTICATO         │
                            │ Avvia chat          │
                            └─────────────────────┘
```

-----

## 📝 4. Crittografia e Decrittografia dei Messaggi

Poiché RSA opera su numeri, le stringhe vengono prima convertite in rappresentazioni numeriche. Il sistema gestisce messaggi di qualsiasi dimensione suddividendoli in blocchi, se necessario.

```
MESSAGGIO ORIGINALE (stringa)
        ↓
┌─────────────────────┐
│ string_to_number()  │
└─────────────────────┘
        ↓
┌─────────────────────┐
│ Controllo dimensione│ ← number >= n?
└─────────────────────┘
        ├────────────────>──────────┐
        ↓                           ↓
  ┌─────────┐                   ┌──────────────┐
  │ PICCOLA │                   │    GRANDE    │
  │(1 blocco)│                  │ (N blocchi)  │
  └─────────┘                   └──────────────┘
        ↓                           ↓
   encrypt()                  _encrypt_large_string()
        ↓                           ↓
   [cipher]                   [cipher1, cipher2, ...]
        ├────────────────>──────────┤
        ↓                           ↓
   decrypt()                  _decrypt_large_string()
        ↓                           ↓
┌─────────────────────┐
│ number_to_string()  │
└─────────────────────┘
        ↓
MESSAGGIO FINALE
```

-----

## 💬 5. Gestione dei Messaggi nella Chat

Una volta autenticato, l'utente può inviare messaggi.

  * **Messaggio Broadcast**: Qualsiasi testo che non inizia con un comando viene inviato a tutti.
  * **Messaggio Privato**: Con `/private <utente> <messaggio>`, il messaggio è visibile solo al destinatario.
  * **Disconnessione**: Con `/quit`, il client termina la connessione.

Per ogni messaggio, vengono eseguiti due passaggi di sicurezza:

1.  **Crittografia**: Il messaggio viene crittografato con la chiave pubblica del server.
2.  **Firma Digitale**: Il messaggio viene firmato con la chiave privata del mittente per verificarne l'autenticità.

<!-- end list -->

```
MESSAGGIO UTENTE
        ↓
┌─────────────────────┐
│ Analisi comando:    │
│ /private, /quit     │
│ o messaggio normale │
└─────────────────────┘
        ├─────────────────────>───────────────────┐
        ↓                                         ↓
  ┌─────────┐                 ┌──────────────┐  ┌──────────────┐
  │ PRIVATO │                 │  BROADCAST   │  │    QUIT      │
  └─────────┘                 └──────────────┘  └──────────────┘
        ↓                           ↓                 ↓
┌─────────────────────┐ ┌─────────────────────┐ ┌─────────────────────┐
│encrypt_string()     │ │encrypt_string()     │ │ Termina connessione │
│con server_public_key│ │con server_public_key│ └─────────────────────┘
└─────────────────────┘ └─────────────────────┘
        ↓                           ↓
┌─────────────────────┐ ┌─────────────────────┐
│sign_message()       │ │sign_message()       │
│con private_key      │ │con private_key      │
└─────────────────────┘ └─────────────────────┘
        ↓                           ↓
┌─────────────────────┐ ┌─────────────────────┐
│send_private_message │ │broadcast_message()  │
│(target_user)        │ │(tutti i client)     │
└─────────────────────┘ └─────────────────────┘
```

-----

## ✍️ 6. Sicurezza e Firma Digitale

Oltre alla crittografia, il sistema implementa la **firma digitale** per garantire autenticità e integrità.

### Verifica della Firma

Quando un messaggio firmato viene ricevuto, il destinatario:

1.  Calcola l'hash **SHA-256** del messaggio originale.
2.  Decripta la firma digitale allegata usando la **chiave pubblica del mittente**.
3.  Confronta i due hash: se corrispondono, la firma è valida.

### Gestione delle Sessioni

Ogni sessione utente ha una durata limitata (es. 3600 secondi). Se un utente rimane inattivo oltre questo timeout, la sua sessione viene terminata automaticamente dal server.

-----

## 🌐 7. Comunicazione di Rete

La comunicazione avviene tramite socket **TCP**. I messaggi vengono serializzati in formato **JSON** e inviati con un protocollo lunghezza-valore.

#### Invio di un Messaggio

1.  I dati vengono convertiti in una stringa JSON e codificati in byte.
2.  La lunghezza del messaggio in byte viene inviata come un intero a 4 byte (big-endian).
3.  Viene inviato il messaggio effettivo.

#### Ricezione di un Messaggio

1.  Si leggono i primi 4 byte per determinare la lunghezza del messaggio.
2.  Si legge esattamente quel numero di byte dal socket.
3.  I byte ricevuti vengono decodificati da JSON al formato dati originale.

-----

## 💾 8. Persistenza dei Dati

  * **Dati Utente (Server)**: Quando un nuovo utente si registra, le sue informazioni (username e chiave pubblica) vengono salvate nel file `users.pkl`.
  * **Chiavi (Client)**: Il client salva le proprie chiavi localmente in un file `{nomeutente}_keys.pkl` per non doverle rigenerare ad ogni avvio.

-----

## ⚙️ 9. Algoritmi Core

#### Esponenziazione Modulare (per Crittografia)

```
modular_exponentiation(base, exp, mod)
        ↓
┌─────────────────────┐
│ result = 1          │
│ base = base % mod   │
└─────────────────────┘
        ↓
┌─────────────────────┐
│ while exp > 0:      │
│   if exp % 2 == 1:  │
│     result *= base  │
│   exp >>= 1         │
│   base = base²      │
└─────────────────────┘
        ↓
┌─────────────────────┐
│ return result       │
└─────────────────────┘
```

#### Algoritmo di Euclide Esteso (per Inverso Modulare)

```
egcd(a, b)
        ↓
┌─────────────────────┐
│ x0=1, x1=0          │
│ y0=0, y1=1          │
└─────────────────────┘
        ↓
┌─────────────────────┐
│ while b != 0:       │
│   q = a // b        │
│   a, b = b, a % b   │
│   aggiorna x0,x1,y0,y1│
└─────────────────────┘
        ↓
┌─────────────────────┐
│ return (gcd, x, y)  │
└─────────────────────┘
```
