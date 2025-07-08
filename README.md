Chat Sicura con Crittografia RSA
Questo progetto implementa un'applicazione di chat client-server sicura che utilizza la crittografia asimmetrica RSA per garantire la confidenzialità, l'integrità e l'autenticazione dei messaggi. 
L'architettura è basata su un server multi-threaded in grado di gestire più client contemporaneamente.

1. Architettura Generale
L'applicazione si basa su un'architettura client-server. Il server è progettato per essere robusto e scalabile, utilizzando il multi-threading per gestire connessioni multiple e simultanee.
Quando un client si connette, il server avvia un thread dedicato (ClientHandler) che gestisce l'intero ciclo di vita della comunicazione con quel client: dallo scambio iniziale delle chiavi,
passando per l'autenticazione, fino alla gestione dei messaggi di chat. 

Il flusso è il seguente:
Il Server si avvia, genera la propria coppia di chiavi RSA e si mette in ascolto di nuove connessioni.
Un Client si connette e il server crea un thread dedicato per gestirlo.
Il thread handle_client si occupa di tutte le interazioni successive:
Scambio di chiavi pubbliche.
Autenticazione dell'utente (registrazione o login).
Gestione della sessione di chat crittografata.

2. Generazione delle Chiavi RSA
La sicurezza del sistema si fonda sull'algoritmo RSA. Le coppie di chiavi (pubblica e privata) vengono generate seguendo i passaggi matematici standard:
Generazione dei Primi: Vengono generati due numeri primi grandi e distinti, p e q.
Calcolo del Modulo: Si calcola il modulo n, che farà parte sia della chiave pubblica che di quella privata.
Funzione Totiente di Eulero:
Si calcola phi(n) (phi di n), necessaria per trovare gli esponenti.
Esponente Pubblico (e): Si sceglie un numero intero e tale che sia coprimo con phi(n) e 1 < e < phi(n).
Esponente Privato (d): Si calcola l'esponente privato d come l'inverso moltiplicativo modulare di e rispetto a phi(n).
Il risultato è una chiave pubblica (e, n), che può essere condivisa, e una chiave privata (d, n), che deve rimanere segreta.

3. Processo di Autenticazione
Per garantire che solo gli utenti autorizzati possano accedere, è stato implementato un meccanismo di autenticazione basato su un modello challenge-response.

Scambio di Chiavi Pubbliche: Appena connesso, il client scambia la propria chiave pubblica con quella del server.
Scelta Utente: L'utente può scegliere se registrarsi o effettuare il login.
Registrazione: L'utente fornisce un nome utente. Il server salva la sua chiave pubblica associandola a quel nome.

Login:
Il server genera una "challenge", ovvero un messaggio casuale.
Cripta la challenge con la chiave pubblica dell'utente (recuperata in fase di registrazione) e la invia al client.
Il client, e solo lui, può decriptare la challenge usando la sua chiave privata.
Il client invia la challenge decriptata al server.
Il server verifica che la risposta corrisponda alla challenge originale. Se sì, l'utente è autenticato e la sessione di chat può iniziare.

4. Crittografia e Decrittografia dei Messaggi
I messaggi scambiati vengono protetti tramite crittografia RSA. Poiché RSA opera su numeri, le stringhe vengono prima convertite in rappresentazioni numeriche.
Il flusso di crittografia gestisce messaggi di qualsiasi dimensione:
Conversione: Il messaggio originale (stringa) viene convertito in un grande numero intero.
Controllo Dimensione: Si verifica se il numero è più piccolo del modulo n della chiave RSA.
Messaggio Piccolo (1 Blocco): Se numero < n, il messaggio viene crittografato direttamente con la funzione encrypt().
Messaggio Grande (N Blocchi): Se numero >= n, il messaggio viene suddiviso in blocchi più piccoli, ognuno dei quali viene crittografato singolarmente. Si ottiene così una lista di messaggi cifrati.
Decrittografia: Il processo inverso viene applicato per decifrare. I singoli blocchi cifrati vengono decriptati e poi riassemblati per ricostruire il numero originale, che viene infine riconvertito nella stringa del messaggio finale.

5. Gestione dei Messaggi nella Chat
Una volta autenticato, l'utente può inviare messaggi. Il client analizza l'input per determinare il tipo di azione:
Messaggio Broadcast: Qualsiasi testo che non inizia con un comando viene inviato a tutti gli utenti connessi.
Messaggio Privato: Usando il comando /private <utente> <messaggio>, un utente può inviare un messaggio visibile solo al destinatario specificato.
Disconnessione: Con il comando /quit, il client termina la connessione in modo pulito.

Per ogni messaggio inviato (broadcast o privato), vengono eseguiti due passaggi di sicurezza fondamentali:
Crittografia: Il messaggio viene crittografato usando la chiave pubblica del server. Questo garantisce che solo il server possa leggerne il contenuto.
Firma Digitale: Il messaggio viene firmato usando la chiave privata del mittente. Questo permette al server (e agli altri client) di verificare l'autenticità del mittente.

6. Sicurezza e Firma Digitale
Oltre alla crittografia, il sistema implementa la firma digitale per garantire autenticità e integrità.

Verifica della Firma
Quando un messaggio firmato viene ricevuto, il destinatario esegue i seguenti passaggi:
Calcola l'hash SHA-256 del messaggio originale.
Decripta la firma digitale allegata usando la chiave pubblica del mittente. Il risultato è l'hash originale calcolato dal mittente.
Confronta i due hash: se corrispondono, la firma è valida e si ha la certezza che il messaggio non è stato alterato e proviene dall'utente dichiarato.

Gestione delle Sessioni
Per prevenire l'uso improprio di sessioni lasciate aperte, ogni sessione utente ha una durata limitata (es. 3600 secondi).
Se un utente autenticato rimane inattivo oltre questo timeout, la sua sessione viene terminata automaticamente dal server.

7. Comunicazione di Rete
La comunicazione tra client e server avviene tramite socket TCP. Per garantire uno scambio di dati affidabile, i messaggi vengono serializzati in formato JSON e strutturati secondo un protocollo semplice:

Invio di un Messaggio
I dati vengono convertiti in una stringa JSON.
La stringa JSON viene codificata in byte.
La lunghezza del messaggio in byte viene calcolata e inviata come un intero a 4 byte (formato big-endian).
Viene inviato il messaggio effettivo.

Ricezione di un Messaggio
Si leggono i primi 4 byte per determinare la lunghezza del messaggio in arrivo.
Si legge esattamente quel numero di byte dal socket.
I byte ricevuti vengono decodificati e riconvertiti da JSON al formato dati originale.

8. Persistenza dei Dati

Dati Utente (Server): Quando un nuovo utente si registra, le sue informazioni (username e chiave pubblica) vengono aggiunte a un dizionario e salvate nel file users.pkl.
Chiavi (Client): Quando un client genera o riceve le sue chiavi per la prima volta, le salva localmente in un file {nomeutente}_keys.pkl, in modo da non doverle rigenerare ad ogni avvio.
