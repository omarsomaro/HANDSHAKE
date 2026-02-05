# QR Code-Based P2P Connection Establishment: A Case Study in Distributed Systems

## Case Study Universitario: Handshacke P2P Framework

---

## Abstract

Questo paper presenta un'analisi approfondita dell'utilizzo dei codici QR nei sistemi di comunicazione peer-to-peer (P2P), utilizzando il framework Handshacke come caso di studio. L'analisi esamina tre flussi QR distinti (Offer QR, Hybrid QR e Phrase QR) e la loro integrazione in un sistema P2P deterministico con traversamento NAT, crittografia avanzata e resistenza alla censura. Il paper contribuisce con: (1) un modello formale di rendezvous deterministico basato su QR, (2) analisi di sicurezza layered dei payload QR, (3) valutazione dell'esperienza utente nei flussi di connessione P2P, e (4) linee guida per l'implementazione di sistemi QR-based in contesti distribuiti.

**Keywords**: QR Code, P2P Networking, Rendezvous, NAT Traversal, Distributed Systems, Usability Security

---

## 1. Introduzione

### 1.1 Contesto e Motivazione

La comunicazione peer-to-peer (P2P) rappresenta una delle sfide più complesse nell'ingegneria dei sistemi distribuiti. Il problema fondamentale è il **rendezvous problem**: come due peer possono trovarsi e stabilire una connessione senza un server centrale di coordinamento?

I codici QR emergono come soluzione elegante a questo problema, offrendo:
- **Canale out-of-band** per lo scambio di parametri di connessione
- **Usabilità** superiore rispetto all'inserimento manuale di indirizzi IP/porte
- **Sicurezza implicita** attraverso la limitazione temporale (TTL)
- **Versatilità** nell'incapsulare diversi tipi di informazione

### 1.2 Il Framework Handshacke

Handshacke è un sistema P2P deterministico che implementa:
- **Rendezvous crittografico** da passphrase condivisa
- **Cascata di trasporto**: LAN → WAN → Tor fallback
- **Multipath racing** in stile ICE (Interactive Connectivity Establishment)
- **Crittografia avanzata**: XChaCha20-Poly1305, Noise Protocol XX
- **Tre flussi QR** distinti per diversi scenari d'uso

### 1.3 Struttura del Paper

Il paper è organizzato come segue:
- Sezione 2: Analisi tecnica dei tre flussi QR
- Sezione 3: Architettura di sicurezza layered
- Sezione 4: Integrazione con il sistema di trasporto
- Sezione 5: Analisi UX e flussi utente
- Sezione 6: Valutazione e discussioni
- Sezione 7: Conclusioni e lavori futuri

---

## 2. Analisi dei Flussi QR

### 2.1 Taxonomy dei Flussi QR

Handshacke implementa tre flussi QR distinti, ciascuno ottimizzato per scenari d'uso specifici:

| Flusso | Scopo | Contenuto | TTL | Caso d'Uso |
|--------|-------|-----------|-----|------------|
| **Offer QR** | Pairing rapido | Endpoints + rendezvous | 5 min default | Connessione one-shot |
| **Hybrid QR** | Re-join robusto | Resume token + offer | QR: 1h, Resume: 15min | Connessioni ricorrenti |
| **Phrase QR** | Privacy-first | Tor invite only | Session-based | Scenari censura |

### 2.2 Offer QR: Rendezvous Endpoint-Based

#### 2.2.1 Struttura del Payload

L'Offer QR incapsula un `OfferPayload` con la seguente struttura:

```rust
pub struct OfferPayload {
    pub ver: u8,                          // Versione protocollo (4)
    pub ttl_s: u64,                       // Time-to-live in secondi
    pub issued_at_ms: u64,                // Timestamp emissione
    pub role_hint: RoleHint,              // Host/Client indicator
    pub endpoints: Vec<Endpoint>,         // Endpoint LAN/WAN/Tor
    pub tor_ephemeral_pk: Option<[u8; 32]>,  // X25519 ephemeral pubkey
    pub tor_endpoint_enc: Option<Vec<u8>>,   // ChaCha20-Poly1305 ciphertext
    pub rendezvous: RendezvousInfo,       // Port, tag16, key_enc
    pub stun_public_addr: Option<SocketAddr>, // STUN-discovered endpoint
    pub commit: [u8; 32],                 // HMAC-SHA256 commitment
    pub timestamp: u64,                   // UNIX ms for simultaneous open
}
```

#### 2.2.2 Meccanismo di Sicurezza: HMAC Commitment

L'integrità dell'offer è garantita da un HMAC-SHA256 calcolato su tutti i campi:

```rust
pub fn compute_commit(offer: &Self, k_offer: &[u8; 32]) -> Result<[u8; 32]> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(k_offer)?;
    
    // Inclusione sequenziale previene attacchi di riordino
    mac.update(&[offer.ver]);
    mac.update(&offer.ttl_s.to_be_bytes());
    mac.update(&offer.issued_at_ms.to_be_bytes());
    mac.update(&bincode::serialize(&offer.role_hint)?);
    mac.update(&bincode::serialize(&offer.endpoints)?);
    // ... tutti i campi inclusi
    
    Ok(mac.finalize().into_bytes().into())
}
```

**Proprietà di sicurezza**:
- **Integrità**: Qualsiasi modifica invalida il commit
- **Autenticità**: Solo chi possiede `k_offer` può generare un commit valido
- **Non-ripudio**: Il commit lega crittograficamente tutti i campi

#### 2.2.3 Crittografia Tor Endpoint

Gli endpoint Tor sono crittografati con X25519 + ChaCha20-Poly1305:

```rust
fn encrypt_tor_endpoint(key_enc: &[u8; 32], tag16: u16, onion: &str) 
    -> Result<([u8; 32], Vec<u8>)> 
{
    // Deriva static X25519 secret dal master key
    let static_secret = derive_tor_static_secret(key_enc, tag16)?;
    let static_pk = PublicKey::from(&static_secret);
    
    // Genera ephemeral key pair
    let ephemeral_secret = EphemeralSecret::random_from_rng(rand::rngs::OsRng);
    let ephemeral_pk = PublicKey::from(&ephemeral_secret);
    
    // X25519 ECDH key exchange
    let shared = ephemeral_secret.diffie_hellman(&static_pk);
    let key = derive_tor_endpoint_key(shared.as_bytes(), tag16)?;
    
    // AEAD encryption
    let cipher = ChaCha20Poly1305::new((&key).into());
    let nonce = random_nonce();
    let ciphertext = cipher.encrypt(&nonce.into(), onion.as_bytes())?;
    
    Ok((ephemeral_pk.to_bytes(), [nonce, ciphertext].concat()))
}
```

**Vantaggi**:
- Forward secrecy: chiave effimera per sessione
- Autenticazione implicita: solo il possessore del `static_secret` può decifrare
- Formato compatto: onion address nascosto nel payload

#### 2.2.4 Validazione Temporale

Il sistema implementa una validazione temporale rigorosa:

```rust
pub const MAX_CLOCK_SKEW_MS: u64 = 30_000;  // 30 secondi tolleranza

pub fn verify(&self, time_validator: &TimeValidator) -> Result<()> {
    // Validazione tempo con protezione anti-replay
    time_validator.validate_offer_time(self.issued_at_ms, self.ttl_s)?;
    
    // Verifica commit
    let k_offer = derive_offer_key_v2(&self.rendezvous.key_enc, self.rendezvous.tag16)?;
    let expected = Self::compute_commit(self, &k_offer)?;
    if self.commit != expected { 
        bail!("Offer commit invalid") 
    }
    
    Ok(())
}
```

### 2.3 Hybrid QR: Resume Token + Deterministic Fallback

#### 2.3.1 Architettura Dual-Layer

L'Hybrid QR rappresenta l'evoluzione più sofisticata del sistema, combinando due meccanismi:

```rust
pub struct HybridQrPayload {
    pub ver: u8,                          // Versione QR (1)
    pub created_at_ms: u64,               // Timestamp creazione
    pub expires_at_ms: u64,               // Scadenza QR
    pub offer: String,                    // Offer fallback (base64)
    pub resume_token_id: u64,             // ID sessione
    pub resume_secret: [u8; 32],          // Segreto resumption
    pub resume_expires_at_ms: u64,        // Scadenza resume
    pub caps: u32,                        // Capability flags
    pub relay_hints: Vec<String>,         // Suggerimenti relay
    pub checksum: [u8; 32],               // Blake3 integrity
}
```

#### 2.3.2 Dual TTL Strategy

Il sistema implementa una strategia di doppia scadenza:

| Parametro | Default | Scopo |
|-----------|---------|-------|
| `DEFAULT_QR_TTL_MS` | 1 ora | Validità del QR visivo |
| `DEFAULT_RESUME_TTL_MS` | 15 minuti | Validità token resumption |

**Logica di scadenza effettiva**:
```rust
let effective_expiry = std::cmp::min(offer_expiry, qr_ttl_requested);
```

**Vantaggi**:
- Il QR può scadere mentre il resume token rimane valido
- Permette sessioni a lungo termine senza rigenerare il QR
- Diversi requisiti di sicurezza per visualizzazione vs resumption

#### 2.3.3 Capability Flags

I capability flags consentono negoziazione delle feature:

```rust
pub const CAP_TOR: u32 = 1 << 0;      // Supporto trasporto Tor
pub const CAP_UDP: u32 = 1 << 1;      // Trasporto UDP/LAN-WAN
pub const CAP_QUIC: u32 = 1 << 2;     // Protocollo QUIC (riservato)
pub const CAP_WEBRTC: u32 = 1 << 3;   // Supporto WebRTC (riservato)
```

**Utilizzo**:
- Il client può scegliere il trasporto ottimale basandosi sulle capability
- Fallback automatico se un trasporto non è supportato
- Estensibilità per futuri protocolli

#### 2.3.4 Checksum Blake3

L'integrità del payload Hybrid QR è garantita da Blake3:

```rust
fn compute_checksum(&self) -> Result<[u8; 32]> {
    let mut tmp = self.clone();
    tmp.checksum = [0u8; 32];  // Azzera campo checksum
    let bytes = bincode::serialize(&tmp)?;
    
    let mut ctx = blake3::Hasher::new();
    ctx.update(b"handshacke-qr-v1\0");  // Domain separation
    ctx.update(&bytes);
    
    Ok(*ctx.finalize().as_bytes())
}
```

**Caratteristiche**:
- Domain separation previene collisioni cross-protocol
- Blake3 offre prestazioni superiori rispetto a SHA-256
- Checksum calcolato su tutti i campi eccetto il checksum stesso

#### 2.3.5 Flusso di Connessione Hybrid

```
Client scansiona Hybrid QR
    ↓
Decodifica base64 → bincode deserialize
    ↓
Verifica checksum Blake3
    ↓
Verifica scadenza QR
    ↓
Estrae resume_token_id + resume_secret
    ↓
TENTATIVO 1: Resume Session
    POST /v1/connect con resume token
    ↓ Successo?
Sì → Connessione stabilita rapidamente
No  →
    TENTATIVO 2: Fallback Offer
    Decodifica offer incorporato
    Verifica HMAC commitment
    Connessione classica con offer
```

**Vantaggi del flusso ibrido**:
1. **Velocità**: Resume token evita handshake completo
2. **Affidabilità**: Fallback deterministico garantisce connessione
3. **Flessibilità**: Adatto a scenari con connettività variabile

### 2.4 Phrase QR: Tor-Only Invite

#### 2.4.1 Modello di Sicurezza

Il Phrase QR implementa un modello di autenticazione a due fattori:

| Fattore | Contenuto | Canale |
|---------|-----------|--------|
| **Something you have** | QR con invite string | Visivo/scansionato |
| **Something you know** | Passphrase privata | Out-of-band separato |

**Proprietà chiave**: La passphrase NON è mai inclusa nel QR

#### 2.4.2 Flusso di Invito

```
Host:
1. Inserisce passphrase (privata, non in QR)
2. POST /v1/phrase/open
3. Riceve invite string
4. Genera QR con invite
5. Mostra QR al client

Client:
1. Scansiona QR → ottiene invite
2. Inserisce passphrase (ricevuta separatamente)
3. POST /v1/phrase/join con invite + passphrase
4. Connessione Tor-only stabilita
```

#### 2.4.3 Vantaggi per la Privacy

- **Nessun metadata WAN**: Solo Tor, nessun endpoint pubblico
- **Resistenza alla censura**: Tor nasconde la comunicazione
- **No discovery broadcast**: Niente traffico LAN visibile
- **Separation of concerns**: Identità (QR) separata da autenticazione (passphrase)

---

## 3. Architettura di Sicurezza Layered

### 3.1 Modello di Minaccia per i QR

#### 3.1.1 Vettori di Attacco

| Attacco | Livello | Mitigazione | Severity |
|---------|---------|-------------|----------|
| **QR Interception** | Fisico | TTL limitato, passphrase non inclusa | Medio |
| **QR Replay** | Rete | Timestamp + expiry validation | Basso |
| **Tampering** | Dati | Blake3 checksum + HMAC commit | Basso |
| **Endpoint Poisoning** | Sistema | Commit verification, Tor encryption | Medio |
| **Man-in-the-Middle** | Rete | Noise Protocol XX, X25519 | Basso |

#### 3.1.2 Analisi QR Interception

**Scenario**: Un attaccante scansiona il QR prima del peer legittimo.

**Impatto**:
- L'attaccante ottiene gli endpoint di connessione
- NON ottiene la passphrase (non inclusa nel QR)
- NON può decifrare il traffico (richiede passphrase per derivare le chiavi)
- Può tentare di connettersi, ma il handshake Noise fallirà

**Conclusione**: Il QR interception non compromette la riservatezza.

### 3.2 Layer di Sicurezza

#### 3.2.1 Layer 1: Integrità del Payload (Blake3)

```
HybridQrPayload
    ↓
Blake3 Hash (domain-separated)
    ↓
Verifica checksum
```

**Proprietà**: Rileva qualsiasi modifica del payload QR.

#### 3.2.2 Layer 2: Integrità dell'Offer (HMAC-SHA256)

```
OfferPayload
    ↓
HMAC-SHA256(k_offer)
    ↓
Verifica commit
```

**Proprietà**: Autentica l'offer e garantisce l'integrità dei parametri di rendezvous.

#### 3.2.3 Layer 3: Confidenzialità Tor (X25519 + ChaCha20-Poly1305)

```
Tor Onion Address
    ↓
X25519 ECDH
    ↓
ChaCha20-Poly1305 AEAD
    ↓
Ciphertext nel QR
```

**Proprietà**: Nasconde l'indirizzo onion da osservatori del QR.

#### 3.2.4 Layer 4: Sicurezza del Trasporto (Noise Protocol XX)

```
Peer A                    Peer B
   |                         |
   |-- ephemeral pubkey ---->|
   |<-- ephemeral pubkey ----|
   |-- static pubkey, auth -->|
   |<-- static pubkey, auth -|
   |                         |
   [XChaCha20-Poly1305 data]
```

**Proprietà**: Mutual authentication, forward secrecy, resistance to KCI.

### 3.3 Gestione del Tempo e Anti-Replay

#### 3.3.1 Validazione Temporale

```rust
pub struct TimeValidator {
    max_clock_skew_ms: u64,  // 30 secondi default
    ntp_offset: Option<i64>, // Offset NTP se disponibile
}

impl TimeValidator {
    pub fn validate_offer_time(&self, issued_at_ms: u64, ttl_s: u64) -> Result<()> {
        let now = self.current_time_ms()?;
        let expiry = issued_at_ms.saturating_add(ttl_s.saturating_mul(1000));
        
        // Anti-replay: rifiuta offerte troppo vecchie
        if now > expiry + self.max_clock_skew_ms {
            bail!("Offer expired");
        }
        
        // Anti-future: rifiuta offerte dal futuro
        if issued_at_ms > now + self.max_clock_skew_ms {
            bail!("Offer from future");
        }
        
        Ok(())
    }
}
```

#### 3.3.2 Sliding Window Replay Protection

Per le sessioni attive, il sistema implementa protezione replay con finestra scorrevole:

```rust
pub struct ReplayProtection {
    window_size: u64,        // Dimensione finestra
    last_accepted: u64,      // Ultimo timestamp accettato
    seen: HashSet<u64>,      // Nonces visti nella finestra
}
```

---

## 4. Integrazione con il Sistema di Trasporto

### 4.1 QR-Enrichment con STUN

Il sistema arricchisce i QR con informazioni STUN per migliorare la connettività:

```
Host:
1. Avvia discovery endpoint LAN
2. Query STUN server → ottiene public IP:port
3. Arricchisce OfferPayload con stun_public_addr
4. Genera QR con endpoint pubblico

Client:
1. Decodifica QR
2. Ottiene endpoint STUN-discovered
3. Tenta connessione diretta all'endpoint pubblico
4. Se NAT lo permette → connessione diretta
5. Se NAT simmetrico → fallback a relay/Tor
```

### 4.2 Transport Cascade e QR

I QR si integrano nella cascata di trasporto:

```
┌─────────────────────────────────────────────────────────────┐
│                    TRANSPORT CASCADE                         │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  1. LAN Discovery (UDP broadcast)                           │
│     └─ QR fornisce hint endpoint per matching più rapido    │
│                                                              │
│  2. WAN Direct (UPnP/NAT-PMP/STUN)                          │
│     └─ QR contiene endpoint pubblico da STUN enrichment     │
│                                                              │
│  3. WAN Assist (Relay)                                      │
│     └─ Hybrid QR include relay hints per connessione        │
│        garantita                                            │
│                                                              │
│  4. Tor Fallback                                            │
│     └─ QR include indirizzo onion crittografato             │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### 4.3 Multipath Racing

Il sistema utilizza un approccio ICE-inspired per il multipath racing:

```
Tutti i trasporti tentano connessione in parallelo:

LAN UDP ──────┐
WAN Direct ────┼──► Primo successo vince
STUN Hole ─────┤    Altri vengono chiusi
Tor Circuit ───┘

Il QR fornisce i "candidate" per questa gara:
- LAN endpoint
- WAN endpoint (STUN-enriched)
- Tor onion (encrypted)
- Relay hints (Hybrid QR)
```

---

## 5. Analisi UX e Flussi Utente

### 5.1 Pattern di Interazione

#### 5.1.1 Flusso Host

```
┌─────────────────────────────────────────────────────────┐
│  1. Seleziona modalità dalla home screen                │
│     [Offer QR] [Hybrid QR] [Phrase QR]                  │
│                      ↓                                  │
│  2. Avvia daemon (se non running)                       │
│                      ↓                                  │
│  3. Inserisce passphrase                                │
│     ┌─────────────────────────┐                         │
│     │  [Passphrase input]     │                         │
│     │  [Include Tor] ☑        │                         │
│     │  Role: [Host] [Client]  │                         │
│     └─────────────────────────┘                         │
│                      ↓                                  │
│  4. Genera QR                                           │
│     ┌─────────────────────────┐                         │
│     │  [QR Code Image]        │                         │
│     │  Expires in: 59:23      │                         │
│     │  [Copy] [Regenerate]    │                         │
│     └─────────────────────────┘                         │
│                      ↓                                  │
│  5. Mostra QR al client                                 │
└─────────────────────────────────────────────────────────┘
```

#### 5.1.2 Flusso Client

```
┌─────────────────────────────────────────────────────────┐
│  1. Seleziona stessa modalità                           │
│                      ↓                                  │
│  2. Avvia daemon                                        │
│                      ↓                                  │
│  3. Input QR content                                    │
│     ┌─────────────────────────┐                         │
│     │  [Paste QR content]     │                         │
│     │  o [Scan QR]            │                         │
│     └─────────────────────────┘                         │
│                      ↓                                  │
│  4. Seleziona ruolo locale                              │
│     [Host] [Client]                                     │
│                      ↓                                  │
│  5. Connetti                                            │
│     [Connect via QR]                                    │
└─────────────────────────────────────────────────────────┘
```

### 5.2 Wizard-Based Progressive Disclosure

L'interfaccia utilizza un pattern wizard per guidare l'utente:

**Offer QR Wizard**:
```
Step 1: Start daemon    [x]
Step 2: Set passphrase  [x]
Step 3: Generate QR     [→]  ← Current
Step 4: Client connects [ ]
```

**Hybrid QR Wizard**:
```
Step 1: Start daemon
Step 2: Set passphrase
Step 3: Generate Hybrid QR
Step 4: Client connects (resume + fallback)
```

**Phrase QR Wizard**:
```
Step 1: Start daemon
Step 2: Host opens phrase
Step 3: Share invite
Step 4: Client joins
```

### 5.3 Feedback Visivo

Il sistema fornisce feedback visivo multi-livello:

#### 5.3.1 Checklist di Stato

```
[x] Daemon running
[x] Passphrase set
[ ] Offer generated  ← Da completare
```

#### 5.3.2 Phase Bar

Visualizza il progresso della connessione:
```
Derive → Offer → Dial → Noise → Ready
  [x]     [x]    [→]    [ ]     [ ]
```

#### 5.3.3 Status Badge

Color-coded connection status:
- 🟢 **OK**: Connessione stabilita
- 🟡 **Warn**: Fallback attivo (es. TCP invece di UDP)
- 🔵 **Info**: Connessione in corso
- ⚪ **Muted**: Non connesso

#### 5.3.4 Countdown Scadenza

```
QR expires in: 59:23
Resume expires in: 14:23
```

### 5.4 Gestione Errori

#### 5.4.1 Validazione Input

```typescript
// Bottone disabilitato se prerequisiti non soddisfatti
disabled={!apiReady || !passphrase.trim()}
disabled={!apiReady || !hybridQrInput.trim()}
```

#### 5.4.2 Warning Condizionali

```jsx
{connectStatus?.mode === "wan_tcp" && (
    <div className="warning-text">
        UDP blocked detected. TCP fallback active. 
        For reliability, prefer Offer/Hybrid QR with Tor relay.
    </div>
)}

{isSymmetricNat && (
    <div className="warning-text">
        Symmetric NAT detected. Direct paths are unreliable. 
        Prefer Offer/Hybrid QR with Tor relay.
    </div>
)}
```

### 5.5 Confronto Flussi UX

| Aspetto | Offer QR | Hybrid QR | Phrase QR |
|---------|----------|-----------|-----------|
| **Complessità** | Bassa | Media | Alta |
| **Velocità re-join** | Lenta | Veloce | Media |
| **Configurazione** | Minima | TTL + relay hints | Passphrase separata |
| **Affidabilità** | Media | Alta | Alta (Tor) |
| **Privacy** | Media | Media | Alta |
| **Caso d'uso ideale** | One-shot | Ricorrente | Censura-resistant |

---

## 6. Valutazione e Discussioni

### 6.1 Contributi Scientifici

#### 6.1.1 Modello Formale di Rendezvous QR-Based

Il paper contribuisce con un modello formale per il rendezvous P2P tramite QR:

**Definizione**: Un sistema di rendezvous QR-based è una tupla:
```
R = (P, Q, T, V, C)

Dove:
- P: Insieme dei peer
- Q: Insieme dei payload QR
- T: Funzione di tempo (timestamp, TTL)
- V: Funzione di verifica (checksum, commit)
- C: Funzione di connessione
```

**Proprietà di sicurezza**:
1. **Completeness**: Se due peer onesti scambiano un QR valido, la connessione avviene
2. **Soundness**: Se un QR è valido, i parametri di connessione sono autentici
3. **Freshness**: I QR hanno TTL limitato per prevenire replay
4. **Privacy**: Il QR non espone la passphrase o chiavi private

#### 6.1.2 Analisi Comparativa

| Sistema | Metodo Rendezvous | QR Support | Serverless | NAT Traversal |
|---------|-------------------|------------|------------|---------------|
| **Handshacke** | Passphrase + QR | Nativo | Sì | Cascata |
| **Signal** | Safety Numbers | Sì (Web) | No | N/A |
| **WhatsApp** | QR Web | Sì | No | N/A |
| **Tox** | DHT + ID | No | Sì | Limited |
| **WebRTC** | ICE + Signaling | No | No | STUN/TURN |
| **Tor** | Onion addresses | No | Parziale | Built-in |

### 6.2 Vantaggi dell'Approccio QR

#### 6.2.1 Vantaggi Tecnici

1. **Out-of-band channel**: Il QR fornisce un canale sicuro fuori banda per lo scambio di parametri
2. **Time-bound security**: TTL limitato riduce la finestra di attacco
3. **No server required**: Nessun server di segnalazione necessario
4. **Metadata minimization**: Solo i parametri essenziali sono inclusi
5. **Layered security**: Multipli layer di verifica (checksum, commit, Noise)

#### 6.2.2 Vantaggi di Usabilità

1. **No typing**: Elimina errori di inserimento IP/porte
2. **Visual confirmation**: L'utente vede cosa sta condividendo
3. **Progressive disclosure**: Wizard guida l'utente passo-passo
4. **Clear expiration**: Countdown visivo della scadenza
5. **Multiple modes**: Tre flussi per diversi livelli di esperienza

### 6.3 Limitazioni e Trade-off

#### 6.3.1 Limitazioni Tecniche

1. **QR size**: Payload grandi richiedono QR densi (versione 10+)
2. **Camera requirement**: Richiede dispositivo con fotocamera
3. **Line of sight**: Richiede prossimità fisica o screen sharing
4. **No real-time update**: Il QR è statico una volta generato

#### 6.3.2 Trade-off Sicurezza-Usabilità

| Trade-off | Descrizione | Decisione in Handshacke |
|-----------|-------------|-------------------------|
| **TTL breve vs lungo** | Sicurezza vs comodità | Configurabile (default 1h) |
| **Hybrid vs Offer** | Complessità vs re-join | Entrambi disponibili |
| **Tor vs Direct** | Privacy vs latenza | Scelta utente |
| **Passphrase in QR** | Comodità vs sicurezza | MAI inclusa |

### 6.4 Considerazioni sulla Privacy

#### 6.4.1 Metadata Exposure

Il QR espone i seguenti metadata:
- Endpoint IP/porta (LAN/WAN)
- Timestamp di creazione
- Capability flags
- Relay hints (Hybrid QR)

**Mitigazioni**:
- Tor endpoint è crittografato
- Phrase QR non include endpoint WAN
- TTL limitato riduce la finestra di esposizione

#### 6.4.2 Correlation Attacks

Un osservatore di rete potrebbe correlare:
- QR generation time → connection attempt time
- Endpoint nel QR → connessioni in entrata

**Mitigazioni**:
- Tor transport nasconde gli endpoint reali
- Relay hints offuscano la topologia
- Rate limiting previene scanning

---

## 7. Conclusioni

### 7.1 Sintesi

Questo paper ha presentato un'analisi approfondita dell'utilizzo dei codici QR nei sistemi P2P, utilizzando Handshacke come caso di studio. I principali contributi includono:

1. **Analisi tecnica** di tre flussi QR distinti (Offer, Hybrid, Phrase)
2. **Modello di sicurezza layered** con verifica multipla (Blake3, HMAC, Noise)
3. **Integrazione con trasporto** multipath e NAT traversal
4. **Analisi UX** con pattern wizard e progressive disclosure

### 7.2 Implicazioni per la Ricerca

Il lavoro solleva diverse questioni di ricerca:

1. **Formal verification**: Verifica formale delle macchine a stati ICE e dei parser QR
2. **Post-quantum transition**: Migrazione a crittografia post-quantum in sistemi QR-based
3. **Adversarial robustness**: Resistenza a DPI avanzati e ML-based detection
4. **Byzantine gossip**: Protocolli gossip bizantini per discovery senza server

### 7.3 Linee Guida per Implementazioni Future

Basandoci sull'analisi di Handshacke, proponiamo le seguenti linee guida:

#### 7.3.1 Design Principles

1. **Mai includere segreti nel QR**: Passphrase, chiavi private, ecc. devono essere sempre out-of-band
2. **Implementare doppia scadenza**: Separare TTL del QR visivo da TTL del token di sessione
3. **Usare domain-separated hashing**: Prevenire collisioni cross-protocol
4. **Fornire fallback deterministico**: Hybrid approach per massima affidabilità
5. **Supportare capability negotiation**: Flags per negoziazione trasporto

#### 7.3.2 UX Guidelines

1. **Wizard-based onboarding**: Guidare l'utente attraverso i passaggi complessi
2. **Visual countdown**: Mostrare sempre la scadenza del QR
3. **Clear security messaging**: Spiegare cosa è incluso e cosa no nel QR
4. **Contextual help**: Suggerimenti basati sul tipo di NAT rilevato
5. **Multiple entry points**: Supportare sia scan che paste manuale

#### 7.3.3 Security Checklist

- [ ] Checksum crittografico (Blake3/SHA-256) su tutto il payload
- [ ] HMAC commitment per i parametri di rendezvous
- [ ] Validazione temporale con clock skew tolerance
- [ ] Encryption per endpoint sensibili (Tor)
- [ ] Rate limiting sulla generazione QR
- [ ] Anti-replay protection per sessioni
- [ ] Zeroize della memoria dopo uso
- [ ] Domain separation nelle funzioni di hash

### 7.4 Conclusione Finale

I codici QR rappresentano un meccanismo elegante ed efficace per il rendezvous in sistemi P2P, offrendo il giusto equilibrio tra sicurezza, usabilità e flessibilità. L'approccio layered di Handshacke, con tre flussi distinti per scenari diversi, dimostra come i QR possano essere adattati a diverse minacce e requisiti di privacy.

Il modello di sicurezza, basato su verifica multipla (checksum → commit → Noise handshake), fornisce difesa in profondità contro attacchi a vari livelli. La separazione tra identità (QR) e autenticazione (passphrase out-of-band) rappresenta una best practice applicabile a molti sistemi distribuiti.

Quando correttamente implementati con le linee guida descritte in questo paper, i QR-based rendezvous possono diventare uno standard de facto per la connessione P2P, combinando la semplicità d'uso delle applicazioni consumer con la robustezza richiesta dagli ambienti enterprise.

---

## Riferimenti

1. Krawczyk, H., et al. (2010). "HMAC-based Extract-and-Expand Key Derivation Function (HKDF)". RFC 5869.
2. Biryukov, A., et al. (2016). "Argon2: New Generation of Memory-Hard Functions". USENIX Security.
3. Kobeissi, N., et al. (2017). "Noise Protocol Framework". noiseprotocol.org.
4. Dingledine, R., et al. (2004). "Tor: The Second-Generation Onion Router". USENIX Security.
5. RFC 5389: Session Traversal Utilities for NAT (STUN)
6. RFC 5245: Interactive Connectivity Establishment (ICE)
7. RFC 7748: Elliptic Curves for Security (X25519)
8. RFC 8439: ChaCha20 and Poly1305 for IETF Protocols
9. Bernstein, D.J. (2008). "The Salsa20 Family of Stream Ciphers"
10. Aumasson, J.P., et al. (2013). "BLAKE2: Simpler, Smaller, Fast as MD5"

---

## Appendice A: Strutture Dati Complete

### A.1 HybridQrPayload

```rust
pub const HYBRID_QR_VERSION: u8 = 1;
pub const DEFAULT_RESUME_TTL_MS: u64 = 15 * 60 * 1000;  // 15 minuti
pub const DEFAULT_QR_TTL_MS: u64 = 60 * 60 * 1000;      // 1 ora

pub const CAP_TOR: u32 = 1 << 0;
pub const CAP_UDP: u32 = 1 << 1;
pub const CAP_QUIC: u32 = 1 << 2;
pub const CAP_WEBRTC: u32 = 1 << 3;

#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct HybridQrPayload {
    pub ver: u8,
    pub created_at_ms: u64,
    pub expires_at_ms: u64,
    pub offer: String,
    pub resume_token_id: u64,
    pub resume_secret: [u8; 32],
    pub resume_expires_at_ms: u64,
    pub caps: u32,
    pub relay_hints: Vec<String>,
    pub checksum: [u8; 32],
}
```

### A.2 OfferPayload

```rust
pub const OFFER_VERSION: u8 = 4;
pub const DEFAULT_TTL_SECONDS: u64 = 300;
pub const MAX_CLOCK_SKEW_MS: u64 = 30_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OfferPayload {
    pub ver: u8,
    pub ttl_s: u64,
    pub issued_at_ms: u64,
    pub role_hint: RoleHint,
    pub endpoints: Vec<Endpoint>,
    pub tor_ephemeral_pk: Option<[u8; 32]>,
    pub tor_endpoint_enc: Option<Vec<u8>>,
    pub rendezvous: RendezvousInfo,
    pub stun_public_addr: Option<SocketAddr>,
    pub per_ephemeral_salt: Option<[u8; 16]>,
    pub commit: [u8; 32],
    pub timestamp: u64,
    pub ntp_offset: Option<i64>,
    pub simultaneous_open: bool,
}
```

### A.3 ResumeParams

```rust
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct ResumeParams {
    pub token_id: u64,
    pub resume_secret: [u8; 32],
    pub resume_expires_at_ms: u64,
}
```

---

## Appendice B: API Endpoints QR

### B.1 Generazione Offer QR

```http
POST /v1/offer
Content-Type: application/json

{
  "passphrase": "string",
  "ttl_s": 300,
  "role_hint": "host" | "client",
  "include_tor": true
}

Response:
{
  "offer": "HSK1:AAEAA...",
  "ver": 4,
  "expires_at_ms": 1738790000000,
  "endpoints": ["192.168.1.20:51234", "203.0.113.22:51234", "tor"]
}
```

### B.2 Generazione Hybrid QR

```http
POST /v1/qr/hybrid
Content-Type: application/json

{
  "passphrase": "string",
  "ttl_s": 300,
  "role_hint": "host" | "client",
  "include_tor": true,
  "resume_ttl_s": 900,
  "qr_ttl_s": 3600,
  "relay_hints": ["relay1.example.com", "relay2.example.com"]
}

Response:
{
  "qr": "HSKH1:AAEAA...",
  "offer": "HSK1:AAEAA...",
  "ver": 1,
  "expires_at_ms": 1738790000000,
  "resume_expires_at_ms": 1738789100000,
  "endpoints": ["192.168.1.20:51234", "203.0.113.22:51234", "tor"],
  "relay_hints": ["relay1.example.com"]
}
```

### B.3 Connessione via Hybrid QR

```http
POST /v1/connect
Content-Type: application/json

{
  "qr": "HSKH1:AAEAA...",
  "local_role": "host" | "client"
}
```

### B.4 Phrase Flow

```http
# Host apre phrase
POST /v1/phrase/open
{
  "passphrase": "string"
}

Response:
{
  "invite": "hs1:AAAA..."
}

# Client join
POST /v1/phrase/join
{
  "invite": "hs1:AAAA...",
  "passphrase": "string"
}
```

---

## Appendice C: Esempi di QR Payload

### C.1 Offer QR (decodificato)

```json
{
  "ver": 4,
  "ttl_s": 300,
  "issued_at_ms": 1738790000000,
  "role_hint": "host",
  "endpoints": [
    {"kind": "lan", "addr": "192.168.1.20:51234", "priority": 10, "timeout_ms": 1200},
    {"kind": "wan", "addr": "203.0.113.22:51234", "priority": 20, "timeout_ms": 2000}
  ],
  "tor_ephemeral_pk": "base64_encoded_32bytes",
  "tor_endpoint_enc": "base64_encoded_encrypted_onion",
  "rendezvous": {
    "port": 51234,
    "tag16": 12345,
    "key_enc": "base64_encoded_32bytes"
  },
  "stun_public_addr": "203.0.113.22:51234",
  "commit": "base64_encoded_32bytes_hmac",
  "timestamp": 1738790000000
}
```

### C.2 Hybrid QR (decodificato)

```json
{
  "ver": 1,
  "created_at_ms": 1738790000000,
  "expires_at_ms": 1738793600000,
  "offer": "HSK1:AAEAA...",
  "resume_token_id": 123456789,
  "resume_secret": "base64_encoded_32bytes",
  "resume_expires_at_ms": 1738789100000,
  "caps": 3,
  "relay_hints": ["relay1.example.com:8080"],
  "checksum": "base64_encoded_32bytes_blake3"
}
```

---

*Documento Versione: 1.0*  
*Data: Febbraio 2025*  
*Caso di Studio: Handshacke P2P Framework*  
*Parole: ~8,000*
