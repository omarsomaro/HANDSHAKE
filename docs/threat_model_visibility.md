# **Handshacke P2P Framework: Operational Threat Model Analysis**
# **Visibility & Exposure Assessment by Transport Layer**

---

## **Executive Summary**

This document provides a comprehensive operational threat model analyzing **who can see what** across each transport layer in the Handshacke P2P framework. Unlike traditional security papers focusing on CVEs, this analysis maps **information exposure, visibility degrees, and surveillance capabilities** for every actor in the communication chain.

**Key Question Answered**: For each transport layer, what information is exposed to which actors, and with what degree of visibility?

---

## **Actor Taxonomy**

### **Passive Observers** (No injection capability)
- **ISP/Backbone Provider**: Observes raw traffic, application behaviors, temporal patterns
- **Network Administrator**: LAN-level visibility, ARP tables, DHCP logs
- **Government Surveillance**: Backbone taps, legal interception points
- **Enterprise Firewall**: Corporate network monitoring, DPI systems

### **Active Attackers** (Can inject/modify traffic)
- **LAN Attacker**: ARP spoofing, packet injection, broadcast manipulation
- **Compromised Gateway**: Malicious router/NAT device
- **Malicious Relay**: WAN Assist relay running adversarial code
- **Tor Guard/Middle**: Can perform traffic correlation, circuit manipulation
- **Stun Server Operator**: Can respond with crafted binding responses

### **Legitimate Participants**
- **Local Peer**: Your node (intended recipient)
- **Remote Peer**: Counterparty in P2P session (post-handshake)
- **Tor Exit**: Sees plaintext to clearnet destinations

### **Infrastructure Providers**
- **UPnP/NAT-PMP Gateway**: Network device providing port mapping
- **DNS Resolver**: Observes DNS queries (if any)
- **NTP Server**: Observes time synchronization requests (if used)

---

## **Information Exposure Categories**

### **Category 1: Full Content** (Decrypted payload)
- **Visibility**: Complete message content
- **Impact**: Total confidentiality breach
- **Mitigation**: Only after Noise handshake

### **Category 2: Encrypted Content** (Ciphertext only)
- **Visibility**: Encrypted payload
- **Impact**: No direct confidentiality breach (IND-CCA secure)
- **Attack Vector**: Traffic analysis, metadata leakage

### **Category 3: Network Metadata** (IP addresses, ports)
- **Visibility**: Source/destination IPs, ports, protocols
- **Impact**: Relationship mapping, geolocation
- **Attack Vector**: Traffic correlation, timing analysis

### **Category 4: Temporal Metadata** (Timing, rates, patterns)
- **Visibility**: Connection times, RTT, burst patterns, flow duration
- **Impact**: User behavior profiling, content inference
- **Attack Vector**: Statistical analysis, machine learning classifiers

### **Category 5: Protocol Metadata** (Protocol type, version, features)
- **Visibility**: Transport protocol, version, fingerprints
- **Impact**: Application identification, policy enforcement
- **Attack Vector**: DPI fingerprinting, active probing

### **Category 6: Relationship Metadata** (Who talks to whom)
- **Visibility**: Peer identities, connection graph
- **Impact**: Social graph construction, targeted surveillance
- **Attack Vector**: Metadata analysis over time

---

## **Layer 1: LAN Discovery (Local Network)**

### **Transport Mechanism**
- UDP broadcast on 5353 (mDNS) or configured port
- Direct ARP/IP communication for responding peers
- Passive listening mode (stealth)

### **Actors & Visibility**

#### **➤ LAN Attacker (Same Broadcast Domain)**

**Full Visibility (Passive)**:
- ✅ **Category 3**: Source MAC/IP of broadcasting peer
- ✅ **Category 4**: Broadcasting frequency, timing patterns
- ✅ **Category 5**: Protocol fingerprint (custom UDP, not standard mDNS)
- ✅ **Category 6**: Which IPs are running Handshacke (discovery responses)

**Full Visibility (Active - ARP spoof)**:
- ✅ **Category 2**: Can intercept and modify broadcast traffic
- ✅ **Category 1**: If attacker responds before legitimate peer, can MITM

**Visibility Degree**: **TOTAL COMPROMISE**
- **Content**: Encrypted (until handshake complete)
- **Identity**: Source MAC/IP fully visible
- **Behavior**: Broadcasting patterns reveal P2P activity
- **Relationships**: Which peers respond

**Exposure Window**: Continuous while discovering

#### **➤ Network Administrator**

**Full Visibility**:
- ✅ **Category 3**: ARP tables show active IPs
- ✅ **Category 4**: Broadcast/multicast traffic volume
- ✅ **Category 5**: Custom UDP protocol (non-standard ports)
- ✅ **Category 6**: DHCP lease logs → device identity mapping

**Visibility Degree**: **ADMINISTRATOR TOTAL VIEW**
- Can identify which machines run P2P software
- Can timestamp activity for forensics
- Could enable port mirroring for deep inspection

#### **➤ ISP/Upstream**

**Visibility**: **NONE** (Link Layer only, doesn't leave LAN)
- ❌ No visibility to broadcast traffic (stops at router)
- ❌ Cannot see Layer 2 frames

**Exception**: If using WiFi with poor security (WEP/WPA2), attacker outside LAN could sniff wireless frames.

#### **➤ Remote Peer**

**Visibility**: **ZERO** (until handshake)
- ❌ Cannot see LAN broadcast (not routable)
- ❌ Only sees traffic after direct connection established

### **Stealth Mode Impact**

**Normal Mode vs Stealth Mode**:

| Actor | Normal Mode Visibility | Stealth Mode Visibility |
|-------|------------------------|-------------------------|
| LAN Attacker | ✅ All broadcast traffic | ⚠️ Only responses to received unicasts |
| Network Admin | ✅ High broadcast volume | ⚠️ No broadcast volume |
| Passive IDS | ✅ Can fingerprint protocol | ❌ No proactive signature (silent) |

**Trade-off**: Stealth mode reduces visibility but also reduces peer discovery speed.

---

## **Layer 2: WAN Direct (UPnP/NAT-PMP/PCP)**

### **Transport Mechanism**
- UPnP SSDP multicast discovery (239.255.255.250:1900)
- NAT-PMP unicast to gateway (224.0.0.1:5351)
- PCP multicast discovery (224.0.0.1)
- Port mapping requests to gateway (internal IP → external IP:port)

### **Actors & Visibility**

#### **➤ Local Gateway (ISP CPE/Home Router)**

**Full Visibility**:
- ✅ **Category 3**: Internal client IP requesting mapping
- ✅ **Category 3**: External port requested and assigned
- ✅ **Category 5**: Protocol used (UPnP/NAT-PMP/PCP)
- ✅ **Category 4**: Timing of requests (frequency patterns)
- ✅ **Category 6**: Can map internal IP → external port:internal port

**Visibility Degree**: **TOTAL MAPPING VISIBILITY**

**Critical Exposure**:
- **Public IP Address**: Gateway knows your public IP (try_stun_binding uses 8.8.8.8)
- **Mapping Strategy**: Pattern of which ports you map reveals application behavior
- **Connection Timing**: When mappings created/destroyed shows when connections active
- **Device Fingerprint**: UPnP user-agent, NAT-PMP version, timing patterns

**Persistence**: Mappings stored in NAT table with 1-24 hour lease → long-lived metadata

**Gateway Logging**: If gateway logs enabled, creates persistent record of:
```
Timestamp, Internal_IP:Port, External_IP:Port, Protocol, Duration
```

#### **➤ ISP (Internet Service Provider)**

**Visibility**: **PARTIAL - METADATA ONLY**

**What ISP Can See**:
- ✅ **Category 3**: Your public IP address (obviously)
- ✅ **Category 4**: Traffic volume to/from your IP
- ✅ **Category 5**: Protocol types (UDP on specific ports)
- ✅ **Category 4**: Connection establishment patterns (burst of packets)

**What ISP CANNOT See** (encrypted):
- ❌ **Category 2**: Content of packets (encrypted after Noise)
- ❌ **Category 1**: Decrypted payload

**Critical Insight**: ISP **CANNOT** see UPnP/NAT-PMP/PCP messages themselves (they stay within LAN):
- UPnP: Multicast 239.255.255.250 → never leaves LAN
- NAT-PMP: Unicast to gateway internal IP → Layer 2 only
- PCP: Multicast 224.0.0.1 → link-local

**ISP Visibility is Indirect**: ISP sees only the **effects** of port mapping:
- Inbound traffic arriving on mapped port
- Outbound traffic from internal client IP
- Can infer mapping exists from bidirectional flow

**Attack Vector**: ISP can **log metadata** per government request:
```
Customer_IP, External_Port, Bytes_Usage, Flow_Duration, Destination_IPs
```

**Legal Interception**: In many jurisdictions, ISPs must retain metadata for 6-24 months.

#### **➤ Malicious Gateway (Compromised Router)**

**Full Visibility**: **WORST CASE**
- ✅ **Category 1**: Could log all traffic if gateway compromised
- ✅ **Category 3**: Complete mapping database
- ✅ **Category 4**: All timing patterns
- ✅ **Category 6**: All connections mapped

**Visibility Degree**: **TOTAL COMPROMISE**

**Attack Scenarios**:
1. **ISP-Complicit CPE**: Carrier-grade NAT with logging
2. **Compromised Firmware**: Router with backdoor
3. **Malicious Router**: Owned by adversary from start

**Mitigation**: Use gateway you control (OpenWrt, pfSense) rather than ISP-provided.

#### **➤ STUN Server Operator (if used)**

**Visibility**: **PARTIAL - LIMITED TO STUN TRAFFIC**

**What STUN Server Sees**:
- ✅ **Category 3**: Your public IP and port (returned in binding response)
- ✅ **Category 4**: Timing of your STUN queries
- ✅ **Category 5**: STUN protocol usage (but that's its purpose)

**What STUN Server CANNOT See**:
- ❌ **Category 2**: Content (STUN only sees binding requests/responses)
- ❌ **Category 6**: Which peers you're connecting to (STUN is for self-discovery only)

**Privacy Risk**: STUN server learns your ISP-assigned public IP (but so does any server you contact).

**Recommendation**: Run your own STUN server or use public ones (Google, Cloudflare).

#### **➤ Internet Backbone** (between gateway and peer)

**Visibility**: **PARTIAL - ENCRYPTED TUNNEL**

**What Backbone Sees**:
- ✅ **Category 3**: Source IP (your public IP), Destination IP (peer's public IP)
- ✅ **Category 3**: Source port (mapped port), Destination port (peer's mapped port)
- ✅ **Category 4**: Traffic volume, flow duration
- ✅ **Category 5**: UDP protocol, packet sizes

**What Backbone CANNOT See**:
- ❌ **Category 2**: Payload encrypted with Noise
- ❌ **Category 1**: No access to decrypted data
- ❌ **Category 6**: Relationship context (just sees two IPs communicating)

**Flow Example**: Backbone observes:
```
Your_IP:31245 → Peer_IP:19845 (UDP)
Encrypted payload of ~1420 bytes
Bidirectional flow for 3 minutes
```

**Correlation Risk**: If adversary monitors both endpoints, can correlate based on:
- Timing (simultaneous start/stop)
- Packet sizes (same encrypted size patterns)
- Volume (matched byte counts)

**Mitigation**: Tor transport makes correlation harder (different IP paths).

### **Exposure Comparison: WAN Direct vs Tor**

| Actor | WAN Direct Visibility | Tor Visibility | Difference |
|-------|----------------------|----------------|------------|
| Gateway | Full mapping data | Only Tor connection | **Tor hides all** |
| ISP | Metadata + public IPs | Tor guard IP only | **Tor hides destination** |
| Backbone | Full metadata | Guard → middle → exit chain | **Tor provides anonymity** |
| Timing | Visible RTT | Multi-hop latency | **Tor adds noise** |
| Volume | Exact byte counts | Padding, multiplexed | **Tor obfuscates** |

**Trade-off**: WAN Direct = faster, less private; Tor = slower, more private.

---

## **Layer 3: STUN Binding**

### **Transport Mechanism**
- UDP requests to STUN server (typically port 3478 or 19302)
- Binding request contains no authentication
- Response contains XOR-MAPPED-ADDRESS (public IP:port)
- Used for NAT type detection

### **Actors & Visibility**

#### **➤ STUN Server Operator**

**Visibility**: **PARTIAL - LIMITED TO STUN**

**What STUN Server Sees**:
- ✅ **Category 3**: Your public IP and source port
- ✅ **Category 4**: Timing of binding requests
- ✅ **Category 5**: STUN protocol version
- ✅ **Category 6**: Transaction ID (can correlate multiple requests from same client)

**What STUN Server CANNOT See**:
- ❌ **Category 2**: No access to data payload (STUN is self-contained)
- ❌ **Category 6**: Who you're connecting to (STUN is only for self-discovery)

**Privacy Impact**: STUN server learns approximately the same information as any server you connect to directly.

**Unique Risk**: STUN server operator can build database of:
- Public IP addresses
- NAT types (based on binding responses from different sources)
- Request patterns (timing, frequency)

**Use Case**: Can map which ISPs use which NAT types.

**Mitigation**: Use multiple public STUN servers (Google `stun.l.google.com:19302`, Cloudflare `stun.cloudflare.com:3478`), rotate between them.

#### **➤ ISP (Path to STUN Server)**

**Visibility**: **PARTIAL - ROUTING METADATA**

**What ISP Sees**:
- ✅ **Category 3**: Your IP → STUN server IP (destination known)
- ✅ **Category 4**: UDP packets to STUN port (3478/19302)
- ✅ **Category 4**: Request volume, burst patterns

**What ISP CANNOT See**:
- ❌ **Category 2**: STUN payload is not encrypted but is protocol-specific
- ❌ **Category 6**: Final STUN response (comes back on different path)

**Unique Insight**: ISP can tell you're doing STUN binding (port 19302 is Google STUN). Could infer you're behind NAT or using P2P software.

#### **➤ Internet Backbone (between ISP and STUN server)**

**Visibility**: **SAME AS ISP** (just routing hops)

**Additional Risk**: Requires DPI to recognize STUN protocol. Standard backbone routers don't inspect payload deeply.

#### **➤ Peer You're Connecting To**

**Visibility**: **ZERO** (until direct connection)
- ❌ Does not participate in STUN at all
- ❌ Cannot see your STUN queries

### **STUN Binding vs STUN with TURN** (Note: Handshacke doesn't use TURN)

**Handshacke uses STUN only for**: Self-discovery (what's my public IP)

**Does NOT use STUN/TURN for**: Relaying data (that's what WAN Assist is for)

**Privacy Advantage**: STUN server doesn't see actual P2P traffic, only metadata queries.

---

## **Layer 4: TCP Hole Punching**

### **Transport Mechanism**
- Simultaneous TCP open attempt
- Both peers SYN to each other's external IP:port
- Requires coordinated timing
- NAT must preserve port mapping for TCP

### **Actors & Visibility**

#### **➤ ISP (Both Sides)**

**Visibility**: **PARTIAL - TCP METADATA**

**What ISP Sees**:
- ✅ **Category 3**: SYN, SYN-ACK, ACK packets
- ✅ **Category 3**: Source/destination IPs and ports
- ✅ **Category 4**: TCP handshake timing (RTT measurements)
- ✅ **Category 5**: TCP protocol (vs UDP)

**What ISP CANNOT See**:
- ❌ **Category 2**: Encrypted payload after handshake
- ❌ **Category 6**: Relationship to peer (just sees connection)

**Unique Fingerprint**: TCP simultaneous open is RARE on internet:
- Normal TCP: Client → SYN, Server → SYN-ACK, Client → ACK
- Simultaneous: Both send SYN simultaneously → Both SYN-ACK → Both ACK

**DPI Detection**: ISP with sophisticated DPI can detect:
- SYN packets without prior ACK
- Both sides initiated simultaneously
- Unusual TCP state machine progression

**Policy Risk**: Some ISPs may flag this as "suspicious P2P behavior".

#### **➤ NAT Device (Gateway)**

**Visibility**: **FULL - STATE TABLE**

**What NAT Sees**:
- ✅ **Category 3**: Internal IP:port → External IP:port mapping creation
- ✅ **Category 4**: Timing of mapping creation
- ✅ **Category 5**: TCP state machine transitions (SYN, SYN-ACK, ACK)
- ✅ **Category 3**: Both peer addresses for simultaneous open

**What NAT Records**:
```
Conntrack entry:
Internal: 192.168.1.100:45678
External: 203.0.113.45:45678 (mapped)
Peer: 198.51.100.23:29845
State: ESTABLISHED
TTL: 3600 seconds
```

**Persistence**: NAT table stores this mapping for hours (configurable).

**Logging Risk**: If gateway logs enabled, creates persistent record of P2P connection.

#### **➤ Internet Backbone** (between gateways)

**Visibility**: **SAME AS ISP**

**Additional Risk**: Backbone routers maintain flow tables that can be analyzed for patterns.

#### **➤ LAN Attacker (Same Network as Initiator)**

**Visibility**: **TOTAL IF ARP-SPOOFING**

**If ARP Spoof Active**:
- ✅ **Category 2**: Can intercept and modify TCP packets
- ✅ **Category 1**: Complete MITM possible

**If No ARP Spoof**:
- ✅ **Category 3**: Can see broadcast ARP requests
- ✅ **Category 4**: Can observe traffic volume
- ❌ Cannot see content

#### **➤ Remote Peer** (After Connection)

**Visibility**: **PEER IS LEGITIMATE**
- ✅ **Category 2**: Encrypted data (Noise-protected)
- ❌ **Category 1**: No access to plaintext (post-handshake)

### **TCP vs UDP Hole Punching: Visibility Comparison**

| Aspect | TCP Visibility | UDP Visibility |
|--------|----------------|----------------|
| ISP detection | Easier (rare pattern) | Harder (common) |
| NAT logging | Detailed state | Simple mapping |
| State table | Complex (SYN, ACK tracking) | Simple (5-tuple) |
| Timeout | Varies (30s-24h) | Typically shorter |
| Fingerprinting | High (simultaneous open) | Low (looks like normal UDP) |

**TCP Conclusion**: More visible to network observers due to unusual pattern.

---

## **Layer 5: ICMP Hole Punching**

### **Transport Mechanism**
- Raw ICMP sockets (requires CAP_NET_RAW)
- Send ICMP Echo Request → triggers UDP pinhole in some NATs
- Unreliable (many NATs don't create pinholes from ICMP)

### **Actors & Visibility**

#### **➤ Operating System (Kernel)**

**Visibility**: **FULL - RAW SOCKET**

**What OS Sees**:
- ✅ **Category 3**: ICMP packet construction
- ✅ **Category 4**: ICMP send timing
- ✅ **Category 5**: ICMP type/code (8/0 for Echo)
- ✅ **Category 6**: Destination IP

**Privilege Requirement**: CAP_NET_RAW or root

**Security Implication**: Application must have elevated privileges → potential privilege escalation vector.

#### **➤ ISP and Backbone**

**Visibility**: **ICMP METADATA**

**What Network Sees**:
- ✅ **Category 3**: ICMP Echo Request → Destination IP
- ✅ **Category 4**: Timing, frequency of ping attempts
- ✅ **Category 5**: ICMP type (8 = Echo)

**What Network CANNOT See**:
- ❌ **Category 2**: Doesn't trigger any mapping (ICMP→UDP pinhole is NAT-internal)
- ❌ Category 3-6: No additional information

**Uniqueness**: ICMP hole punching is INCREDIBLY RARE in legitimate traffic.

**DPI Detection**: Any ICMP from application-level code is suspicious (normally only kernel/ping does ICMP).

**Policy Risk**: Many firewalls block outbound ICMP entirely.

#### **➤ NAT Device**

**Visibility**: **INTERNAL ONLY**

What NAT Sees:
- ✅ ICMP Echo Request → creates internal state
- ✅ MAY create UDP pinhole (proprietary behavior)
- ✅ Records mapping if pinhole created

What NAT Does NOT Log: ICMP doesn't create external mapping, only internal state.

 **Behavior Variation**  :
- **Full Cone NAT**: May create UDP pinhole after ICMP
- **Symmetric NAT**: Likely won't create pinhole
- **Port Restricted**: Depends on NAT implementation
- **Carrier-Grade NAT**: Almost never creates ICMP-triggered pinholes

#### **➤ Destination Host**

**Visibility**: **ECHO ONLY**
- ✅ **Category 2**: Receives ICMP Echo Request with payload
- ✅ **Category 3**: Source IP (your public IP)

**Impact on Destination**: Host processes ping as normal ICMP (may respond with Echo Reply).

**Detection**: Destination may log unusual number of pings from same source.

### **ICMP vs UDP/TCP: Visibility Comparison**

| Actor | ICMP Visibility | UDP Visibility | TCP Visibility |
|-------|----------------|----------------|----------------|
| ISP | Sees ping (rare) | Sees UDP flow | Sees TCP flow |
| NAT | Internal only | Creates mapping | Creates mapping |
| Firewall | Often blocked | Often allowed | Often allowed |
| Adversary | Very suspicious | Less suspicious | Less suspicious |
| Success Rate | Very low | Medium | Low |

**Conclusion**: ICMP hole punching is highly detectable and unreliable.

---

## **Layer 6: Tor Transport**

### **Transport Mechanism**
- SOCKS5 proxy connection to Tor daemon (typically 127.0.0.1:9050)
- Tor establishes multi-hop circuit: Guard → Middle → Exit
- Optional onion service endpoints (.onion addresses)
- Onion service reachability via hidden service descriptors

### **Actors & Visibility**

#### **➤ Tor Client (Your Machine)**

**Full Visibility**:
- ✅ **Category 1**: SOCKS5 authentication credentials (local only)
- ✅ **Category 3**: Tor control port access (if enabled)
- ✅ **Category 6**: Onion address of hidden service (if connecting)

#### **➤ Tor Guard Node (First Hop)**

**Visibility**: **SIGNIFICANT - FIRST HOP**

**What Guard Sees**:
- ✅ **Category 3**: Your real IP address (source of circuit)
- ✅ **Category 4**: Timing of circuit creation, data transmission
- ✅ **Category 5**: Tor protocol version, circuit establishment
- ✅ **Category 6**: Next hop IP (middle node) you're connecting to

**What Guard CANNOT See**:
- ❌ **Category 2**: Content (multiple layers of encryption)
- ❌ **Category 6**: Final destination (exit IP or onion)
- ❌ **Category 6**: Which onion service you're accessing

**Critical Exposure**:
- Guard knows you're using Tor
- Guard knows your real IP
- Guard knows traffic volume (no padding in default Tor)
- Guard could be malicious/compromised

**Guard Persistence**: Same guard used for weeks/months (Tor guard rotation policy)

**Attack Scenarios**:
1. **Malicious Guard**: Run by adversary to harvest client IPs
2. **Compromised Guard**: Hacked to log client IPs
3. **Guard Fingerprinting**: Identifies you're using Handshacke (SOCKS5 patterns)

**Privacy Impact**: High - Guard is single point of trust

#### **➤ Tor Middle Node**

**Visibility**: **LIMITED - OPPORTUNISTIC**

**What Middle Sees**:
- ✅ **Category 3**: Guard IP (previous hop)
- ✅ **Category 3**: Exit IP (next hop)
- ✅ **Category 4**: Encrypted relay cell timing
- ✅ **Category 5**: Tor protocol cells

**What Middle CANNOT See**:
- ❌ **Category 3**: Your real IP (removed by Guard)
- ❌ **Category 6**: Final destination
- ❌ **Category 2**: Content (layer encryption)

**Attack Scenarios**:
1. **Correlation Attack**: If adversary controls both Guard and Middle, can correlate traffic
2. **Traffic Shaping**: Could delay cells to enable timing attacks

**Recommendation**: Use multiple middle nodes (three-hop circuit provides defense in depth).

#### **➤ Tor Exit Node** (if connecting to clearnet, not .onion)

**Visibility**: **TOTAL FOR CLEARNET TRAFFIC**

**What Exit Sees**:
- ✅ **Category 2**: Decrypted traffic to clearnet (Tor decrypts at Exit)
- ✅ **Category 3**: Destination IP/port (clearnet server)
- ✅ **Category 4**: Full TLS handshake (if HTTPS)
- ✅ **Category 5**: Application protocol
- ❌ **Category 3**: Your real IP (removed by Guard/Middle)
- ❌ **Category 6**: Your identity

**TLS Protection**: If connecting to HTTPS site, Exit sees TLS handshake with SNI exposed, but not content (encrypted end-to-end).

**Critical Risk**: Exit can be malicious, perform MITM attacks on non-TLS traffic.

#### **➤ Onion Service Directory (HS-Dir)**

**Visibility**: **ONION METADATA**

**What HS-Dir Sees**:
- ✅ **Category 6**: Hidden service descriptors (onion address → introduction points)
- ✅ **Category 4**: When descriptor published/retrieved
- ✅ **Category 6**: Which hidden services are popular

**What HS-Dir CANNOT See**:
- ❌ **Category 3**: Your IP = visitor (protected)
- ❌ **Category 6**: Who is accessing which hidden service

**Privacy Note**: Hidden service **operator** publishes descriptor to multiple HS-Dirs, but **visitor** fetches descriptor for onion addresses they want to access.

**Attack Scenarios**:
1. **Malicious HS-Dir**: Could return fake introduction points (onion service hijacking)
2. **Descriptor Harvesting**: Map all active onions

#### **➤ Remote Clearnet Destination** (via Tor Exit)

**Visibility**: **SAME AS EXIT (see above)**

**Additional**: Destination sees Exit's IP, not yours.

#### **➤ Remote .onion Peer** (hidden service to hidden service)

**Visibility**: **END-TO-END ENCRYPTED**

**Tor Circuit**: Client → Guard → Middle → Rendezvous → Middle → Guard → Server

**What Each Party Sees**:
- Rendezvous Point: Connects two circuits, sees encrypted cells only
- Client Guard: Cannot identify server
- Server Guard: Cannot identify client

**Perfect Anonymity**: Client and server mutually anonymous.

**Latency**: 6 hops total (vs 3 for clearnet), but provides stronger anonymity.

### **SOCKS5 Authentication Pattern** (Handshacke-Specific)

**Vulnerability**: Tor Guard can fingerprint Handshacke usage

**Normal Tor Browser SOCKS5**:
```
AUTH: No authentication
CONNECT: Domain name (DNS resolution)
```

**Handshacke SOCKS5**:
```
AUTH: May include auth (with Tor configured authentication)
CONNECT: IP address (no DNS)
```

**Fingerprint**: Combination of:
- Connection pattern (many short connections)
- IP-based destination (not domains)
- Timing between SOCKS5 commands

**Adversary**: Guard can identify you're using Handshacke, not Tor Browser.

**Mitigation**: Could use Tor'sIsolateSOCKSAuth option.

### **Onion Service Exposed Endpoint**

**Handshacke Support**: Can run hidden service (.onion address in offer)

**Visibility**:
- **Onion Address**: Published in offer (public)
- **Introduction Points**: 3 Tor nodes chosen by hidden service
- **HS-Dir**: Knows onion → introduction relationship

**Client Access**:
- Client learns onion from offer
- Client fetches descriptor from HS-Dir
- Client connects to introduction points
- Service responds via rendezvous

**Privacy**: Client anonymity preserved, server location hidden.

---

## **Layer 7: WAN Assist Relay (Coordinator)**

### **Transport Mechanism**
- HTTPS/WSS connection to relay server
- Upload/download offers via REST API or WebSocket
- Relay coordinates simultaneous open by exchanging offers between peers
- Tor onion endpoints for relay anonymization

### **Actors & Visibility**

#### **➤ Relay Operator (Honest/Malicious)**

**Full Visibility**: **MAXIMUM EXPOSURE**

**What Relay Sees**:
- ✅ **Category 6**: All offers uploaded to relay
- ✅ **Category 3**: Source IPs connecting to relay (if not using Tor)
- ✅ **Category 4**: When offers uploaded/downloaded
- ✅ **Category 6**: Which hashes are being queried (relationship signal)
- ✅ **Category 5**: Protocol version, client implementations

**Critical Exposure**:

**Offer Content** (encrypted but metadata-rich):
```rust
OfferPayload {
    ver: u8,                    // Protocol version
    ttl_s: u64,                 // Offer lifetime
    role_hint: RoleHint,        // Client/Host
    endpoints: Vec<Endpoint>,   // LAN/WAN/Tor addresses
    tor_ephemeral_pk: Option<[u8; 32]>, // Tor info
    rendezvous: RendezvousInfo, // Port, tag16, key_enc
    per_ephemeral_salt: Option<[u8; 16]>, // Case salt
    commit: [u8; 32],           // Commitment
}
```

**Metadata Leakage**:
- **Network Topology**: From endpoints, can infer NAT types, locations
- **Activity Patterns**: Upload frequency shows connection attempts
- **Peer Relationships**: If attacker queries same hash twice = relationship
- **Timing**: Coordinated queries reveal simultaneous connection attempts

**Example Inference**:
```
Offer uploaded from IP_A at 12:00:00
Offer downloaded by IP_B at 12:00:01
Hash_H queried by both within 30s
→ A and B are communicating
```

**Malicious Relay Attack Scenarios**:

1. **Metadata Harvesting**:
   - Log all offers for traffic analysis
   - Build graph of who talks to whom
   - Sell to advertisers or provide to authorities

2. **Selective DoS**:
   - Refuse to relay offers for specific hashes (targeted blocking)
   - Slow down relay for specific IPs (performance degradation)
   - Drop offers during critical time window (denial of timing)

3. **Offer Injection**:
   - Inject fake offers for hash (poisoning)
   - Redirect peers to malicious endpoints
   - Man-in-the-middle attacks

4. **Timing Correlation**:
   - Relay is centralized → can see both sides of simultaneous open
   - Learn relationship between peers
   - Break anonymity via timing analysis

5. **Sybil Attack on Relay**:
   - Run multiple relay instances
   - Harvest metadata from all instances
   - Control majority of relay infrastructure

**Relay Honesty Model**: Zero-trust architecture assumes relay is **potentially malicious**.

**Defense Mechanisms**:
- **Offer Encryption**: Sensitive fields encrypted, but metadata exposed
- **Tor Relay Access**: Can access relay via .onion address
  - Relay only sees Tor traffic
  - Cannot see real client IP
  - Can still see offers and timing
  - **Metadata still exposed!**

**Trade-off**: Tor to relay protects client IP but not offer metadata.

#### **➤ ISP (Path to Relay)**

**Visibility**: **DEPENDS ON RELAY ACCESS METHOD**

**Direct Access** (no Tor):
- ✅ **Category 3**: Client IP connecting to relay
- ✅ **Category 4**: Encrypted HTTPS/WSS traffic
- ✅ **Category 5**: TLS protocol fingerprint

**Tor Access**:
- ✅ **Category 3**: Guard IP only
- ❌ Cannot see relay IP (hidden)
- ❌ Cannot see offer content (encrypted)

#### **➤ Internet Backbone** (between client and relay)

**Visibility**: **SAME AS ISP**

#### **➤ LAN Attacker** (if client on LAN)

**Visibility**: **ARP-SPOOFING POSSIBLE**

If ARP spoof active:
- ✅ Can redirect relay traffic through attacker
- ✅ Can see offers in plaintext (before encryption to relay)

If no ARP spoof:
- ✅ Only encrypted traffic to relay
- ❌ Cannot see content

#### **➤ Remote Peer** (Other Party in Communication)

**Visibility**: **POST-HANDSHAKE ONLY**

After handshake:
- ✅ Sees that connection came via relay
- ❌ Cannot see relay's metadata operations

**Relay is Transparent**: Peers don't know relay was used for coordination (only see direct connection).

### **Relay Exposure Comparison: Direct vs Tor**

| Actor | Direct Relay Visibility | Tor Relay Visibility | Privacy Gain |
|-------|------------------------|---------------------|--------------|
| Relay Operator | Full metadata + client IP | Full metadata only | ❌ No metadata protection |
| ISP | Client IP → relay IP | Guard IP only | ✅ IP hidden |
| Backbone | Same as ISP | Same as ISP | ✅ IP hidden |
| LAN Attacker | Possible ARP hijack | Same threat | ❓ No change |

**Critical Realization**: Using Tor to access relay **hides client IP but NOT metadata**. Relay still learns timing, offers, relationships.

### **Relay vs Pure P2P (No Relay)**

**Without Relay**:
- Peers must find each other via DHT or static bootstrap
- No central metadata repository
- Harder to coordinate simultaneous open
- But **no metadata exposure to third party**

**With Relay**:
- Easy coordination
- Metadata exposed to relay operator
- Trust in relay required

**Trade-off**: Convenience vs centralization risk.

### **Simultaneous Open Coordination Through Relay**

**Visibility During Coordination**:

```rust
// Client A uploads offer at T=0
// Client B downloads offer at T=500ms
// Both attempt simultaneous open at T=5000ms

Relay Learned:
- A and B are coordinating
- Approximate RTT between A and B
- Both are using same hash (relationship)
- Both attempted connection (success/failure)
```

**Privacy Risk**: Relay can deanonymize relationships even without seeing IPs.

**Mitigation**: Clients could add random delays unrelated to relay coordination, but implementation doesn't show this.

### **Relay Anonymization via Onion Services**

**Advantage**: Relay runs .onion service
- Hidden from clearnet
- Resistant to censorship
- No clearnet infrastructure needed

**Disadvantage**: Still central metadata collection point.

**Tor-to-Relay Flow**:
```
Client → Guard → Middle → Rendezvous → Middle → Guard → Relay.onion
                                             ↑
                                         Hidden service
```

**Multiple Relays**: Could use multiple relays and split traffic across them.
- Hides full offer from any single relay
- Increases complexity
- Current implementation uses single relay

---

## **Layer 8: Multipath Coordination**

### **Transport Mechanism**
- ICE-like candidate gathering and racing
- Simultaneous attempts across multiple transports
- Path quality tracking (RTT, loss rate)
- Fallback between transports

### **Actors & Visibility**

#### **➤ Individual Transport Actors**

**Each transport layer exposes to its respective actors**:
- LAN: Exposes to LAN actors
- UPnP: Exposes to gateway
- STUN: Exposes to STUN server
- Relay: Exposes to relay
- Tor: Exposes to Tor nodes

#### **➤ Multipath Coordinator (ICE Agent)**

**Local to node**: Doesn't expose additional info to network

**What Coordinator Knows**:
- ✅ **Category 6**: All candidates gathered
- ✅ **Category 4**: RTT measurements for each path
- ✅ **Category 6**: Which path succeeded/failed
- ✅ **Category 6**: Switching patterns between transports

**Learning**: Coordinator learns best transport strategy for this network environment.

**Privacy Impact**: Local knowledge only, no network exposure.

### **Path Preference Leakage**

**Information Exposure**:

If adversary observes connections over time:
- Can see which transport is preferred
- Can infer NAT type based on transport selection
- Can fingerprint node capabilities

**Example**:
```
Node always uses UPnP first → likely home network
Node falls back to Tor frequently → likely restrictive NAT
Node never uses LAN → not on local network with peers
```

### **Transport Leakage to Peer**

**What Peer Learns**:
- Which transport was used for this connection
- RTT characteristics (can infer path)
- Whether multipath was used

**Information Value**:
- Can identify if peer is on same LAN
- Can infer peer's network quality
- Can optimize own transport selection

**Privacy Impact**: Low (operational information, not private).

### **Adaptive Transport Learning**

**Behavior Over Time**:

For a given passphrase (same rendezvous port):
- NAT detection results may persist across sessions
- Transport preference learned
- Could create user profile

**Persistence Risk**:

If same passphrase used repeatedly:
- Adversary can track network changes
- ISP can see same port pattern across sessions
- Timing patterns may correlate across days

**Mitigation**: Per-ephemeral-salt randomizes port.

```rust
pub per_ephemeral_salt: Option<[u8; 16]>, // Port randomization
```

**With Salt**: Even same passphrase → different port → different NAT behavior observed.

---

## **Composite Exposure Analysis**

### **Scenario: Client Behind Corporate Firewall → Home User**

**Communication Flow**:

```
Corporate_Client (Double NAT) → Gateway (Firewall) → ISP → Backbone
    ↓                            ↑
    └────────────────── WAN Assist Relay ─────────────→ Home_User (UPnP)

Timeline:
T0: Corp Client builds offer (includes LAN, WAN, Relay candidates)
T1: Corp Client uploads offer to Relay via Tor
   - Tor Guard sees: Encrypted traffic to middle
   - Relay (via Tor) sees: Offer upload, client IP hidden
T2: Home User downloads offer via Tor
   - Relay (via Tor) sees: Offer download
T3: Both attempt connections:
   - Corp cannot reach Home via LAN (different networks)
   - Corp cannot reach Home via WAN (double NAT blocks)
   - Both succeed via Relay
T4: Connection established via relay
   - All traffic through relay
   - Relay sees all metadata
   - Content encrypted (Noise)
```

### **Exposure Timeline**

| Time | Actor | Visibility | Privacy State |
|------|-------|------------|---------------|
| T0 | Corporate Firewall | Sees internal offer building | Compromised (LAN) |
| T1 | Tor Guard | Encrypted to middle | Protected |
| T1 | Relay (via Tor) | Sees offer upload | Metadata exposed |
| T1 | ISP | Tor traffic only | IP hidden |
| T2 | Home User (ISP) | Tor traffic only | IP hidden |
| T2 | Relay (via Tor) | Sees offer download | Metadata exposed |
| T3 | Corporate Firewall | Redirect via relay | Compromised (relay) |
| T3 | ISP | Relay traffic | Encrypted |
| T4 | Relay | Full relay metadata | Metadata exposed |
| T4 | Both Peers | Encrypted end-to-end | Content protected |

### **Privacy Compromise Chain**

**Weakest Links**:
1. **Corporate LAN**: Full LAN visibility
2. **Relay Metadata**: Central metadata repository
3. **Corporate Firewall**: Can force through relay
4. **Tor Guard** (if malicious): Knows client using Tor

**Strong Protection**:
1. **Content**: Always encrypted via Noise
2. **Remote IPs**: Hidden via Tor
3. **Timing**: Obfuscated by multi-hop latency
4. **NAT Inference**: Randomization prevents tracking

---

## **Privacy-Preservation Trade-offs**

### **Transport Selection vs Privacy**

| Transport | Performance | Privacy | Use Case |
|-----------|-------------|---------|----------|
| LAN | Excellent | None (fully exposed) | Same network |
| UPnP/NAT-PMP | Good | Low (gateway sees all) | Home network |
| STUN | Medium | Medium (STUN server sees metadata) | NAT discovery |
| TCP Hole Punch | Medium | Low (unusual pattern) | Restrictive NAT |
| Relay | Good | Low (central metadata) | Coordination |
| Tor | Poor | High (strong anonymity) | Censorship resistance |

### **Multipath Strategy** (Privacy Perspective)

**Concurrent Multipath**:
- **Privacy**: Bad - Multiple simultaneous attempts reveal multiple paths
- **Security**: Good - Faster connection, harder to block

**Sequential Multipath**:
- **Privacy**: Good - Only one transport active at time
- **Security**: Bad - Slower, easier to block

**Racing Privacy Impact**:
- Adversary sees multiple connection attempts
- Can infer network conditions (which succeed/fail)
- Can fingerprint NAT type based on success pattern

**Privacy Recommendation**: Sequential transport attempt preferred for anonymity-sensitive scenarios.

### **Simultaneous Open Privacy**

**Simultaneous Open**:
- **Pro**: Faster connection
- **Con**: Requires precise timing → reveals RTT relationship
- **Con**: Makes correlation easier for observer

**Sequential Open**:
- **Pro**: No coordination, harder to correlate
- **Con**: Slower, may fail on symmetric NAT

**Privacy-Security Trade-off**: Simultaneous improves reliability but harms anonymity slightly.

---

## **Advanced Adversary Scenarios**

### **Scenario 1: Nation-State Adversary** (NSA/GCHQ level)

**Capabilities**:
- Global passive surveillance (upstream fiber taps)
- Active Tor node operation (Guard/Middle)
- Legal access to Tor relay
- Cooperation with ISPs

**Attack Strategy**:

1. **Fiber Tap at Backbone**: Observes all Tor traffic
```
Sees: Encrypted Tor cells between Guard and Middle
From: Your_IP → Guard_IP (initial)
To: Exit_IP → Destination_IP (final)
```

2. **Malicious Guard Operation**: Runs Tor Guard nodes
```
Sees: Circuit establishment from your IP
Knows: You're using Tor
Can: Delay/drop cells selectively
```

3. **Relay Metadata Access**: Subpoenas or compromises relay
```
Gets: All offers uploaded/downloaded
Correlates: Offers with Tor timing
Reconstructs: Peer relationships
```

4. **ISP Cooperation**: Requests logs
```
Gets: Your UPnP request logs
Shows: Port 12345 mapped at time T
Correlates: With Tor circuit timing
Confirms: P2P activity
```

**Result**: Nation-state can **deanonymize relationships** and **confirm P2P usage**, but **cannot decrypt content** (Noise + Tor).

### **Scenario 2: Corporate Insider**

**Capabilities**:
- LAN access
- Network monitoring tools
- Gateway admin access
- May control local relay

**Attack Strategy**:

1. **LAN Sniffing**: Captures all broadcast traffic
```
Sees: Handshacke discovery broadcasts
Identifies: Which machines running P2P
Maps: MAC address → employee identity
```

2. **Gateway Logs**: Accesses NAT table
```
Sees: Port mapping 31245 → external:31245
Correlates: With LAN broadcast source
Identifies: Specific employee connections
```

3. **Local Relay**: Operates relay on corporate network
```
Sees: All offers uploaded by employees
Correlates: With timesheets → who talking to who
```

**Result**: Insider can **identify users, map relationships, prove P2P usage**.

### **Scenario 3: Malicious Relay Operator**

**Capabilities**:
- Runs relay infrastructure
- Controls relay code
- Can modify relay behavior

**Attack Strategy**:

1. **Metadata Harvesting**: Logs all offers
```
Collects: Millions of offers over time
Analyzes: Hash frequency
Maps: Relationship graph
Sells: Data to advertisers/authorities
```

2. **Selective DoS**: Blocks specific offers
```
Target: Hash_H (political dissidents)
Action: Refuse to relay offers for H
Result: Prevents connections for target group
```

3. **Offer Injection**: Inserts fake offers
```
Target: Hash_H
Inject: Fake offers pointing to attacker endpoints
Result: Peers connect to attacker (MITM)
```

4. **Timing Analysis**: Correlates simultaneous opens
```
Observes: A and B querying same hash within 30s
Inferences: A and B are communicating
Maps: Social graph
```

**Result**: Relay operator can **deanonymize, censor, and MITM** all users.

---

## **Privacy Enhancement Recommendations**

### **For Tor Transport**

1. **Always Use Tor for Relay Access**
   - Hide client IP from relay
   - Prevents ISP from seeing relay destination

2. **Multiple Relay Instances**
   - Use different relays
   - Split offer metadata
   - Makes metadata reconstruction harder

3. **Onion Service Only**
   - Don't use clearnet relays
   - Hidden services more censorship-resistant

### **For UPnP/STUN**

1. **Randomize Timing**
   - Add jitter to requests
   - Prevent timing fingerprinting

2. **Use Multiple STUN Servers**
   - Rotate between providers
   - No single provider sees full profile

3. **Disable When Not Needed**
   - Use only if behind appropriate NAT
   - Avoid unnecessary exposure

### **For LAN**

1. **Stealth Mode Default**
   - Passive listening only
   - No broadcast

2. **802.1X Authentication**
   - Enterprise deployments
   - Prevent rogue devices

3. **VLAN Segmentation**
   - Isolate P2P traffic

### **For Multipath**

1. **Sequential First**
   - Try transports sequentially
   - Reduce visibility of multiple attempts

2. **Randomize Order**
   - Don't always try same order
   - Prevents fingerprinting

3. **Limit Exposure**
   - Only try transports appropriate to network

### **For Relay**

1. **Metadata Minimization**
   - Remove unnecessary fields from offer
   - Encrypt all non-essential metadata

2. **Offer Splitting**
   - Send parts to different relays
   - Require recombination

3. **Anonymous Upload**
   - Use anonymous credentials
   - Don't link offers to identity

---

## **Comparison: Visibility by Actor**

| Actor | Best Visibility | Worst Visibility | Key Data Accessed |
|-------|----------------|------------------|-------------------|
| ISP | Direct connections (public IPs) | Tor (only guard) | Metadata, volumes |
| LAN Attacker | Broadcast, ARP | Tor | MAC, IPs, timing |
| Gateway | UPnP/NAT mappings | Tor | Internal:External mappings |
| STUN Server | Binding requests | Tor | Public IP:port |
| Tor Guard | Circuit establishment | - | Client IP, timing |
| Tor Middle | Hop-to-hop | - | Neighbor IPs |
| Tor Exit | Cleartext | - | Destination, content |
| Relay | Offer metadata | Tor (metadata still) | Offers, hashes, timing |
| Malicious Relay | All metadata | - | Relationships, patterns |
| Remote Peer | Post-handshake only | Pre-handshake | Content (encrypted) |

---

## **Operational Security Guidance**

### **High Privacy Scenario** (Whistleblower, Activist)

**Configuration**:
```bash
HANDSHACKE_ENABLE_LAN=false
HANDSHACKE_ENABLE_UPNP=false
HANDSHACKE_ENABLE_STUN=false
HANDSHACKE_FORCE_TOR=true
HANDSHACKE_RELAY_ONLY_ONION=true
HANDSHACKE_RENDEZVOUS_COORDINATION=relay
```

**Trade-offs**: Slow, but maximum anonymity.

**Visibility**:
- ISP: Tor traffic only
- Network: Tor guard only
- Relay: Encrypted + via Tor
- Metadata: Minimal

### **Balanced Security Scenario** (Privacy-conscious user)

**Configuration**:
```bash
HANDSHACKE_ENABLE_LAN=true
HANDSHACKE_ENABLE_UPNP=true
HANDSHACKE_STUN_SERVERS=rotate(gcloud,cloudflare)
HANDSHACKE_ENABLE_TOR=fallback
HANDSHACKE_RELAY_ONION=true
HANDSHACKE_RENDEZVOUS_COORDINATION=relay
```

**Trade-offs**: Fast when possible, falls back to Tor.

**Visibility**:
- Local: LAN/UPnP customized
- ISP: Metadata visible
- Relay: Via Tor
- Tor: Fallback privacy

### **Performance Scenario** (Low privacy need)

**Configuration**:
```bash
HANDSHACKE_ENABLE_LAN=true
HANDSHACKE_ENABLE_UPNP=true
HANDSHACKE_ENABLE_STUN=true
HANDSHACKE_ENABLE_TOR=false
HANDSHACKE_RELAY_DIRECT=true
```

**Trade-offs**: Maximum performance, high visibility.

**Visibility**:
- LAN: Full broadcast
- Gateway: Full logging
- ISP: Full metadata
- No anonymity protections

---

## **Privacy Budget Concept**

**Idea**: Each transport has "privacy cost" that user accumulates. Once budget exceeded, automatically switch to higher privacy transport.

**Costs**:
- LAN: 0 (no outbound network)
- UPnP: 1 (gateway visibility)
- STUN: 2 (STUN server + gateway)
- Relay: 3 (central metadata)
- Tor: 0 (anonymity)

**Threshold**: After cost > 5, force Tor.

**Implementation**: Not currently in codebase, but could be added.

---

## **Metadata Minimization by Layer**

| Layer | Minimization Technique | Effectiveness |
|-------|------------------------|---------------|
| LAN | Stealth mode | High |
| UPnP | Randomized lease duration | Medium |
| STUN | Multiple servers + rotation | Medium |
| TCP Punch | Randomized ports | Low |
| ICMP Punch | Payload encryption | Low |
| Tor | Multi-hop, padding | High |
| Relay | Onion-only access | High |
| Multipath | Sequential selection | High |

---

## **Conclusion**

**Key Findings**:

1. **LAN layer**: Total compromise if attacker on same network. Stealth mode essential.

2. **WAN Direct (UPnP/STUN)**: Gateway is trusted party with full visibility. No cryptographic protection.

3. **Tor**: Provides strong anonymity for IP addresses but NOT for metadata to relay operator.

4. **Relay**: Centralized metadata is privacy Achilles heel. Tor access helps but doesn't solve metadata leakage.

5. **Multipath**: Increases performance but also increases attack surface. Multiple transports = multiple exposure points.

6. **Early drop**: Excellent first line of defense but doesn't prevent metadata leakage.

**Privacy-First Recommendation**:
- Always use Tor for relay access
- Prefer sequential transport attempts (slower but less visible)
- Use long passphrases (not short ones)
- Enable stealth mode on untrusted networks
- Consider running own relay infrastructure

**Performance-First Recommendation**:
- Use all transports concurrently
- Accept higher visibility for speed
- Ensure gateway is trusted
- Use on trusted networks only

**Balanced Approach**:
- Start with fast transports (LAN, UPnP)
- Fall back to private transports (Tor)
- Use per-ephemeral-salt for port randomization
- Accept moderate privacy for usability

---

## **Appendix: Visibility Quick Reference**

### **Quick Decision Tree**

```
Need maximum privacy?
├── Yes → Use Tor only, disable LAN/UPnP/STUN
│   └── Use relay only via .onion
│       └── Ensure passphrase is long (60+ chars)
├── No → Need speed?
│   ├── Yes → Enable all transports
│   │   └── Use trusted gateway
│   └── No → Balanced?
│       └── Use LAN/UPnP/STUN + Tor fallback
└── Network is untrusted?
    ├── Yes → Stealth mode + Tor
    └── No → Normal mode acceptable
```

### **Visibility Score by Transport** (Lower = More Private)

| Transport | Performance | Privacy Score | Actor with Max Visibility |
|-----------|-------------|---------------|---------------------------|
| LAN | Fast | 9/10 (worst) | LAN attacker (full) |
| UPnP | Fast | 8/10 | Gateway (full) |
| STUN | Medium | 6/10 | STUN server + gateway |
| TCP Punch | Medium | 7/10 | ISP (pattern) |
| ICMP Punch | Low | 8/10 | ISP (suspicious) |
| Relay | Good | 5/10 | Relay operator (metadata) |
| Tor | Slow | 1/10 (best) | Exit node (cleartext) |

**Note**: Tor score is 1/10 for source anonymity, but 9/10 for bandwidth/latency cost.

---

**Document Version**: 1.0  
**Analysis Date**: 2025-01-22  
**Analyst**: Security Research Team  
**Classification**: Public - Operational Security Guide  
**Focus**: Visibility and exposure assessment (not CVE analysis)  

---