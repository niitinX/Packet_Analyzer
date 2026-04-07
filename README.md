# DPI Engine - Deep Packet Inspection System

This document explains **everything** about this project - from basic networking concepts to the complete code architecture. After reading this, you should understand exactly how packets flow through the system without needing to read the code.

---

## Table of Contents

1. [What is DPI?](#1-what-is-dpi)
2. [Networking Background](#2-networking-background)
3. [Project Overview](#3-project-overview)
4. [File Structure](#4-file-structure)
5. [The Journey of a Packet (Simple Version)](#5-the-journey-of-a-packet-simple-version)
6. [The Journey of a Packet (Multi-threaded Version)](#6-the-journey-of-a-packet-multi-threaded-version)
7. [Deep Dive: Each Component](#7-deep-dive-each-component)
8. [How SNI Extraction Works](#8-how-sni-extraction-works)
9. [How Blocking Works](#9-how-blocking-works)
10. [Building and Running](#10-building-and-running)
11. [Understanding the Output](#11-understanding-the-output)

---

## 1. What is DPI?

**Deep Packet Inspection (DPI)** is a technology used to examine the contents of network packets as they pass through a checkpoint. Unlike simple firewalls that only look at packet headers (source/destination IP), DPI looks *inside* the packet payload.

### Real-World Uses:
- **ISPs**: Throttle or block certain applications (e.g., BitTorrent)
- **Enterprises**: Block social media on office networks
- **Parental Controls**: Block inappropriate websites
- **Security**: Detect malware or intrusion attempts

### What Our DPI Engine Does:
```
User Traffic (PCAP) → [DPI Engine] → Filtered Traffic (PCAP)
               ↓
          - Identifies apps (YouTube, Facebook, etc.)
          - Blocks based on rules
          - Generates reports
```

---

## 2. Networking Background

### The Network Stack (Layers)

When you visit a website, data travels through multiple "layers":

```
┌─────────────────────────────────────────────────────────┐
│ Layer 7: Application    │ HTTP, TLS, DNS               │
├─────────────────────────────────────────────────────────┤
│ Layer 4: Transport      │ TCP (reliable), UDP (fast)   │
├─────────────────────────────────────────────────────────┤
│ Layer 3: Network        │ IP addresses (routing)       │
├─────────────────────────────────────────────────────────┤
│ Layer 2: Data Link      │ MAC addresses (local network)│
└─────────────────────────────────────────────────────────┘
```

### A Packet's Structure

Every network packet is like a **Russian nesting doll** - headers wrapped inside headers:

```
┌──────────────────────────────────────────────────────────────────┐
│ Ethernet Header (14 bytes)                                       │
│ ┌──────────────────────────────────────────────────────────────┐ │
│ │ IP Header (20 bytes)                                         │ │
│ │ ┌──────────────────────────────────────────────────────────┐ │ │
│ │ │ TCP Header (20 bytes)                                    │ │ │
│ │ │ ┌──────────────────────────────────────────────────────┐ │ │ │
│ │ │ │ Payload (Application Data)                           │ │ │ │
│ │ │ │ e.g., TLS Client Hello with SNI                      │ │ │ │
│ │ │ └──────────────────────────────────────────────────────┘ │ │ │
│ │ └──────────────────────────────────────────────────────────┘ │ │
│ └──────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────┘
```

### The Five-Tuple

A **connection** (or "flow") is uniquely identified by 5 values:

| Field | Example | Purpose |
|-------|---------|---------|
| Source IP | 192.168.1.100 | Who is sending |
| Destination IP | 172.217.14.206 | Where it's going |
| Source Port | 54321 | Sender's application identifier |
| Destination Port | 443 | Service being accessed (443 = HTTPS) |
| Protocol | TCP (6) | TCP or UDP |

**Why is this important?**
- All packets with the same 5-tuple belong to the same connection
- If we block one packet of a connection, we should block all of them
- This is how we "track" conversations between computers

### What is SNI?

**Server Name Indication (SNI)** is part of the TLS/HTTPS handshake. When you visit `https://www.youtube.com`:

1. Your browser sends a "Client Hello" message
2. This message includes the domain name in **plaintext** (not encrypted yet!)
3. The server uses this to know which certificate to send

```
TLS Client Hello:
├── Version: TLS 1.2
├── Random: [32 bytes]
├── Cipher Suites: [list]
└── Extensions:
  └── SNI Extension:
    └── Server Name: "www.youtube.com"  ← We extract THIS!
```

**This is the key to DPI**: Even though HTTPS is encrypted, the domain name is visible in the first packet!

---

## 3. Project Overview

### What This Project Does

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│ Wireshark   │     │ DPI Engine  │     │ Output      │
│ Capture     │ ──► │             │ ──► │ PCAP        │
│ (input.pcap)│     │ - Parse     │     │ (filtered)  │
└─────────────┘     │ - Classify  │     └─────────────┘
          │ - Block     │
          │ - Report    │
          └─────────────┘
```

### Two Versions

| Version | File | Use Case |
|---------|------|----------|
| Simple (Single-threaded) | `packet_analyzer/dpi_simple.py` | Learning, small captures |
| Multi-threaded | `packet_analyzer/dpi_mt.py` | Production, large captures |

---

## 4. File Structure

```
packet_analyzer/
├── pcap_reader.py        # PCAP file reading/writing
├── packet_parser.py      # Network protocol parsing
├── sni_extractor.py      # TLS/HTTP inspection
├── dpi_types.py          # Data structures (FiveTuple, AppType, etc.)
├── rules.py              # Blocking rules
├── thread_safe_queue.py  # Thread-safe queue
├── live_stats.py         # Live stats tracker
├── dpi_simple.py         # ★ SIMPLE VERSION ★
└── dpi_mt.py             # ★ MULTI-THREADED VERSION ★

generate_test_pcap.py     # Creates test data
rules.json                # Sample rules file
api/                      # FastAPI backend
ui/                       # React frontend
README.md                 # This file!
```

---

## 5. The Journey of a Packet (Simple Version)

Let's trace a single packet through `packet_analyzer/dpi_simple.py`:

### Step 1: Read PCAP File

```python
reader = PcapReader(input_path)
reader.open()
```

**What happens:**
1. Open the file in binary mode
2. Read the 24-byte global header (magic number, version, etc.)
3. Verify it's a valid PCAP file

**PCAP File Format:**
```
┌────────────────────────────┐
│ Global Header (24 bytes)   │  ← Read once at start
├────────────────────────────┤
│ Packet Header (16 bytes)   │  ← Timestamp, length
│ Packet Data (variable)     │  ← Actual network bytes
├────────────────────────────┤
│ Packet Header (16 bytes)   │
│ Packet Data (variable)     │
├────────────────────────────┤
│ ... more packets ...       │
└────────────────────────────┘
```

### Step 2: Read Each Packet

```python
for raw in reader:
  parsed = parse_packet(raw.data)
```

**What happens:**
1. Read 16-byte packet header
2. Read N bytes of packet data (N = header.incl_len)
3. Return `None` when no more packets

### Step 3: Parse Protocol Headers

```python
parsed = parse_packet(raw.data)
```

**What happens (in packet_parser.py):**

```
raw.data bytes:
[0-13]   Ethernet Header
[14-33]  IP Header  
[34-53]  TCP Header
[54+]    Payload

After parsing:
parsed.src_mac  = "00:11:22:33:44:55"
parsed.dst_mac  = "aa:bb:cc:dd:ee:ff"
parsed.src_ip   = 3232235876
parsed.dst_ip   = 2886794750
parsed.src_port = 54321
parsed.dst_port = 443
parsed.protocol = 6 (TCP)
```

**Parsing the Ethernet Header (14 bytes):**
```
Bytes 0-5:   Destination MAC
Bytes 6-11:  Source MAC
Bytes 12-13: EtherType (0x0800 = IPv4)
```

**Parsing the IP Header (20+ bytes):**
```
Byte 0:      Version (4 bits) + Header Length (4 bits)
Byte 8:      TTL (Time To Live)
Byte 9:      Protocol (6=TCP, 17=UDP)
Bytes 12-15: Source IP
Bytes 16-19: Destination IP
```

**Parsing the TCP Header (20+ bytes):**
```
Bytes 0-1:   Source Port
Bytes 2-3:   Destination Port
Bytes 4-7:   Sequence Number
Bytes 8-11:  Acknowledgment Number
Byte 12:     Data Offset (header length)
Byte 13:     Flags (SYN, ACK, FIN, etc.)
```

### Step 4: Create Five-Tuple and Look Up Flow

```python
flow = flows.setdefault(parsed.tuple, Flow())
```

**What happens:**
- The flow table is a hash map: `FiveTuple → Flow`
- If this 5-tuple exists, we get the existing flow
- If not, a new flow is created
- All packets with the same 5-tuple share the same flow

### Step 5: Extract SNI (Deep Packet Inspection)

```python
if pkt.dst_port == 443 and pkt.payload:
  sni = extract_tls_sni(pkt.payload)
  if sni:
    flow.sni = sni
    flow.app_type = sni_to_app_type(sni)
```

**What happens (in sni_extractor.py):**

1. **Check if it's a TLS Client Hello:**
   ```
   Byte 0: Content Type = 0x16 (Handshake) ✓
   Byte 5: Handshake Type = 0x01 (Client Hello) ✓
   ```

2. **Navigate to Extensions:**
   ```
   Skip: Version, Random, Session ID, Cipher Suites, Compression
   ```

3. **Find SNI Extension (type 0x0000):**
   ```
   Extension Type: 0x0000 (SNI)
   Extension Length: N
   SNI List Length: M
   SNI Type: 0x00 (hostname)
   SNI Length: L
   SNI Value: "www.youtube.com"  ← FOUND!
   ```

4. **Map SNI to App Type:**
   ```python
   if "youtube" in s:
     return AppType.YOUTUBE
   ```

### Step 6: Check Blocking Rules

```python
if rules.is_blocked(parsed.src_ip, flow.app_type, flow.sni):
  flow.blocked = True
```

**What happens:**
```python
if src_ip in self.blocked_ips:
  return True
if app in self.blocked_apps:
  return True
if sni:
  sni_lower = sni.lower()
  for dom in self.blocked_domains:
    if dom in sni_lower:
      return True
return False
```

### Step 7: Forward or Drop

```python
if flow.blocked:
  dropped += 1
  continue

forwarded += 1
writer.write_packet(raw.header, raw.data)
```

### Step 8: Generate Report

After processing all packets:
```python
for app, count in app_stats.most_common():
  pct = (count / snapshot.total_packets * 100.0) if snapshot.total_packets else 0.0
  bar = _render_bar(pct)
```

---

## 6. The Journey of a Packet (Multi-threaded Version)

The multi-threaded version (`packet_analyzer/dpi_mt.py`) adds **parallelism** for high performance:

### Architecture Overview

```
          ┌─────────────────┐
          │  Reader Thread  │
          │  (reads PCAP)   │
          └────────┬────────┘
               │
        ┌──────────────┴──────────────┐
        │      hash(5-tuple) % 2      │
        ▼                             ▼
  ┌─────────────────┐           ┌─────────────────┐
  │  LB0 Thread     │           │  LB1 Thread     │
  │  (Load Balancer)│           │  (Load Balancer)│
  └────────┬────────┘           └────────┬────────┘
       │                             │
    ┌──────┴──────┐               ┌──────┴──────┐
    │hash % 2     │               │hash % 2     │
    ▼             ▼               ▼             ▼
┌──────────┐ ┌──────────┐   ┌──────────┐ ┌──────────┐
│FP0 Thread│ │FP1 Thread│   │FP2 Thread│ │FP3 Thread│
│(Fast Path)│ │(Fast Path)│   │(Fast Path)│ │(Fast Path)│
└─────┬────┘ └─────┬────┘   └─────┬────┘ └─────┬────┘
    │            │              │            │
    └────────────┴──────────────┴────────────┘
              │
              ▼
        ┌───────────────────────┐
        │   Output Queue        │
        └───────────┬───────────┘
              │
              ▼
        ┌───────────────────────┐
        │  Output Writer Thread │
        │  (writes to PCAP)     │
        └───────────────────────┘
```

### Why This Design?

1. **Load Balancers (LBs):** Distribute work across FPs
2. **Fast Paths (FPs):** Do the actual DPI processing
3. **Consistent Hashing:** Same 5-tuple always goes to same FP

**Why consistent hashing matters:**
```
Connection: 192.168.1.100:54321 → 142.250.185.206:443

Packet 1 (SYN):         hash → FP2
Packet 2 (SYN-ACK):     hash → FP2  (same FP!)
Packet 3 (Client Hello): hash → FP2  (same FP!)
Packet 4 (Data):        hash → FP2  (same FP!)

All packets of this connection go to FP2.
FP2 can track the flow state correctly.
```

### Detailed Flow

#### Step 1: Reader Thread

```python
for raw in reader:
  parsed = parse_packet(raw.data)
  if not parsed:
    continue
  item = PacketItem(raw=raw, parsed=parsed)
  lb_idx = hash(parsed.tuple) % lbs
  load_balancers[lb_idx].queue.push(item)
```

#### Step 2: Load Balancer Thread

```python
def _run(self) -> None:
  num_fps = len(self.fps)
  while True:
    item = self.queue.pop()
    if item is None:
      break
    idx = hash(item.parsed.tuple) % num_fps
    self.fps[idx].queue.push(item)
    self.dispatched += 1
```

#### Step 3: Fast Path Thread

```python
def _run(self) -> None:
  while True:
    item = self.queue.pop()
    if item is None:
      break
    flow = self.flows.setdefault(item.parsed.tuple, Flow())
    flow = self._classify(item.parsed, flow)
    if self.rules.is_blocked(item.parsed.src_ip, flow.app_type, flow.sni):
      flow.blocked = True
    if flow.blocked:
      self.dropped += 1
      self.stats.record_dropped()
      continue
    self.forwarded += 1
    self.stats.record_forwarded()
    self.output_queue.push(item.raw)
```

#### Step 4: Output Writer Thread

```python
def _run(self) -> None:
  self._writer = PcapWriter(self.output_path)
  self._writer.open()
  while True:
    item = self.queue.pop()
    if item is None:
      break
    self._writer.write_packet(item.header, item.data)
  self._writer.close()
```

### Thread-Safe Queue

The magic that makes multi-threading work:

```python
class ThreadSafeQueue(Generic[T]):
  def __init__(self) -> None:
    self._queue: Deque[T] = deque()
    self._cond = Condition()
    self._closed = False

  def push(self, item: T) -> None:
    with self._cond:
      if self._closed:
        return
      self._queue.append(item)
      self._cond.notify()

  def pop(self) -> Optional[T]:
    with self._cond:
      while not self._queue and not self._closed:
        self._cond.wait()
      if not self._queue:
        return None
      return self._queue.popleft()
```

**How it works:**
- `push()`: Producer adds item, signals waiting consumers
- `pop()`: Consumer waits until item available, then takes it
- `Condition`: Efficient waiting (no busy-loop)

---

## 7. Deep Dive: Each Component

### pcap_reader.py

**Purpose:** Read network captures saved by Wireshark

**Key structures:**
```python
@dataclass
class PcapGlobalHeader:
  magic_number: int
  version_major: int
  version_minor: int
  thiszone: int
  sigfigs: int
  snaplen: int
  network: int

@dataclass
class PcapPacketHeader:
  ts_sec: int
  ts_usec: int
  incl_len: int
  orig_len: int
```

**Key functions:**
- `open()`: Open PCAP, validate header
- `read_next_packet()`: Read next packet into buffer
- `close()`: Clean up

### packet_parser.py

**Purpose:** Extract protocol fields from raw bytes

**Key function:**
```python
def parse_packet(frame: bytes) -> Optional[ParsedPacket]:
  dst_mac = _mac_to_str(frame[0:6])
  src_mac = _mac_to_str(frame[6:12])
  eth_type = _read_u16(frame, 12)
  if eth_type != ETH_TYPE_IPV4:
    return None
  # ... parse IPv4 + TCP/UDP ...
```

**Important concepts:**

*Network Byte Order:* Network protocols use big-endian (most significant byte first). We use `struct.unpack_from("!H", ...)` and `struct.unpack_from("!I", ...)` to convert.

### sni_extractor.py

**Purpose:** Extract domain names from TLS and HTTP

**For TLS (HTTPS):**
```python
def extract_tls_sni(payload: bytes) -> Optional[str]:
  if payload[0] != 0x16:
    return None
  if payload[5] != 0x01:
    return None
  # ... skip to extensions and find type 0x0000 ...
```

**For HTTP:**
```python
def extract_http_host(payload: bytes) -> Optional[str]:
  if not (text.startswith("GET ") or text.startswith("POST ") or text.startswith("HEAD ")):
    return None
  for line in text.split("\r\n"):
    if line.lower().startswith("host:"):
      return line.split(":", 1)[1].strip()
```

### dpi_types.py

**Purpose:** Define data structures used throughout

**FiveTuple:**
```python
@dataclass(frozen=True)
class FiveTuple:
  src_ip: int
  dst_ip: int
  src_port: int
  dst_port: int
  protocol: int
```

**AppType:**
```python
class AppType(str, Enum):
  UNKNOWN = "unknown"
  HTTP = "http"
  HTTPS = "https"
  DNS = "dns"
  GOOGLE = "google"
  YOUTUBE = "youtube"
  FACEBOOK = "facebook"
```

**sni_to_app_type function:**
```python
def sni_to_app_type(sni: str) -> AppType:
  s = sni.lower()
  if "youtube" in s:
    return AppType.YOUTUBE
  if "facebook" in s:
    return AppType.FACEBOOK
  if "google" in s:
    return AppType.GOOGLE
  if "github" in s:
    return AppType.GITHUB
  if "tiktok" in s:
    return AppType.TIKTOK
  return AppType.HTTPS
```

---

## 8. How SNI Extraction Works

### The TLS Handshake

When you visit `https://www.youtube.com`:

```
┌──────────┐                              ┌──────────┐
│  Browser │                              │  Server  │
└────┬─────┘                              └────┬─────┘
   │                                         │
   │ ──── Client Hello ─────────────────────►│
   │      (includes SNI: www.youtube.com)    │
   │                                         │
   │ ◄─── Server Hello ───────────────────── │
   │      (includes certificate)             │
   │                                         │
   │ ──── Key Exchange ─────────────────────►│
   │                                         │
   │ ◄═══ Encrypted Data ══════════════════► │
   │      (from here on, everything is       │
   │       encrypted - we can't see it)      │
```

**We can only extract SNI from the Client Hello!**

### TLS Client Hello Structure

```
Byte 0:     Content Type = 0x16 (Handshake)
Bytes 1-2:  Version = 0x0301 (TLS 1.0)
Bytes 3-4:  Record Length

-- Handshake Layer --
Byte 5:     Handshake Type = 0x01 (Client Hello)
Bytes 6-8:  Handshake Length

-- Client Hello Body --
Bytes 9-10:  Client Version
Bytes 11-42: Random (32 bytes)
Byte 43:     Session ID Length (N)
Bytes 44 to 44+N: Session ID
... Cipher Suites ...
... Compression Methods ...

-- Extensions --
Bytes X-X+1: Extensions Length
For each extension:
  Bytes: Extension Type (2)
  Bytes: Extension Length (2)
  Bytes: Extension Data

-- SNI Extension (Type 0x0000) --
Extension Type: 0x0000
Extension Length: L
  SNI List Length: M
  SNI Type: 0x00 (hostname)
  SNI Length: K
  SNI Value: "www.youtube.com" ← THE GOAL!
```

### Our Extraction Code (Simplified)

```python
def extract_tls_sni(payload: bytes) -> Optional[str]:
  if payload[0] != 0x16:
    return None
  if payload[5] != 0x01:
    return None
  offset = 43
  session_len = payload[offset]
  offset += 1 + session_len
  cipher_len = _read_u16_be(payload, offset)
  offset += 2 + cipher_len
  comp_len = payload[offset]
  offset += 1 + comp_len
  ext_len = _read_u16_be(payload, offset)
  offset += 2
  ext_end = offset + ext_len
  while offset + 4 <= ext_end:
    ext_type = _read_u16_be(payload, offset)
    ext_data_len = _read_u16_be(payload, offset + 2)
    offset += 4
    if ext_type == 0x0000:
      sni_len = _read_u16_be(payload, offset + 3)
      sni_start = offset + 5
      return payload[sni_start:sni_start + sni_len].decode("utf-8", errors="ignore")
    offset += ext_data_len
  return None
```

---

## 9. How Blocking Works

### Rule Types

| Rule Type | Example | What it Blocks |
|-----------|---------|----------------|
| IP | `192.168.1.50` | All traffic from this source |
| App | `youtube` | All YouTube connections |
| Domain | `tiktok` | Any SNI containing "tiktok" |

### The Blocking Flow

```
Packet arrives
    │
    ▼
┌─────────────────────────────────┐
│ Is source IP in blocked list?  │──Yes──► DROP
└───────────────┬─────────────────┘
        │No
        ▼
┌─────────────────────────────────┐
│ Is app type in blocked list?   │──Yes──► DROP
└───────────────┬─────────────────┘
        │No
        ▼
┌─────────────────────────────────┐
│ Does SNI match blocked domain? │──Yes──► DROP
└───────────────┬─────────────────┘
        │No
        ▼
      FORWARD
```

### Flow-Based Blocking

**Important:** We block at the *flow* level, not packet level.

```
Connection to YouTube:
  Packet 1 (SYN)           → No SNI yet, FORWARD
  Packet 2 (SYN-ACK)       → No SNI yet, FORWARD  
  Packet 3 (ACK)           → No SNI yet, FORWARD
  Packet 4 (Client Hello)  → SNI: www.youtube.com
               → App: YOUTUBE (blocked!)
               → Mark flow as BLOCKED
               → DROP this packet
  Packet 5 (Data)          → Flow is BLOCKED → DROP
  Packet 6 (Data)          → Flow is BLOCKED → DROP
  ...all subsequent packets → DROP
```

**Why this approach?**
- We can't identify the app until we see the Client Hello
- Once identified, we block all future packets of that flow
- The connection will fail/timeout on the client

---

## 10. Building and Running

### Prerequisites

- **Python 3.10+**
- No external libraries needed for core DPI (PCAP parsing is custom)
- Input must be PCAP (not pcapng)

### Run Commands

**Simple Version:**
```bash
python -m packet_analyzer.dpi_simple input.pcap output.pcap
```

**Multi-threaded Version:**
```bash
python -m packet_analyzer.dpi_mt input.pcap output.pcap --lbs 2 --fps 4
```

**With blocking:**
```bash
python -m packet_analyzer.dpi_mt input.pcap output.pcap \
  --block-app youtube \
  --block-app tiktok \
  --block-ip 192.168.1.50 \
  --block-domain facebook
```

**Rules file:**
```bash
python -m packet_analyzer.dpi_simple input.pcap output.pcap \
  --rules-in rules.json \
  --rules-out rules.json
```

**Create test data:**
```bash
python generate_test_pcap.py
```

---

## 11. Understanding the Output

### Sample Output (Multi-threaded)

```
╔══════════════════════════════════════════════════════════════════════╗
║              DPI ENGINE v2.0 (Multi-threaded)                        ║
╠══════════════════════════════════════════════════════════════════════╣
║ Load Balancers:  2    FPs per LB:  2    Total FPs:  4                ║
╚══════════════════════════════════════════════════════════════════════╝

[Rules] Blocked app: YouTube
[Rules] Blocked IP: 192.168.1.50

[Reader] Processing packets...
[Reader] Done reading 77 packets

╔══════════════════════════════════════════════════════════════════════╗
║                      PROCESSING REPORT                               ║
╠══════════════════════════════════════════════════════════════════════╣
║ Total Packets:                77                                     ║
║ Total Bytes:                5738                                     ║
║ TCP Packets:                  73                                     ║
║ UDP Packets:                   4                                     ║
╠══════════════════════════════════════════════════════════════════════╣
║ Forwarded:                    69                                     ║
║ Dropped:                       8                                     ║
╠══════════════════════════════════════════════════════════════════════╣
║ THREAD STATISTICS                                                     ║
║   LB0 dispatched:             53                                     ║
║   LB1 dispatched:             24                                     ║
║   FP0 processed:              53                                     ║
║   FP1 processed:               0                                     ║
║   FP2 processed:               0                                     ║
║   FP3 processed:              24                                     ║
╠══════════════════════════════════════════════════════════════════════╣
║                   APPLICATION BREAKDOWN                               ║
╠══════════════════════════════════════════════════════════════════════╣
║ HTTPS                39  50.6% ##########                             ║
║ Unknown              16  20.8% ####                                   ║
║ YouTube               4   5.2% # (BLOCKED)                            ║
║ DNS                   4   5.2% #                                      ║
║ Facebook              3   3.9%                                        ║
║ ...                                                             ...  ║
╚══════════════════════════════════════════════════════════════════════╝

[Detected Domains/SNIs]
  - www.youtube.com -> YouTube
  - www.facebook.com -> Facebook
  - www.google.com -> Google
  - github.com -> GitHub
  ...
```

### What Each Section Means

| Section | Meaning |
|---------|---------|
| Configuration | Number of threads created |
| Rules | Which blocking rules are active |
| Total Packets | Packets read from input file |
| Forwarded | Packets written to output file |
| Dropped | Packets blocked (not written) |
| Thread Statistics | Work distribution across threads |
| Application Breakdown | Traffic classification results |
| Detected SNIs | Actual domain names found |

---

## Summary

This DPI engine demonstrates:

1. **Network Protocol Parsing** - Understanding packet structure
2. **Deep Packet Inspection** - Looking inside encrypted connections
3. **Flow Tracking** - Managing stateful connections
4. **Multi-threaded Architecture** - Scaling with thread pools
5. **Producer-Consumer Pattern** - Thread-safe queues

The key insight is that even HTTPS traffic leaks the destination domain in the TLS handshake, allowing network operators to identify and control application usage.

