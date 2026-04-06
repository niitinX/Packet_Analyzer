# DPI Engine (Python)

A pure-Python Deep Packet Inspection engine that parses PCAP files, classifies flows by TLS SNI/HTTP Host, enforces blocking rules, and writes filtered PCAP output. Includes single-threaded and multi-threaded pipelines, live stats, throttling, and persistent rules.

## Highlights

- Parses Ethernet/IPv4/TCP/UDP and extracts flow 5-tuple state
- SNI and Host extraction for HTTPS/HTTP classification
- Flow-based blocking (IP, app, domain)
- Multi-threaded pipeline with consistent hashing
- Live stats, throttling, and JSON rule persistence

## Architecture (Multi-threaded)

Reader -> Load Balancers -> Fast Paths -> Output Writer

- Reader: reads PCAP and parses packets
- LB: consistent hashing keeps a flow on one FP
- FP: DPI + rules + flow state
- Writer: writes allowed packets to output PCAP

## How It Works (Single-threaded)

1. Read packet from PCAP
2. Parse headers and payload
3. Build 5-tuple, look up flow
4. Extract SNI/Host and classify app
5. Apply blocking rules
6. Forward (write) or drop
7. Report stats

## Layout

- packet_analyzer/pcap_reader.py - PCAP reader/writer
- packet_analyzer/packet_parser.py - Ethernet/IPv4/TCP/UDP parsing
- packet_analyzer/sni_extractor.py - TLS SNI and HTTP Host extraction
- packet_analyzer/rules.py - Blocking rules + persistence
- packet_analyzer/dpi_simple.py - Single-threaded engine
- packet_analyzer/dpi_mt.py - Multi-threaded engine
- packet_analyzer/live_stats.py - Live stats printer
- scripts/benchmark.py - Benchmark runner
- api/ - FastAPI backend
- ui/ - React frontend

## Requirements

- Python 3.10+
- Input must be PCAP (not pcapng)

## Run (Single-threaded)

```bash
python -m packet_analyzer.dpi_simple input.pcap output.pcap --block-app youtube
```

## Run (Multi-threaded)

```bash
python -m packet_analyzer.dpi_mt input.pcap output.pcap --lbs 2 --fps 4 --block-app youtube
```

## Optional Flags

- --rules-in rules.json / --rules-out rules.json
- --throttle-ms 10
- --stats-interval 2
- --perf
- --quiet

## Rules File (rules.json)

```json
{
  "blocked_ips": ["192.168.1.50"],
  "blocked_apps": ["youtube"],
  "blocked_domains": ["facebook"]
}
```

## Benchmark

```bash
python -m scripts.benchmark test_dpi.pcap --mode simple --repeat 3
python -m scripts.benchmark test_dpi.pcap --mode mt --lbs 2 --fps 4 --repeat 3
```

## API + UI (FastAPI + React)

Start the API:

```bash
python -m pip install -r api/requirements.txt
python -m uvicorn api.app:app --reload
```

Start the UI:

```bash
cd ui
npm install
npm run dev
```

Generate a sample PCAP via the UI:

- Click "Generate sample PCAP and run" in the UI to run the built-in sample capture.
- Toggle "Randomize sample domains" to generate a different sample each run.

## Resume Bullets

- Built a Python DPI engine that parses PCAP files, tracks flows by 5-tuple, extracts TLS SNI/HTTP Host, and enforces blocking rules.
- Designed a multi-threaded pipeline with load balancers and consistent hashing to keep flow state correct.
- Added live stats, throttling, and persistent rule sets; measured throughput with a custom benchmark script.





## Ongoing Work

**full project layout** with FastAPI + React UI added:

```
DPI/
├── packet_analyzer/
│   ├── __init__.py
│   ├── dpi_types.py
│   ├── pcap_reader.py
│   ├── packet_parser.py
│   ├── sni_extractor.py
│   ├── rules.py
│   ├── thread_safe_queue.py
│   ├── live_stats.py
│   ├── dpi_simple.py
│   └── dpi_mt.py
├── scripts/
│   ├── __init__.py
│   └── benchmark.py
├── generate_test_pcap.py
├── test_dpi.pcap
├── rules.json
├── README.md
├── .gitignore
│
├── api/                         # FastAPI backend
│   ├── app.py                   # FastAPI entrypoint
│   ├── jobs/                    # per-run job storage
│   │   └── <job_id>/
│   │       ├── input.pcap
│   │       ├── output.pcap
│   │       └── report.json
│   ├── schemas.py               # request/response models
│   └── utils.py                 # helpers (file mgmt, job runner)
│
└── ui/                          # React frontend
    ├── package.json
    ├── public/
    │   └── index.html
    └── src/
        ├── App.jsx
        ├── api.js               # API client
        ├── components/
        │   ├── UploadForm.jsx
        │   ├── RulesForm.jsx
        │   ├── RunConfig.jsx
        │   ├── Progress.jsx
        │   └── Report.jsx
        └── styles/
            └── app.css
```

