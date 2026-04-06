# DPI Engine (Python)

A pure-Python Deep Packet Inspection engine that parses PCAP files, classifies flows by SNI/Host, applies blocking rules, and writes filtered PCAP output.

## Layout

- `packet_analyzer/pcap_reader.py` - PCAP reader/writer
- `packet_analyzer/packet_parser.py` - Ethernet/IPv4/TCP/UDP parsing
- `packet_analyzer/sni_extractor.py` - TLS SNI and HTTP Host extraction
- `packet_analyzer/rules.py` - Blocking rules
- `packet_analyzer/dpi_types.py` - FiveTuple, Flow, AppType
- `packet_analyzer/dpi_simple.py` - Single-threaded engine
- `packet_analyzer/dpi_mt.py` - Multi-threaded engine

## Requirements

- Python 3.10+
- Input must be PCAP (not pcapng)

## Run (Single-threaded)

```bash
python -m packet_analyzer.dpi_simple input.pcap output.pcap \
  --block-app youtube \
  --block-ip 192.168.1.50 \
  --block-domain facebook
```

## Run (Multi-threaded)

```bash
python -m packet_analyzer.dpi_mt input.pcap output.pcap \
  --lbs 2 --fps 4 \
  --block-app youtube
```

## Notes

- App types are defined in `AppType` (see `packet_analyzer/dpi_types.py`).
- HTTPS SNI is extracted from TLS Client Hello only.
