# Real-Time CICFlowMeter (97-Feature) Flow Extractor

A full-featured real-time flow extractor that replicates and extends [CICFlowMeter], written in Python.

This tool extracts **97 detailed flow features** (transport + application layer) from live network traffic and exports them **directly to CSV**, ready for ML pipelines, security monitoring, and network analysis.

---

## ✅ Key Features

- **97 total flow features** (packet stats, IATs, flags, application-layer)
- **Supports both PyShark (Wireshark)** and **Scapy** for packet capture
- Extracts real-time flows from live traffic
- **Auto-creates and writes to `output/live_flow_features.csv`**
- Parses HTTP, TLS, and DNS layers
- Handles subflows, bulk metrics, active/idle periods
- Configurable flow timeout, subflow window, bulk interval, etc.

---

## Project Structure

```bash
RealTime-CICFlowMeter/
├── main.py                   # Packet capture and orchestration
├── config.py                 # Constants and logging setup
├── packet_processor.py       # Interface and flow key extraction
├── flow_manager.py           # Per-flow state and updates
├── feature_computation.py    # Feature extraction and CSV export
├── output/
│   └── live_flow_features.csv  # Auto-generated output file

---

## Features Extracted (Sample)

    Flow Duration, Total Packets/Bytes

    Fwd/Bwd Packet Length Stats (Mean, Max, Min, Std)

    Inter-Arrival Times (Flow, Fwd, Bwd)

    Active/Idle Periods

    Bulk Metrics (Fwd/Bwd rates, durations)

    TCP Flags (SYN, ACK, URG, etc.)

    Subflow Counts

    Window Sizes, Header Lengths

    Application-Layer Stats:

        HTTP Requests/Responses, Methods, Status Codes

        TLS Handshake Count, Version, Cipher Suite Count

        DNS Query Types, Response Codes

    🔢 Total: 97 CICFlowMeter-style features
