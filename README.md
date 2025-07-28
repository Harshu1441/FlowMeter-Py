# Real-Time CICFlowMeter (97-Feature) Flow Extractor

A full-featured real-time flow extractor that replicates and extends [CICFlowMeter], written in Python.

This tool extracts **97 detailed flow features** (transport + application layer) from live network traffic and exports them **directly to CSV**, ready for ML pipelines, security monitoring, and network analysis.

---

## ✅ Key Features

- **97 total flow features** (packet stats, IATs, flags, application-layer)
- **Supports PyShark (Wireshark)** for packet capture
- Extracts real-time flows from live traffic
- **Auto-creates and writes to `output/live_flow_features.csv`**
- Parses HTTP, TLS, and DNS layers
- Handles subflows, bulk metrics, active/idle periods
- Configurable flow timeout, subflow window, bulk interval, etc.

---

## Project Structure

RealTime-CICFlowMeter/
├── main.py                   # Packet capture and orchestration
├── config.py                 # Constants and logging setup
├── packet_processor.py       # Interface and flow key extraction
├── flow_manager.py           # Per-flow state and updates
├── feature_computation.py    # Feature extraction and CSV export
├── output/
│   └── live_flow_features.csv  # Auto-generated output file

---
## Features Extracted (Sample Overview)

- **Basic Flow Stats**  
  `Flow Duration`, `Total Fwd/Bwd Packets`, `Total Fwd/Bwd Bytes`

- **Packet Length Metrics**  
  `Fwd/Bwd Packet Length Mean`, `Max`, `Min`, `Std`

- **Time-Based Features**  
  `Flow IAT Mean/Max/Min/Std`, `Fwd/Bwd IATs`, `Active/Idle Durations`

- **TCP Flag Counts**  
  `SYN`, `ACK`, `URG`, `FIN`, `PSH`, `RST`, etc.

- **Bulk Transfer Features**  
  Bulk durations, byte and packet counts, rate metrics

- **Header and Payload Details**  
  `Header Length`, `Payload Bytes`, `Window Sizes`

- **Subflow Stats**  
  `Subflow Count`, `Bytes per Subflow`, `Packets per Subflow`

- **Application-Layer Statistics**
  - **HTTP:** Method, Status Code, Header Fields
  - **TLS:** Version, Cipher Suites, Handshake Counts
  - **DNS:** Query Types, Response Codes

> **Total:** 97 CICFlowMeter-style features

---

## How to Run

### Prerequisites

- Python 3.7+
- [TShark](https://www.wireshark.org/docs/man-pages/tshark.html) installed (recommended for PyShark backend)

### Installation

```bash
pip install pandas numpy
pip install pyshark

python main.py
