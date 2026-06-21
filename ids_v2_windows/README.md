# AI Cybersecurity IDS — Windows Port (Hybrid C++ Backend / Python ML)

This is a Windows port of the C++/Python hybrid IDS. The architecture is
unchanged:

```
┌────────────────────────────────────────────────────────────────┐
│                        C++ Backend                             │
│                                                                │
│  Network ──► PacketSniffer ──► FeatureEngineer ──► Collector  │
│             (Npcap/pcap)                              (CSV)    │
│                                    │                           │
│                                    ▼                           │
│                             ThreatDetector                     │
│                                    │                           │
│                             MLClient (TCP)                     │
│                                    │                           │
└────────────────────────────────────│───────────────────────────┘
                                     │  JSON over TCP :9999
┌────────────────────────────────────│───────────────────────────┐
│                        Python ML Service                       │
│                                    │                           │
│                             ml_service.py                      │
│                           ┌────────┴────────┐                  │
│                    AnomalyModel        AttackClassifier        │
│                  (IsolationForest)  (RandomForestClassifier)   │
│                      sklearn              sklearn              │
└────────────────────────────────────────────────────────────────┘
                                    │
                             dashboard.py
                             (Streamlit, reads CSV)
```

## What changed from the Linux version

- **`cpp/core/PacketSniffer.h`** — rewritten to not depend on
  `<netinet/ip.h>` / `<netinet/tcp.h>` / `<netinet/udp.h>` or BSD struct
  field names (`ip_hl`, `th_sport`, ...), none of which exist on Windows.
  It now defines its own minimal `IPv4Header` / `TCPHeader` / `UDPHeader`
  layouts and uses `<winsock2.h>` / `<ws2tcpip.h>` for byte-order
  conversion and `inet_ntop`.
- **Interface resolution** — Npcap device names look like
  `\Device\NPF_{GUID}`, so `Config::INTERFACE` is now matched against the
  *description* of each adapter (e.g. `"Wi-Fi"`, `"Ethernet"`) via
  `pcap_findalldevs()`. The program prints all detected adapters at
  startup so you can pick the right string.
- **`cpp/utils/Config.h`** — default `INTERFACE` is `"Wi-Fi"` on Windows,
  `"eth0"` on Linux.
- **`cpp/response/FirewallController.h`** — Windows branch now adds both
  inbound and outbound `netsh advfirewall` block rules (requires
  Administrator).
- **`cpp/utils/Logger.h`** / **`cpp/response/AlertManager.h`** — use
  `localtime_s` on Windows / `localtime_r` on Linux instead of the
  non-thread-safe `std::localtime`.
- **`cpp/main.cpp`** — enables ANSI color codes on the Windows console
  (`ENABLE_VIRTUAL_TERMINAL_PROCESSING`) and prints the list of available
  capture adapters at startup.
- **`cpp/CMakeLists.txt`** — Windows build now requires the `NPCAP_SDK`
  environment variable and sets `_WIN32_WINNT=0x0600`,
  `WIN32_LEAN_AND_MEAN`, `NOMINMAX`.
- **Python files** (`ml_service.py`, `trainer.py`, `dashboard.py`,
  `models/*.py`) — unchanged. They were already cross-platform.

---

## Project Structure

```
ids_v2_windows/
├── cpp/
│   ├── main.cpp
│   ├── CMakeLists.txt
│   ├── common/Types.h
│   ├── core/
│   │   ├── PacketSniffer.h
│   │   ├── FeatureEngineer.h
│   │   └── Collector.h
│   ├── detection/
│   │   ├── MLClient.h
│   │   └── ThreatDetector.h
│   ├── response/
│   │   ├── FirewallController.h
│   │   └── AlertManager.h
│   └── utils/
│       ├── Config.h
│       └── Logger.h
│
└── python/
    ├── ml_service.py
    ├── trainer.py
    ├── dashboard.py
    ├── requirements.txt
    └── models/
        ├── anomaly_model.py
        └── attack_classifier.py
```

---

## Prerequisites

1. **Npcap (runtime)** — download and install from
   [https://npcap.com](https://npcap.com). During installation, check
   **"Install Npcap in WinPcap API-compatible Mode"**.
2. **Npcap SDK (build-time headers/libs)** — download the SDK zip from the
   same page, extract it (e.g. to `C:\npcap-sdk`), and set an environment
   variable:
   ```powershell
   setx NPCAP_SDK "C:\npcap-sdk"
   ```
   (open a new terminal afterwards so the variable is picked up).
3. **Visual Studio 2022** (Desktop development with C++ workload) or any
   MSVC/MinGW toolchain with C++20 support, plus **CMake ≥ 3.16**.
4. **Python 3.10+** for the ML service / dashboard.

---

## Quick Start

### 1 — Install Python dependencies
```powershell
cd ids_v2_windows\python
pip install -r requirements.txt
```

### 2 — Train the models
```powershell
# Put your labelled CSV at data\training_data.csv first (see format below)
python trainer.py
# Outputs: models\anomaly_model.pkl  models\attack_classifier.pkl
```

Training CSV format:
```
src_ip,dst_ip,protocol,src_port,dst_port,packet_size,label
192.168.1.5,10.0.0.1,TCP,12345,80,512,NORMAL
10.0.0.99,192.168.1.1,UDP,53,53,64,DDoS
```

### 3 — Start the Python ML service
```powershell
python ml_service.py
# Listening on 127.0.0.1:9999
```

### 4 — Build the C++ backend
```powershell
cd ids_v2_windows\cpp
mkdir build
cd build
cmake .. -G "Visual Studio 17 2022" -A x64
cmake --build . --config Release
```

### 5 — Find your network adapter name
Run the built executable once from an **elevated (Administrator)
terminal** — it will print all Npcap-visible adapters and their
descriptions, e.g.:
```
[INFO] Available capture adapters:
[INFO]   \Device\NPF_{1234...}  -- Intel(R) Wi-Fi 6 AX201
[INFO]   \Device\NPF_{5678...}  -- Realtek PCIe GbE Family Controller
```
Edit `cpp/utils/Config.h` and set `INTERFACE` to a string that uniquely
matches the description of the adapter you want (e.g. `"Wi-Fi 6"` or
`"Realtek"`), then rebuild.

### 6 — Run the C++ backend (as Administrator)
Raw packet capture and firewall rule changes both require elevated
privileges:
```powershell
cd ids_v2_windows\cpp\build\Release
.\ids_backend.exe
```
Press `Ctrl+C` to stop.

### 7 — (Optional) Launch the Streamlit dashboard
```powershell
cd ids_v2_windows\python
streamlit run dashboard.py
```

---

## IPC Protocol (unchanged)

The C++ backend and Python ML service communicate over **TCP on
localhost:9999** using newline-delimited JSON — one connection per packet
classification.

**C++ → Python (request):**
```json
{"packet_size":512,"is_tcp":1,"is_udp":0,"src_port":12345,"dst_port":80,"src_ip":"1.2.3.4","dst_ip":"5.6.7.8"}
```

**Python → C++ (response):**
```json
{"status":"THREAT","attack_type":"DDoS"}
{"status":"NORMAL","attack_type":""}
```

---

## Configuration

**C++ side** — edit `cpp/utils/Config.h`:

| Constant | Default (Windows) | Description |
|---|---|---|
| `INTERFACE` | `"Wi-Fi"` | Adapter description fragment, resolved to a `\Device\NPF_{...}` name at runtime |
| `ML_SERVICE_HOST` | `"127.0.0.1"` | Python ML service IP |
| `ML_SERVICE_PORT` | `9999` | Python ML service port |
| `BUFFER_SIZE` | `50` | Packets buffered before CSV flush |

**Python side** — edit `python/ml_service.py` top constants:

| Constant | Default | Description |
|---|---|---|
| `HOST` | `"127.0.0.1"` | Bind address |
| `PORT` | `9999` | Bind port |
| `ANOMALY_MODEL_PATH` | `"models/anomaly_model.pkl"` | |
| `CLASSIFIER_MODEL_PATH` | `"models/attack_classifier.pkl"` | |

---

## Troubleshooting

- **`pcap_open_live` fails / no adapters listed** — make sure the Npcap
  *runtime* is installed (not just the SDK), and run the program as
  Administrator.
- **Firewall blocking does nothing** — `netsh advfirewall` commands
  require an elevated terminal. Check Windows Defender Firewall ▸
  Advanced Settings ▸ Inbound/Outbound Rules for rules named
  `IDS Block <ip> (in)` / `(out)`.
- **CMake can't find Npcap headers/libs** — confirm `NPCAP_SDK` points to
  the extracted SDK folder (it should contain an `Include\pcap.h` and a
  `Lib\x64\wpcap.lib`), and open a new terminal after setting it.
- **No color in console output** — only affects cosmetics; requires
  Windows 10 1511+ (the program enables VT processing automatically).
