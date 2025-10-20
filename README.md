# Network Traffic Analysis — Streamlit Dashboard

A small Streamlit dashboard that captures and visualizes live network packets using Scapy, stores lightweight packet metadata in memory, and shows realtime charts with Plotly.

This repository contains a simple proof-of-concept network monitoring UI (works on Windows, Linux, or macOS) intended for learning and small-scale troubleshooting. Packet capture requires elevated privileges on most OSes.

## Features

- Live packet capture (Scapy) running in a background thread
- Lightweight in-memory packet store (capped to prevent unbounded growth)
- Real-time visualizations:
  - Protocol distribution
  - Packets per second timeline
  - Top source IP addresses
- Recent packet table with basic fields (timestamp, source, destination, protocol, size)

## Requirements

- Python 3.9+
- Administrator/root privileges to sniff raw packets
- On Windows: install Npcap (https://nmap.org/npcap/) and run the app as Administrator

Python dependencies are listed in `requirements.txt`. Typical packages used by the project:

- streamlit
- scapy
- pandas
- plotly

## Quick setup (Windows - cmd.exe)

1. Create and activate a virtual environment:

```bash
python -m venv .venv
.venv\Scripts\activate
```

2. Install dependencies from `requirements.txt` (or install the packages manually):

```bash
pip install -r requirements.txt
```

3. (Windows only) Install Npcap and run a command prompt as Administrator.

4. Run the dashboard with Streamlit:

```bash
streamlit run main.py
```

Open the local URL that Streamlit prints (usually http://localhost:8501).

## Usage notes

- The app starts a background thread to sniff packets. It stores lightweight metadata (timestamp, source, destination, protocol, size, ports/flags) in memory and updates the UI on a short refresh loop.
- The in-memory buffer is capped (the code keeps the last ~10,000 packets) to avoid exhausting RAM during long captures.

## Troubleshooting

- Permission / socket errors on Windows: ensure Npcap is installed and you're running the shell as Administrator.
- Scapy errors: Scapy may print warnings about missing dependencies on Windows. Installing Npcap and running as Administrator resolves most capture errors.
- If the UI is unresponsive due to continuous reruns, comment out or modify the auto-refresh logic in `main.py` (the example uses a blocking sleep + `st.rerun()`). Consider using `st_autorefresh` or a Streamlit timer-based pattern instead.

## Developer notes

- Entry point: `main.py` (Streamlit app)
- Core packet handling and visualizations: `dashboard.py`
- Key classes/functions:
  - `PacketProcessor` — collects and stores packet metadata; thread-safe via a lock
  - `start_packet_capture()` — starts Scapy `sniff()` in a daemon thread and returns the processor
  - `create_visualizations(df)` — renders Plotly charts from a pandas DataFrame

Known caveats / recent fixes in the code:
- Make sure `PacketProcessor.__init__` is present (typo `__int__` breaks initialization and prevents attributes like `lock` from being created).
- Packet capture requires elevated privileges; handle exceptions raised by Scapy when permissions are insufficient.
- The code currently uses `time.sleep()` + `st.rerun()` for auto-refresh which can be improved for smoother UI behavior.

## Security & legal

Only capture traffic on networks and hosts where you have permission. Capturing network traffic may expose sensitive data; treat captures as confidential.

## Contributing

Small fixes and improvements are welcome. Suggested enhancements:

- Replace the UI auto-refresh pattern with `st_autorefresh` or a non-blocking approach
- Add filtering controls (by protocol, IP, port)
- Persist summaries to disk or a database for longer retention


