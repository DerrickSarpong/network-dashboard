# Network Traffic Analysis — Streamlit Dashboard

A small Streamlit dashboard that captures and visualizes live network packets using Scapy, stores lightweight packet metadata in memory, and shows realtime charts with Plotly.

This repository is a proof-of-concept network monitoring UI (Windows, Linux, macOS). Recent updates improved capture safety, added start/stop controls, and removed blocking UI refresh behavior.

Checklist of what changed (high level)

- Start/Stop capture controls added; capture runs in a background thread and can be stopped cleanly.
- `PacketProcessor` is thread-safe and exposes `start_capture()` / `stop_capture()` / `get_dataframe()`.
- Visualizations use a normalized `timestamp` column and group with pandas `.dt.floor('s')` (lowercase 's').
- Plotly options are passed via the `config` parameter to `st.plotly_chart`.
- UI no longer blocks the main thread with `time.sleep()`; manual refresh uses a button and `st.experimental_rerun()`.
- The app now surfaces the real exception when capture fails (useful to debug permission / Npcap issues).

## Features

- Live packet capture (Scapy) running in a background thread
- Start / Stop capture controls (sidebar)
- Manual refresh button
- Lightweight in-memory packet store (default cap: 10,000 packets)
- Real-time visualizations:
  - Protocol distribution
  - Packets-per-second timeline
  - Top source IP addresses
- Recent packet table with basic fields (timestamp, source, destination, protocol, size)

## Requirements

- Python 3.9+
- Administrator/root privileges to sniff raw packets
- On Windows: install Npcap (https://nmap.org/npcap/) and run the command prompt as Administrator

Dependencies are listed in `requirements.txt`. Typical packages used by the project:

- streamlit
- scapy
- pandas
- plotly

## Quick setup (Windows - cmd.exe)

1. Create and activate a virtual environment:

   ```cmd
   python -m venv .venv
   .venv\Scripts\activate
   ```

2. Install dependencies:

   ```cmd
   pip install -r requirements.txt
   ```

3. (Windows only) Install Npcap and run the command prompt as Administrator.

4. Run the dashboard with Streamlit:

   ```cmd
   streamlit run main.py
   ```

   Open the local URL that Streamlit prints (usually http://localhost:8501).

## Quick sniff permission test (optional)

If the app fails to start capture, you can run a tiny sniff test in an elevated cmd to confirm whether raw-socket capture is allowed. Create a file named `sniff_test.py` with the following content:

```python
from scapy.all import sniff, get_if_list

print("Available interfaces:", get_if_list())
print("Attempting a short sniff (count=1, timeout=5)...")
try:
    sniff(count=1, timeout=5)
    print("Sniff succeeded (you have sufficient permissions).")
except PermissionError as e:
    print("PermissionError:", e)
except Exception as e:
    print("Other error:", e)
```

Run it from an Administrator prompt:

```cmd
.venv\Scripts\activate
python sniff_test.py
```

If the test shows a `PermissionError` or other socket error, ensure Npcap is installed and you are running the shell as Administrator.

## Usage notes

- Start/Stop: use the sidebar buttons to control capture. The capture runs in a background thread and can be stopped cleanly.
- Manual refresh: click the "Refresh Data" button to re-render the dashboard immediately.
- Visualizations: the code normalizes `timestamp` and groups by second using `df['timestamp'].dt.floor('s')` to avoid pandas deprecation warnings related to uppercase aliases.
- Plotly: chart configuration (for example hiding the mode bar) is passed via `config` to `st.plotly_chart(fig, config=...)`.
- DataFrame display: `st.dataframe(..., use_container_width=True)` is used instead of deprecated `width='stretch'`.

## Troubleshooting

- "Failed to start packet capture": the app now displays the underlying exception. Common causes:
  - Not running as Administrator on Windows.
  - Npcap not installed or not compatible.
  - No available interfaces or invalid interface selection.
- If you see permission errors, follow the Quick sniff permission test above.
- If Streamlit UI seems unresponsive, ensure you are not running any blocking code in the Streamlit main thread. The app no longer uses `time.sleep()` for auto-refresh; refresh is manual or handled using Streamlit-friendly patterns.

## Developer notes (what to look at in the code)

- `main.py` — Streamlit entrypoint
  - Initializes `PacketProcessor` in `st.session_state` (uses `start_packet_capture()`)
  - Sidebar Start / Stop capture buttons
  - Manual refresh (`st.button("Refresh Data")` -> `st.experimental_rerun()`)
  - Shows errors returned when starting capture

- `dashboard.py` — core logic
  - `PacketProcessor` class
    - `__init__(max_packets=10000)` — initializes lock, data store, and capture control
    - `process_packet(packet)` — Scapy callback that extracts packet metadata and appends to the buffer (thread-safe)
    - `get_dataframe()` — returns a copy of the stored packet DataFrame
    - `start_capture(iface=None, filter_expr=None)` — starts a background thread that runs `sniff()` with a `stop_filter` driven by an internal Event
    - `stop_capture()` — signals the capture thread to stop and joins it
  - `create_visualizations(df)` — normalizes timestamps, groups per second using `.dt.floor('s')`, and renders Plotly charts with `st.plotly_chart(..., config=...)`

Implementation notes & rationale

- Thread safety: `PacketProcessor` uses a threading.Lock to protect `packet_data` mutations and to return a safe `DataFrame` copy.
- Graceful stop: the capture thread uses `stop_filter=lambda pkt: stop_event.is_set()` so the thread exits soon after the stop is signaled.
- Resource limits: the buffer is capped (`max_packets`) to avoid unbounded memory growth; default 10,000 is configurable in the constructor.

## Migration / compatibility notes

- pandas: use lowercase `'s'` when calling `.dt.floor('s')` to avoid deprecation warnings for uppercase aliases.
- Streamlit / Plotly: use `config` in `st.plotly_chart(..., config=...)` to pass Plotly configuration options (the previous keyword args have been deprecated).
- Replace deprecated `width='stretch'` on `st.dataframe` with `use_container_width=True`.

## Security & legal

Only capture traffic on networks and hosts where you have permission. Capturing network traffic may expose sensitive data; treat captures as confidential.

## Contributing

Small fixes and improvements are welcome. Suggested next steps:

- Replace manual refresh with `st_autorefresh` or a timer-based pattern for a smoother UX.
- Add interface selector and capture filters in the UI.
- Add unit tests that exercise `PacketProcessor.process_packet()` using synthetic Scapy-like packets.

---

If you'd like, I can also:

- Add the optional `sniff_test.py` file to the repository so you can run it directly.
- Replace the current manual refresh with a non-blocking `st_autorefresh` implementation.
