import pandas as pd
import plotly.express as px
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
from datetime import datetime
import threading
import logging
import streamlit as st
from typing import Optional

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# Packet Processor
class PacketProcessor:
    """Process and analyze network packets"""

    def __init__(self, max_packets: int = 10000):
        self.protocol_map = {
            1: 'ICMP',
            6: 'TCP',
            17: 'UDP',
        }
        self.packet_data = []
        self.start_time = datetime.now()
        self.packet_count = 0
        self.lock = threading.Lock()
        self.max_packets = max_packets

        # Capture control
        self._stop_event = threading.Event()
        self._capture_thread = None

    def get_protocol_name(self, protocol_num: int) -> str:
        """Convert protocol number to name"""
        return self.protocol_map.get(protocol_num, f'OTHER({protocol_num})')

    def process_packet(self, packet) -> None:
        """Callback for sniff: extract and store packet metadata."""
        try:
            if IP in packet:
                now = datetime.now()
                packet_info = {
                    'timestamp': now,
                    'source': packet[IP].src,
                    'destination': packet[IP].dst,
                    'protocol': self.get_protocol_name(packet[IP].proto),
                    'size': len(packet),
                    'time_relative': (now - self.start_time).total_seconds(),
                }

                # Add TCP-specific information
                if TCP in packet:
                    packet_info.update({
                        'src_port': getattr(packet[TCP], 'sport', None),
                        'dst_port': getattr(packet[TCP], 'dport', None),
                        'tcp_flags': getattr(packet[TCP], 'flags', None),
                    })

                # Add UDP-specific information
                elif UDP in packet:
                    packet_info.update({
                        'src_port': getattr(packet[UDP], 'sport', None),
                        'dst_port': getattr(packet[UDP], 'dport', None),
                    })

                with self.lock:
                    self.packet_data.append(packet_info)
                    self.packet_count += 1

                    # Keep only last 10000 packets to prevent memory issues
                    if len(self.packet_data) > self.max_packets:
                        # drop oldest
                        excess = len(self.packet_data) - self.max_packets
                        if excess > 0:
                            self.packet_data = self.packet_data[excess:]

        except Exception as e:
            logger.exception("Error processing packet: %s", e)

    def get_dataframe(self) -> pd.DataFrame:
        """Convert packet date to pandas DataFrame"""
        with self.lock:
            return pd.DataFrame(self.packet_data).copy()


    def _capture_loop(self, iface: str | None = None, filter_expr: str | None = None):
        """Internal capture loop using scapy.sniff with a stop filter."""
        try:
            sniff(
                prn=self.process_packet,
                store=False,
                iface=iface,
                filter=filter_expr,
                stop_filter=lambda pkt: self._stop_event.is_set()
            )
        except Exception as e:
            logger.exception("Packet capture stopped with error: %s", e)

    def start_capture(self, iface: str | None = None, filter_expr: str | None = None):
        """Start background capture thread (no-op if already running)."""
        if self._capture_thread and self._capture_thread.is_alive():
            logger.info("Capture already running")
            return
        self._stop_event.clear()
        self._capture_thread = threading.Thread(
            target=self._capture_loop, args=(iface, filter_expr), daemon=True
        )
        self._capture_thread.start()
        logger.info("Started packet capture thread")

    def stop_capture(self, timeout: float = 2.0):
        """Signal the capture thread to stop and join it."""
        self._stop_event.set()
        if self._capture_thread:
            self._capture_thread.join(timeout)
            if self._capture_thread.is_alive():
                logger.warning("Capture thread did not stop within timeout")
            else:
                logger.info("Capture thread stopped")
            self._capture_thread = None


def create_visualizations(df: pd.DataFrame):
    """Render protocol distribution, packets/sec timeline, and top sources."""
    if df is None or len(df) == 0:
        st.info("No packet data available yet.")
        return

    # Ensure timestamp column exists and is datetime
    if 'timestamp' not in df.columns:
        st.warning("Dataframe missing 'timestamp' column.")
        return

    df = df.copy()
    df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
    df = df.dropna(subset=['timestamp'])
    if df.empty:
        st.info("No valid timestamps to plot.")
        return

    # Define your configuration options
    my_config = {
        'displayModeBar': False,  # Hides the floating toolbar
        'scrollZoom': True,  # Enables scroll zooming
        'responsive': True,  # Makes the figure responsive
    }

    # Protocol distribution
    protocol_counts = df['protocol'].value_counts()
    fig_protocol = px.pie(
        values=protocol_counts.values,
        names=protocol_counts.index,
        title="Protocol Distribution"
    )
    st.plotly_chart(fig_protocol, config=my_config)

    # Packets timeline (per second)
    df_grouped = df.groupby(df['timestamp'].dt.floor('s')).size()
    fig_timeline = px.line(
        x=df_grouped.index,
        y=df_grouped.values,
        title="Packets per Second"
    )
    st.plotly_chart(fig_timeline, config=my_config)

    # Top source IPs
    top_sources = df['source'].value_counts().head(10)
    fig_sources = px.bar(
        x=top_sources.index,
        y=top_sources.values,
        title="Top Source IP Addresses"
    )
    st.plotly_chart(fig_sources,config=my_config)


def start_packet_capture(iface: Optional[str] = None, filter_expr: Optional[str] = None) -> PacketProcessor:
    """
    Convenience: create a PacketProcessor, start capture, and return it.
    The processor can later be stopped via `processor.stop_capture()`.
    """
    processor = PacketProcessor()
    try:
        processor.start_capture(iface=iface, filter_expr=filter_expr)
    except PermissionError as e:
        logger.exception("Permission error starting capture: %s", e)
        raise
    except Exception as e:
        logger.exception("Failed to start packet capture: %s", e)
        raise
    return processor