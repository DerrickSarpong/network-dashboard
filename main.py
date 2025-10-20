import streamlit as st
from datetime import datetime
import time
from dashboard import create_visualizations, start_packet_capture, logger


def main():
    """Main function to run the dashboard"""
    st.set_page_config(page_title="Network Traffic Analysis", layout="wide")
    st.title("Real-time Network Traffic Analysis")

    # Start processor in session state if missing
    if "processor" not in st.session_state:
        try:
            st.session_state.processor = start_packet_capture()
            st.session_state.start_time = st.session_state.processor.start_time
        except Exception as e:
            # Show the actual exception message so you can diagnose permission / interface issues
            st.error(f"Failed to start packet capture: {e}")
            logger.exception("Start capture failed")
            st.stop()

    processor = st.session_state.processor

    # Controls: start / stop capture
    if processor._capture_thread and processor._capture_thread.is_alive():
        if st.button("Stop Capture"):
            processor.stop_capture()
    else:
        if st.button("Start Capture"):
            processor.start_capture()

    # Main layout
    col1, col2 = st.columns(2)

    # Get current data snapshot
    df = processor.get_dataframe()

    # Display metrics
    with col1:
        st.metric("Total Packets", len(df))
    with col2:
        # Compute capture duration from the processor start_time (if available)
        try:
            duration_seconds = (datetime.now() - processor.start_time).total_seconds()
            st.metric("Capture Duration", f"{duration_seconds:.2f}s")
        except Exception:
            st.metric("Capture Duration", "N/A")

    # Display visualizations
    create_visualizations(df)

    # Display recent packets
    st.subheader("Recent Packets")
    if len(df) > 0:
        cols = ["timestamp", "source", "destination", "protocol", "size"]
        available = [c for c in cols if c in df.columns]
        st.dataframe(df.tail(10)[available], width='stretch')

    # Add refresh button (safe call that works across Streamlit versions)
    if st.button("Refresh Data"):
        st.rerun()

    # Auto refresh
    time.sleep(3)
    st.rerun()


if __name__ == "__main__":
    main()
