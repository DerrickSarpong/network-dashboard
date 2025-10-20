import streamlit as st
import time

from dashboard import create_visualizations, start_packet_capture


def main():
    """Main function to run the dashboard"""
    st.set_page_config(page_title="Network Traffic Analysis", layout="wide")
    st.title("Real-time Network Traffic Analysis")

    # Initialize packet processor in session state
    if "processor" not in st.session_state:
        st.session_state.processor = start_packet_capture()
        st.session_state.start_time = time.time()

    # Create dashboard layout
    col1, col2 = st.columns(2)

    # Get current data
    df = st.session_state.processor.get_dataframe()

    # Display metrics
    with col1:
        st.metric("Total Packets", len(df))
    with col2:
        duration = time.time() - st.session_state.start_time
        st.metric("Capture Duration", f"{duration:.2f}s")

    # Display visualizations
    create_visualizations(df)

    # Display recent packets
    st.subheader("Recent Packets")
    if len(df) > 0:
        st.dataframe(
            df.tail(10)[["timestamp", "source", "destination", "protocol", "size"]],
            use_container_width=True,
        )

    # Add refresh button
    if st.button("Refresh Data"):
        st.rerun()

    # Auto refresh
    time.sleep(2)
    st.rerun()


if __name__ == "__main__":
    main()
