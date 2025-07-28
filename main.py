import time
import logging
from packet_processor import get_interface, get_flow_key, USE_PYSHARK
from flow_manager import FLOW_STATS, init_flow, update_flow
from feature_computation import write_flow_to_csv
from config import FLOW_TIMEOUT, SUBFLOW_WINDOW, BULK_INTERVAL, ACTIVE_THRESHOLD
import os

try:
    import pyshark
except ImportError:
    from scapy.all import sniff

logger = logging.getLogger(__name__)

def expire_flows():
    """Remove expired flows and write them to CSV."""
    now = time.time()
    to_remove = []
    for k, v in FLOW_STATS.items():
        if v['flow_end'] and now - v['flow_end'] > FLOW_TIMEOUT:
            write_flow_to_csv(k, v)
            to_remove.append(k)
    for k in to_remove:
        del FLOW_STATS[k]
        logger.debug(f"Expired flow: {k}")

def packet_callback(pkt):
    """Process each captured packet."""
    ts = time.time()
    key = get_flow_key(pkt)
    if not key:
        return
    direction = 'fwd' if pkt.ip.src == key[0] else 'bwd'
    if key not in FLOW_STATS:
        FLOW_STATS[key] = init_flow()
        logger.info(f"New flow started: {key}")
    update_flow(pkt, ts, key, direction, USE_PYSHARK, SUBFLOW_WINDOW, BULK_INTERVAL, ACTIVE_THRESHOLD)
    expire_flows()

if __name__ == "__main__":
    logger.info("Starting full-featured CICFlowMeter extractor...")
    interface = "Wi-Fi"
    if not interface and USE_PYSHARK:
        logger.error("No valid network interface found. Please specify an interface.")
        exit(1)
    try:
        if USE_PYSHARK:
            logger.info(f"Using pyshark for packet capture on interface: {interface}")
            capture = pyshark.LiveCapture(interface=interface, bpf_filter='ip')
            capture.apply_on_packets(packet_callback)
        else:
            logger.info("Using scapy for packet capture")
            sniff(prn=packet_callback, store=False, filter='ip')
    except KeyboardInterrupt:
        logger.info("Stopping capture...")
        expire_flows()
    except Exception as e:
        logger.error(f"Capture failed: {e}", exc_info=True)