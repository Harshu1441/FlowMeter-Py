import logging

try:
    import pyshark
    USE_PYSHARK = True
except ImportError:
    from scapy.all import sniff, IP, TCP, UDP
    USE_PYSHARK = False

logger = logging.getLogger(__name__)

def get_interface():
    """Get the first available network interface for capture."""
    if USE_PYSHARK:
        try:
            interfaces = pyshark.tshark.get_tshark_interfaces()
            logger.info(f"Available interfaces: {interfaces}")
            for iface in interfaces:
                if 'Wi-Fi' in iface or 'Wireless' in iface or 'NPF' in iface:
                    return iface
            return interfaces[0] if interfaces else None
        except Exception as e:
            logger.error(f"Failed to get interfaces: {e}")
            return None
    else:
        return None  # Scapy uses filter, not interface name

def get_flow_key(pkt):
    """Extract flow key from packet."""
    try:
        if USE_PYSHARK:
            if not hasattr(pkt, 'ip'):
                logger.debug("Packet missing IP layer")
                return None
            ip = pkt.ip
            proto = pkt.transport_layer
            if proto not in ['TCP', 'UDP']:
                logger.debug(f"Unsupported protocol: {proto}")
                return None
            sport = int(pkt[pkt.transport_layer].srcport)
            dport = int(pkt[pkt.transport_layer].dstport)
            return (ip.src, ip.dst, sport, dport, proto)
        else:
            ip = pkt[IP]
            proto = "TCP" if TCP in pkt else "UDP" if UDP in pkt else None
            if not proto:
                logger.debug("Packet missing TCP/UDP layer")
                return None
            sport = pkt[TCP].sport if proto == "TCP" else pkt[UDP].sport
            dport = pkt[TCP].dport if proto == "TCP" else pkt[UDP].dport
            return (ip.src, ip.dst, sport, dport, proto)
    except (AttributeError, IndexError) as e:
        logger.warning(f"Failed to parse packet: {e}")
        return None