from collections import defaultdict
import logging

logger = logging.getLogger(__name__)

FLOW_STATS = {}

def init_flow():
    """Initialize a new flow dictionary with default values."""
    return {
        'fwd_pkt_len': [], 'bwd_pkt_len': [], 'all_pkt_len': [],
        'fwd_times': [], 'bwd_times': [], 'all_times': [],
        'fwd_iat': [], 'bwd_iat': [], 'flow_iat': [],
        'flow_start': None, 'flow_end': None,
        'fwd_pkt_count': 0, 'bwd_pkt_count': 0,
        'fwd_bytes': 0, 'bwd_bytes': 0,
        'fwd_flags': [], 'bwd_flags': [],
        'fwd_psh_flags': 0, 'bwd_psh_flags': 0,
        'fwd_urg_flags': 0, 'bwd_urg_flags': 0,
        'flag_counts': defaultdict(int),
        'fwd_hdr_len': [], 'bwd_hdr_len': [],
        'fwd_seg_size': [], 'bwd_seg_size': [],
        'fwd_win_bytes': [], 'bwd_win_bytes': [],
        'fwd_data_pkts': 0, 'bwd_data_pkts': 0,
        'subflow_starts': [], 'subflow_ends': [],
        'subflow_fwd_pkts': [], 'subflow_bwd_pkts': [],
        'subflow_fwd_bytes': [], 'subflow_bwd_bytes': [],
        'fwd_bulk_pkts': [], 'bwd_bulk_pkts': [],
        'fwd_bulk_bytes': [], 'bwd_bulk_bytes': [],
        'fwd_bulk_durations': [], 'bwd_bulk_durations': [],
        'active_periods': [], 'idle_periods': [],
        # Application-layer stats
        'http_requests': 0, 'http_responses': 0,
        'http_methods': defaultdict(int),
        'http_response_codes': defaultdict(int),
        'http_content_length': 0,
        'tls_handshakes': 0,
        'tls_versions': defaultdict(int),
        'tls_cipher_suites': set(),
        'tls_extensions': 0,
        'dns_queries': 0, 'dns_responses': 0,
        'dns_query_types': defaultdict(int),
        'dns_response_codes': defaultdict(int)
    }

def update_flow(pkt, ts, key, direction, USE_PYSHARK, SUBFLOW_WINDOW, BULK_INTERVAL, ACTIVE_THRESHOLD):
    """Update flow statistics based on packet data."""
    flow = FLOW_STATS[key]
    proto = key[4]
    
    if USE_PYSHARK:
        try:
            length = int(pkt.captured_length)
            ip_hdr_len = int(pkt.ip.hdr_len)
            if proto == 'TCP' and hasattr(pkt, 'tcp'):
                tcp_hdr_len = int(getattr(pkt.tcp, 'dataofs', 0)) * 4
                flags = getattr(pkt.tcp, 'flags', '')
                window = int(getattr(pkt.tcp, 'window_size', 0))
            else:
                tcp_hdr_len = 8 if proto == 'UDP' else 0
                flags = ''
                window = 0
            payload_len = length - (ip_hdr_len + tcp_hdr_len)
        except (AttributeError, ValueError) as e:
            logger.warning(f"Failed to parse packet fields for {key}: {e}")
            return
    else:
        from scapy.all import IP, TCP, UDP
        length = len(pkt)
        ip_hdr_len = pkt[IP].ihl * 4
        tcp_hdr_len = pkt[TCP].dataofs * 4 if proto == 'TCP' else 8 if proto == 'UDP' else 0
        payload_len = length - (ip_hdr_len + tcp_hdr_len)
        flags = pkt.sprintf('%TCP.flags%') if proto == 'TCP' else ''
        window = pkt[TCP].window if proto == 'TCP' else 0

    if flow['flow_start'] is None:
        flow['flow_start'] = ts
    flow['flow_end'] = ts
    flow['all_times'].append(ts)
    flow['all_pkt_len'].append(length)

    for flag in ["F", "S", "R", "P", "A", "U", "C", "E"]:
        flow['flag_counts'][flag] += int(flag in flags)

    # Application-layer parsing with pyshark
    if USE_PYSHARK:
        try:
            # HTTP
            if hasattr(pkt, 'http'):
                if hasattr(pkt.http, 'request_method'):
                    flow['http_requests'] += 1
                    method = getattr(pkt.http, 'request_method', 'UNKNOWN')
                    flow['http_methods'][method] += 1
                    logger.debug(f"HTTP request detected: {method}")
                if hasattr(pkt.http, 'response_code'):
                    flow['http_responses'] += 1
                    code = getattr(pkt.http, 'response_code', '0')
                    flow['http_response_codes'][code] += 1
                    logger.debug(f"HTTP response detected: {code}")
                if hasattr(pkt.http, 'content_length'):
                    flow['http_content_length'] += int(getattr(pkt.http, 'content_length', 0))
            
            # TLS/SSL
            if hasattr(pkt, 'tls'):
                if hasattr(pkt.tls, 'handshake_type'):
                    flow['tls_handshakes'] += 1
                    logger.debug(f"TLS handshake detected")
                if hasattr(pkt.tls, 'handshake_version'):
                    version = getattr(pkt.tls, 'handshake_version', 'UNKNOWN')
                    flow['tls_versions'][version] += 1
                if hasattr(pkt.tls, 'handshake_ciphersuite'):
                    cipher = getattr(pkt.tls, 'handshake_ciphersuite', '')
                    flow['tls_cipher_suites'].add(cipher)
                if hasattr(pkt.tls, 'handshake_extensions_length'):
                    flow['tls_extensions'] += int(getattr(pkt.tls, 'handshake_extensions_length', 0))
            
            # DNS
            if hasattr(pkt, 'dns'):
                if hasattr(pkt.dns, 'qry_name'):
                    flow['dns_queries'] += 1
                    qtype = getattr(pkt.dns, 'qry_type', 'UNKNOWN')
                    flow['dns_query_types'][qtype] += 1
                    logger.debug(f"DNS query detected: {qtype}")
                if hasattr(pkt.dns, 'resp_type'):
                    flow['dns_responses'] += 1
                    rcode = getattr(pkt.dns, 'resp_rcode', '0')
                    flow['dns_response_codes'][rcode] += 1
                    logger.debug(f"DNS response detected: {rcode}")
        except (AttributeError, ValueError) as e:
            logger.warning(f"Failed to parse application-layer fields for {key}: {e}")

    # Subflow tracking
    if not flow['subflow_starts'] or ts >= flow['subflow_ends'][-1] + SUBFLOW_WINDOW:
        flow['subflow_starts'].append(ts)
        flow['subflow_ends'].append(ts + SUBFLOW_WINDOW)
        flow['subflow_fwd_pkts'].append(0)
        flow['subflow_bwd_pkts'].append(0)
        flow['subflow_fwd_bytes'].append(0)
        flow['subflow_bwd_bytes'].append(0)
        logger.debug(f"New subflow started for {key} at {ts}")
    flow['subflow_ends'][-1] = max(flow['subflow_ends'][-1], ts)

    # Active/Idle tracking
    if len(flow['all_times']) > 1 and flow['all_times'][-1] - flow['all_times'][-2] > ACTIVE_THRESHOLD:
        idle_time = flow['all_times'][-1] - flow['all_times'][-2]
        flow['idle_periods'].append(idle_time)
        logger.debug(f"Idle period detected for {key}: {idle_time}s")
        if flow['active_periods']:
            flow['active_periods'][-1][-1] = flow['all_times'][-2]
    if not flow['active_periods']:
        flow['active_periods'].append([flow['flow_start'], ts])
    else:
        flow['active_periods'][-1][-1] = ts

    if direction == 'fwd':
        flow['fwd_pkt_len'].append(length)
        flow['fwd_times'].append(ts)
        if len(flow['fwd_times']) > 1:
            flow['fwd_iat'].append(ts - flow['fwd_times'][-2])
        flow['fwd_pkt_count'] += 1
        flow['fwd_bytes'] += length
        flow['fwd_flags'].append(flags)
        flow['fwd_psh_flags'] += int('P' in flags)
        flow['fwd_urg_flags'] += int('U' in flags)
        flow['fwd_hdr_len'].append(ip_hdr_len + tcp_hdr_len)
        flow['fwd_seg_size'].append(window)
        flow['fwd_win_bytes'].append(window)
        flow['fwd_data_pkts'] += int(payload_len > 0)
        flow['subflow_fwd_pkts'][-1] += 1
        flow['subflow_fwd_bytes'][-1] += length
        if payload_len > 0:
            if not flow['fwd_bulk_pkts'] or (len(flow['fwd_times']) > 1 and ts - flow['fwd_times'][-2] > BULK_INTERVAL):
                flow['fwd_bulk_pkts'].append(1)
                flow['fwd_bulk_bytes'].append(payload_len)
                flow['fwd_bulk_durations'].append([ts, ts])
                logger.debug(f"New forward bulk started for {key}")
            else:
                flow['fwd_bulk_pkts'][-1] += 1
                flow['fwd_bulk_bytes'][-1] += payload_len
                flow['fwd_bulk_durations'][-1][-1] = ts
    else:
        flow['bwd_pkt_len'].append(length)
        flow['bwd_times'].append(ts)
        if len(flow['bwd_times']) > 1:
            flow['bwd_iat'].append(ts - flow['bwd_times'][-2])
        flow['bwd_pkt_count'] += 1
        flow['bwd_bytes'] += length
        flow['bwd_flags'].append(flags)
        flow['bwd_psh_flags'] += int('P' in flags)
        flow['bwd_urg_flags'] += int('U' in flags)
        flow['bwd_hdr_len'].append(ip_hdr_len + tcp_hdr_len)
        flow['bwd_seg_size'].append(window)
        flow['bwd_win_bytes'].append(window)
        flow['bwd_data_pkts'] += int(payload_len > 0)
        flow['subflow_bwd_pkts'][-1] += 1
        flow['subflow_bwd_bytes'][-1] += length
        if payload_len > 0:
            if not flow['bwd_bulk_pkts'] or (len(flow['bwd_times']) > 1 and ts - flow['bwd_times'][-2] > BULK_INTERVAL):
                flow['bwd_bulk_pkts'].append(1)
                flow['bwd_bulk_bytes'].append(payload_len)
                flow['bwd_bulk_durations'].append([ts, ts])
                logger.debug(f"New backward bulk started for {key}")
            else:
                flow['bwd_bulk_pkts'][-1] += 1
                flow['bwd_bulk_bytes'][-1] += payload_len
                flow['bwd_bulk_durations'][-1][-1] = ts

    if len(flow['all_times']) > 1:
        flow['flow_iat'].append(ts - flow['all_times'][-2])