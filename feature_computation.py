import pandas as pd
import numpy as np
import logging
import os
from config import OUTPUT_CSV

logger = logging.getLogger(__name__)

def compute_features(key, flow):
    """Compute flow features for CSV output."""
    duration = (flow['flow_end'] - flow['flow_start']) if flow['flow_start'] else 0
    f = lambda x: (np.mean(x) if x else 0, np.std(x) if x else 0, np.max(x) if x else 0, np.min(x) if x else 0, np.sum(x) if x else 0)
    
    pkt_len = f(flow['all_pkt_len'])
    fwd_len = f(flow['fwd_pkt_len'])
    bwd_len = f(flow['bwd_pkt_len'])
    flow_iat = f(flow['flow_iat'])
    fwd_iat = f(flow['fwd_iat'])
    bwd_iat = f(flow['bwd_iat'])
    active = f([end - start for start, end in flow['active_periods'] if end > start])
    idle = f(flow['idle_periods'])
    subflow_fwd_pkts = f(flow['subflow_fwd_pkts'])
    subflow_bwd_pkts = f(flow['subflow_bwd_pkts'])
    subflow_fwd_bytes = f(flow['subflow_fwd_bytes'])
    subflow_bwd_bytes = f(flow['subflow_bwd_bytes'])
    fwd_win = f(flow['fwd_win_bytes'])
    bwd_win = f(flow['bwd_win_bytes'])
    fwd_bulk_rate = f([bytes / (end - start) if end - start > 0 else 0 for bytes, (start, end) in zip(flow['fwd_bulk_bytes'], flow['fwd_bulk_durations'])])
    bwd_bulk_rate = f([bytes / (end - start) if end - start > 0 else 0 for bytes, (start, end) in zip(flow['bwd_bulk_bytes'], flow['bwd_bulk_durations'])])

    total_pkts = flow['fwd_pkt_count'] + flow['bwd_pkt_count']
    total_bytes = flow['fwd_bytes'] + flow['bwd_bytes']
    down_up_ratio = flow['bwd_bytes'] / flow['fwd_bytes'] if flow['fwd_bytes'] > 0 else 0
    avg_pkt_size = total_bytes / total_pkts if total_pkts > 0 else 0

    # Application-layer features
    most_common_tls_version = max(flow['tls_versions'], key=flow['tls_versions'].get, default='NONE')
    most_common_http_method = max(flow['http_methods'], key=flow['http_methods'].get, default='NONE')
    most_common_http_code = max(flow['http_response_codes'], key=flow['http_response_codes'].get, default='0')
    most_common_dns_qtype = max(flow['dns_query_types'], key=flow['dns_query_types'].get, default='NONE')
    most_common_dns_rcode = max(flow['dns_response_codes'], key=flow['dns_response_codes'].get, default='0')

    features = {
        'Flow ID': f"{key[0]}-{key[1]}-{key[2]}-{key[3]}-{key[4]}",
        'Src IP': key[0], 'Dst IP': key[1], 'Src Port': key[2], 'Dst Port': key[3], 'Protocol': key[4],
        'Timestamp': flow['flow_start'],
        'Flow Duration': duration * 1000000,  # microseconds
        'Total Fwd Packets': flow['fwd_pkt_count'],
        'Total Backward Packets': flow['bwd_pkt_count'],
        'Total Length of Fwd Packets': flow['fwd_bytes'],
        'Total Length of Bwd Packets': flow['bwd_bytes'],
        'Fwd Packet Length Max': fwd_len[2], 'Fwd Packet Length Min': fwd_len[3],
        'Fwd Packet Length Mean': fwd_len[0], 'Fwd Packet Length Std': fwd_len[1],
        'Bwd Packet Length Max': bwd_len[2], 'Bwd Packet Length Min': bwd_len[3],
        'Bwd Packet Length Mean': bwd_len[0], 'Bwd Packet Length Std': bwd_len[1],
        'Flow Bytes/s': total_bytes / (duration * 1000000) if duration > 0 else 0,
        'Flow Packets/s': total_pkts / (duration * 1000000) if duration > 0 else 0,
        'Flow IAT Mean': flow_iat[0], 'Flow IAT Std': flow_iat[1],
        'Flow IAT Max': flow_iat[2], 'Flow IAT Min': flow_iat[3],
        'Fwd IAT Total': fwd_iat[4], 'Fwd IAT Mean': fwd_iat[0],
        'Fwd IAT Std': fwd_iat[1], 'Fwd IAT Max': fwd_iat[2], 'Fwd IAT Min': fwd_iat[3],
        'Bwd IAT Total': bwd_iat[4], 'Bwd IAT Mean': bwd_iat[0],
        'Bwd IAT Std': bwd_iat[1], 'Bwd IAT Max': bwd_iat[2], 'Bwd IAT Min': bwd_iat[3],
        'Fwd PSH Flags': flow['fwd_psh_flags'], 'Bwd PSH Flags': flow['bwd_psh_flags'],
        'Fwd URG Flags': flow['fwd_urg_flags'], 'Bwd URG Flags': flow['bwd_urg_flags'],
        'Fwd Header Length': np.sum(flow['fwd_hdr_len']),
        'Bwd Header Length': np.sum(flow['bwd_hdr_len']),
        'Fwd Packets/s': flow['fwd_pkt_count'] / (duration * 1000000) if duration > 0 else 0,
        'Bwd Packets/s': flow['bwd_pkt_count'] / (duration * 1000000) if duration > 0 else 0,
        'Min Packet Length': pkt_len[3], 'Max Packet Length': pkt_len[2],
        'Packet Length Mean': pkt_len[0], 'Packet Length Std': pkt_len[1],
        'Packet Length Variance': pkt_len[1] ** 2 if pkt_len[1] > 0 else 0,
        'FIN Flag Count': flow['flag_counts']['F'], 'SYN Flag Count': flow['flag_counts']['S'],
        'RST Flag Count': flow['flag_counts']['R'], 'PSH Flag Count': flow['flag_counts']['P'],
        'ACK Flag Count': flow['flag_counts']['A'], 'URG Flag Count': flow['flag_counts']['U'],
        'CWR Flag Count': flow['flag_counts']['C'], 'ECE Flag Count': flow['flag_counts']['E'],
        'Down/Up Ratio': down_up_ratio,
        'Average Packet Size': avg_pkt_size,
        'Avg Fwd Segment Size': np.mean(flow['fwd_seg_size']) if flow['fwd_seg_size'] else 0,
        'Avg Bwd Segment Size': np.mean(flow['bwd_seg_size']) if flow['bwd_seg_size'] else 0,
        'Fwd Header Length.1': np.sum(flow['fwd_hdr_len']),
        'Fwd Avg Bytes/Bulk': np.mean(flow['fwd_bulk_bytes']) if flow['fwd_bulk_bytes'] else 0,
        'Fwd Avg Packets/Bulk': np.mean(flow['fwd_bulk_pkts']) if flow['fwd_bulk_pkts'] else 0,
        'Fwd Avg Bulk Rate': fwd_bulk_rate[0],
        'Bwd Avg Bytes/Bulk': np.mean(flow['bwd_bulk_bytes']) if flow['bwd_bulk_bytes'] else 0,
        'Bwd Avg Packets/Bulk': np.mean(flow['bwd_bulk_pkts']) if flow['bwd_bulk_pkts'] else 0,
        'Bwd Avg Bulk Rate': bwd_bulk_rate[0],
        'Subflow Fwd Packets': subflow_fwd_pkts[0], 'Subflow Fwd Bytes': subflow_fwd_bytes[0],
        'Subflow Bwd Packets': subflow_bwd_pkts[0], 'Subflow Bwd Bytes': subflow_bwd_bytes[0],
        'Init_Win_bytes_forward': flow['fwd_win_bytes'][0] if flow['fwd_win_bytes'] else 0,
        'Init_Win_bytes_backward': flow['bwd_win_bytes'][0] if flow['bwd_win_bytes'] else 0,
        'act_data_pkt_fwd': flow['fwd_data_pkts'],
        'min_seg_size_forward': np.min(flow['fwd_seg_size']) if flow['fwd_seg_size'] else 0,
        'Active Mean': active[0], 'Active Std': active[1], 'Active Max': active[2], 'Active Min': active[3],
        'Idle Mean': idle[0], 'Idle Std': idle[1], 'Idle Max': idle[2], 'Idle Min': idle[3],
        # Application-layer features
        'HTTP Request Count': flow['http_requests'],
        'HTTP Response Count': flow['http_responses'],
        'HTTP Most Common Method': most_common_http_method,
        'HTTP Most Common Response Code': most_common_http_code,
        'HTTP Content Length': flow['http_content_length'],
        'TLS Handshake Count': flow['tls_handshakes'],
        'TLS Most Common Version': most_common_tls_version,
        'TLS Cipher Suite Count': len(flow['tls_cipher_suites']),
        'TLS Extensions Count': flow['tls_extensions'],
        'DNS Query Count': flow['dns_queries'],
        'DNS Response Count': flow['dns_responses'],
        'DNS Most Common Query Type': most_common_dns_qtype,
        'DNS Most Common Response Code': most_common_dns_rcode
    }
    logger.debug(f"Computed features for {key}: {features}")
    return features

def write_flow_to_csv(flow_key, flow_data):
    """Write flow features to CSV."""
    try:
        features = compute_features(flow_key, flow_data)
        df = pd.DataFrame([features])
        df.to_csv(OUTPUT_CSV, mode='a', header=not os.path.exists(OUTPUT_CSV), index=False)
        logger.info(f"Flow written to CSV: {flow_key}")
    except IOError as e:
        logger.error(f"Failed to write to CSV: {e}")