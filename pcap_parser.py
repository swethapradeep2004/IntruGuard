import os
import pandas as pd
from scapy.all import rdpcap, IP, TCP, UDP

def parse_pcap_to_csv(input_pcap, output_csv):
    print(f"Parsing {input_pcap} into flows...")
    try:
        packets = rdpcap(input_pcap)
    except Exception as e:
        raise Exception(f"Failed to read PCAP: {e}")
        
    flows = {}
    
    # Stateful tracking for features
    for pkt in packets:
        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            proto = pkt[IP].proto
            length = len(pkt)
            
            src_port = 0
            dst_port = 0
            if TCP in pkt:
                src_port = pkt[TCP].sport
                dst_port = pkt[TCP].dport
            elif UDP in pkt:
                src_port = pkt[UDP].sport
                dst_port = pkt[UDP].dport
                
            # Key flow uniquely via source-dest-port
            flow_key = (src_ip, dst_ip, dst_port, proto)
            
            if flow_key not in flows:
                flows[flow_key] = {
                    "src_bytes": 0,
                    "dst_bytes": 0,
                    "logged_in": 0,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port
                }
                
            flows[flow_key]["src_bytes"] += length 
            if dst_port in [80, 443, 22, 21, 3389, 3306, 1433]:
                flows[flow_key]["logged_in"] = 1
                
    # Calculate aggregation counts for NSL-KDD logic
    records = []
    host_counts = {}
    host_srv_counts = {}
    
    for k, v in flows.items():
        dst_ip = v["dst_ip"]
        dst_port = v["dst_port"]
        
        if dst_ip not in host_counts:
            host_counts[dst_ip] = 0
        host_counts[dst_ip] += 1
        
        srv_key = f"{dst_ip}:{dst_port}"
        if srv_key not in host_srv_counts:
            host_srv_counts[srv_key] = 0
        host_srv_counts[srv_key] += 1

    for k, v in flows.items():
        dst_ip = v["dst_ip"]
        dst_port = v["dst_port"]
        srv_key = f"{dst_ip}:{dst_port}"
        
        count = host_counts[dst_ip]
        srv_count = host_srv_counts[srv_key]
        
        dst_host_srv_count = srv_count
        dst_host_same_srv_rate = srv_count / max(1, count)
        
        record = {
            "src_bytes": v["src_bytes"],
            "dst_bytes": v["dst_bytes"],
            "logged_in": v["logged_in"],
            "count": count,
            "srv_count": srv_count,
            "dst_host_srv_count": dst_host_srv_count,
            "dst_host_same_srv_rate": round(dst_host_same_srv_rate, 2)
        }
        records.append(record)
        
    df = pd.DataFrame(records)
    if len(df) == 0:
         df = pd.DataFrame([{
            "src_bytes": 0, "dst_bytes": 0, "logged_in": 0, 
            "count": 0, "srv_count": 0, "dst_host_srv_count": 0, 
            "dst_host_same_srv_rate": 0.0
         }])
         
    df.to_csv(output_csv, index=False)
    print(f"Extraction complete! Saved features to {output_csv}")
    return True
