import os
import numpy as np
import pandas as pd
from scapy.all import PcapReader, IP, TCP, UDP
from collections import defaultdict
from pathlib import Path
from typing import Dict
import time

PROJECT_ROOT: Path = Path(__file__).resolve().parent.parent

print(f"[*] PROJECT ROOT: {PROJECT_ROOT}")

PCAP_FILE = PROJECT_ROOT / "raw-datasets" / "202503181400.pcap.gz"
OUTPUT_FILE = PROJECT_ROOT /"parsed" / "mawi_flows_2M.csv"

print(f"[*] PCAP FILE: {PCAP_FILE}")
print(f"[*] OUTPUT FILE: {OUTPUT_FILE}")

MAX_PACKETS = 2000000
MIN_PACKETS_PER_FLOW = 5

flow_buffer =defaultdict(list)

def calculate_advanced_features(iat: np.ndarray, sizes: np.ndarray) -> Dict[str, float]:
  """
  Extracts Burst and Silence metrics 
  """
  
  if len(iat) == 0:
    return { k: 0.0 for k in ["burst_density", "mean_burst_time", "std_burst_time", "mean_idle_time", "std_idle_time", "idle_ratio"] }
  
  threshold = max(np.mean(iat) + 2 * np.std(iat), 0.05)
  idle_indices = np.where(iat > threshold)[0]
  
  # Silence stats
  if len(idle_indices) > 0:
    idle_times = iat[idle_indices]
    mean_idle = np.mean(idle_times)
    std_idle = np.std(idle_times)
    total_idle_time = np.sum(idle_times)
  else: 
    mean_idle, std_idle, total_idle_time = 0, 0, 0
  
  total_time = np.sum(iat)
  total_active_time = total_time - total_idle_time
  
  # Burst Density 
  burst_density = float(np.sum(sizes) / (total_active_time + 1e-6))
  
  return {
    "burst_density": burst_density,
    "mean_burst_time": total_active_time / (len(idle_indices) + 1),
    "std_burst_time": 0.0, # Skipped for performance
    "mean_idle_time": mean_idle,
    "std_idle_time": std_idle, 
    "idle_ratio": total_idle_time / (total_time + 1e-6)
  }
  
def calculate_features(flow_key, packets):
  """
  Turns a list of raw packets into a single row of statistical features. 
  """
  
  timestamps = np.array([p[0] for p in packets])
  sizes= np.array([p[1] for p in packets])
  
  packet_count = len(sizes)
  total_bytes = np.sum(sizes)
  duration = timestamps[-1] - timestamps[0]
  
  if duration == 0: duration = 1e-6
  
  iat = np.diff(timestamps)
  
  if len(iat) > 0:
    mean_iat = float(np.mean(iat))
    std_iat = float(np.std(iat))
    max_iat = float(np.max(iat))
  else:
    mean_iat, std_iat, max_iat = 0.0, 0.0, 0.0
    
  mean_size = float(np.mean(sizes))
  std_size = float(np.std(sizes))
  min_size = float(np.min(sizes))
  max_size = float(np.max(sizes))

  advanced_stats = calculate_advanced_features(iat, sizes)
  large_packet_ratio = float(np.sum(sizes > 1200)) / len(sizes) if len(sizes) > 0 else 0.0
      
  return {
    "src_ip": flow_key[0],
    "dst_ip": flow_key[1],
    "src_port": flow_key[2],
    "dst_port": flow_key[3],
    "protocol": flow_key[4],
    "packet_count": packet_count,
    "flow_duration": duration,
    "total_bytes": total_bytes,
    "mean_packet_size": mean_size,
    "std_packet_size": std_size,
    "min_packet_size": min_size,
    "max_packet_size": max_size,
    "large_packet_ratio": large_packet_ratio,
    "mean_iat": mean_iat,
    "std_iat": std_iat,
    "max_iat": max_iat,
    "burst_density": advanced_stats["burst_density"],
    "mean_burst_time": advanced_stats["mean_burst_time"],
    "std_burst_time": advanced_stats["std_burst_time"],
    "idle_ratio": advanced_stats["idle_ratio"],
    "mean_idle_time": advanced_stats["mean_idle_time"],
    "std_idle_time": advanced_stats["std_idle_time"]
  }

def process_mawi_stream():
  pcap_str = str(PCAP_FILE)
  
  print(f"[*] STARTING STREAM: {PCAP_FILE}")
  print(f"[*] STOP LIMITT: {MAX_PACKETS:,} packets")
  
  count = 0
  start_time = time.time()
  
  try:
    with PcapReader(pcap_str) as pcap:
      for packet in pcap:
        if IP in packet: 
          real_length = packet[IP].len
          timestamp = float(packet.time)
          
          src = packet[IP].src
          dst = packet[IP].dst
          proto = packet[IP].proto
          
          sport = 0
          dport = 0
          
          if TCP in packet:
            sport = packet[TCP].sport
            dport = packet[TCP].dport
          elif UDP in packet:
            sport = packet[UDP].sport
            dport = packet[UDP].dport
          else: 
            # SKIPPING ICMP/IGMP/etc FOR NOW
            continue
          
          key = (src, dst, sport, dport, proto)
          flow_buffer[key].append((timestamp, real_length))
          
          count += 1
          
          if count % 100000 == 0:
            print(f"[*] Processed {count:,} packets")
            
          if count >= MAX_PACKETS:
            print("[!] MAX PACKET LIMIT REACHED")
            break
  except FileNotFoundError: 
    print(f"[ERROR] FILE NOT FOUND AT {PCAP_FILE}.")
    return
  
  print(f"[*] COMPLETED STREAM. {count:,} packets processed in {time.time() - start_time:.2f} seconds.")
  print(f"[*] CALCULATING STATISTICAL FEATURES...")
  
  dataset = []
  
  for key, packet, in flow_buffer.items():
    if len(packet) >= MIN_PACKETS_PER_FLOW:
      features = calculate_features(key, packet)
      dataset.append(features)
  
  df = pd.DataFrame(dataset)
  df.to_csv(OUTPUT_FILE, index=False)
  
  end_time = time.time()
  print(f"\n[SUCCESS] SAVED {len(df):,} flows to {OUTPUT_FILE}")
  print(f"TIME TAKEN: {end_time - start_time:.2f} seconds")
  

if __name__ == "__main__":
  process_mawi_stream()
