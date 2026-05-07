import pandas as pd
import random
import socket
import struct

def generate_random_ip():
    """Generates a random public IPv4 address."""
    return socket.inet_ntoa(struct.pack('>I', random.randint(1, 0xffffffff)))

records = []
target_ip = "10.0.0.4" # Your internal honeypot IP

# Generate 500 diverse fake "attacks"
for _ in range(500):
    attack_type = random.choice(["brute_force", "port_scan", "ddos", "normal"])
    src_ip = generate_random_ip()
    
    if attack_type == "brute_force":
        # High packet count, long duration, moderate bytes
        pkt_count = random.randint(15, 150)
        duration = random.uniform(10.0, 300.0)
        bytes_sent = pkt_count * random.randint(100, 500)
    elif attack_type == "port_scan":
        # Low packet count, very short duration
        pkt_count = random.randint(1, 3)
        duration = random.uniform(0.1, 2.0)
        bytes_sent = pkt_count * random.randint(40, 60)
    elif attack_type == "ddos":
        # Massive packet count, huge bytes, varied duration
        pkt_count = random.randint(500, 5000)
        duration = random.uniform(1.0, 60.0)
        bytes_sent = pkt_count * random.randint(1000, 1500)
    else: # normal
        # Standard SSH session behavior
        pkt_count = random.randint(5, 20)
        duration = random.uniform(5.0, 60.0)
        bytes_sent = pkt_count * random.randint(100, 800)

    records.append({
        'src_ip': src_ip,
        'dst_ip': target_ip,
        'protocol': 'TCP',
        'packet_count': pkt_count,
        'total_bytes': bytes_sent,
        'duration': round(duration, 3),
        'src_bytes': bytes_sent,
        'dst_bytes': 0 # Simplified
    })

# Save to CSV
df = pd.DataFrame(records)
df.to_csv("synthetic_attacks_features.csv", index=False)
print(f"Generated {len(df)} synthetic attack flows!")