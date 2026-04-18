import requests
import time

BASE_URL = "http://127.0.0.1:5000"

def run_simulation():
    print("\n🚀 Starting Traffic Simulation...")
    
    # Login
    try:
        resp = requests.post(f"{BASE_URL}/login", json={"username": "admin", "password": "admin123"})
        token = resp.json().get("token")
        headers = {"Authorization": f"Bearer {token}"}
        print("Logged in successfully. Token acquired.\n")
    except requests.exceptions.ConnectionError:
        print("Error: Cannot connect to server. Is run.py running?")
        return

    scenarios = [
        {"name": "Normal Traffic", "count": 150, "ips": ["192.168.1.1", "10.0.0.2", "172.16.0.4", "8.8.8.8"]},
        {"name": "Flash Crowd (High Volume, Many IPs)", "count": 6500, "ips": [f"203.0.113.{i}" for i in range(1, 100)]},
        {"name": "DoS Attack (High Volume, Few Spoofed IPs)", "count": 15000, "ips": ["45.22.12.1", "45.22.12.1", "45.22.12.2"]}
    ]

    for s in scenarios:
        print(f"Simulating Scenario: {s['name']}")
        r = requests.post(f"{BASE_URL}/traffic_sniffer", json={"packet_count": s["count"], "ips": s["ips"]})
        data = r.json()
        print(f"   -> Verdict: {data.get('verdict')} | Entropy: {data.get('entropy')}")
        print(f"   -> Database Hash Chain: {data.get('log_hash')[:25]}...\n")

        if data.get("mitigation"):
            print("   Triggering Mitigation Engine Secure Channel...")
            mit_r = requests.post(f"{BASE_URL}/mitigation_engine", json={"target_ip": "45.22.12.1"}, headers=headers)
            print(f"   -> Firewall Response: {mit_r.json().get('status')} via {mit_r.json().get('secure_channel_used')}\n")
        time.sleep(2)

if __name__ == "__main__":
    run_simulation()