class BankingTrojanSimulator:
    """
    Banking Trojan Simulator - แสดงแนวคิดการทำงาน
    Educational purpose only - DO NOT use in real systems
    """
    
    def __init__(self):
        self.target_sites = [
            "bank.com",
            "paypal.com",
            "stripe.com"
        ]
        self.captured_credentials = []
    
    def monitor_browser(self):
        """จำลองการตรวจสอบ browser activity"""
        print("[SIMULATION] Monitoring browser activity...")
        print("[SIMULATION] Waiting for banking websites...")
    
    def inject_fake_form(self, url):
        """จำลองการแทรก fake login form"""
        if any(site in url for site in self.target_sites):
            print(f"[SIMULATION] Detected banking site: {url}")
            print("[SIMULATION] Injecting fake login form...")
            print("[SIMULATION] Waiting for user credentials...")
    
    def capture_credentials(self, username, password):
        """จำลองการขโมย credentials"""
        print(f"[SIMULATION] Captured credentials!")
        self.captured_credentials.append({
            'username': username,
            'password': '****' + password[-4:],  # แสดงแค่ 4 ตัวท้าย
            'timestamp': '2024-01-15 10:30:00'
        })
    
    def send_to_attacker(self):
        """ส่งข้อมูลไปยัง C&C server"""
        print("[SIMULATION] Sending data to C&C server...")
        print(f"[SIMULATION] Total credentials stolen: {len(self.captured_credentials)}")

# Demo
if __name__ == "__main__":
    print("=== Banking Trojan Behavior Simulation ===\n")
    trojan = BankingTrojanSimulator()
    trojan.monitor_browser()
    trojan.inject_fake_form("https://bank.com/login")
    trojan.capture_credentials("user@example.com", "password123")
    trojan.send_to_attacker()