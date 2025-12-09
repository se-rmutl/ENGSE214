class WannaCrySimulator:
    """
    จำลองพฤติกรรมของ WannaCry
    Educational demonstration only
    """
    
    def __init__(self):
        self.infected_hosts = []
        self.kill_switch_domain = "iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com"
    
    def check_kill_switch(self):
        """WannaCry ตรวจสอบ kill switch domain"""
        try:
            # ถ้า domain นี้ resolve ได้ = หยุดการแพร่กระจาย
            import socket
            socket.gethostbyname(self.kill_switch_domain)
            print("[SIMULATION] Kill switch activated! Stopping propagation.")
            return True
        except:
            print("[SIMULATION] Kill switch not found. Continue spreading.")
            return False
    
    def scan_smb_vulnerability(self):
        """สแกนหา SMBv1 vulnerability (MS17-010)"""
        print("[SIMULATION] Scanning network for SMB vulnerability...")
        # ในความเป็นจริง: ใช้ EternalBlue exploit
        vulnerable_hosts = [
            "192.168.1.10",  # Windows 7 (unpatched)
            "192.168.1.20",  # Windows XP
        ]
        return vulnerable_hosts
    
    def exploit_and_spread(self, target):
        """ใช้ exploit และแพร่กระจาย"""
        print(f"[SIMULATION] Exploiting {target}...")
        print(f"[SIMULATION] Copying ransomware to {target}...")
        print(f"[SIMULATION] Executing ransomware on {target}...")
        self.infected_hosts.append(target)
    
    def encrypt_files(self):
        """เข้ารหัสไฟล์"""
        print("[SIMULATION] Encrypting files...")
        file_extensions = ['.doc', '.xls', '.pdf', '.jpg', '.png', '.zip']
        print(f"[SIMULATION] Target extensions: {file_extensions}")
    
    def display_ransom_screen(self):
        """แสดงหน้าจอเรียกค่าไถ่"""
        ransom_note = """
╔════════════════════════════════════════════════╗
║              Ooops, your files have            ║
║              been encrypted!                   ║
╠════════════════════════════════════════════════╣
║                                                ║
║  What happened to my computer?                 ║
║  Your important files are encrypted.           ║
║                                                ║
║  Can I recover my files?                       ║
║  Sure. We guarantee that you can recover all   ║
║  your files safely and easily.                 ║
║                                                ║
║  How do I pay?                                 ║
║  Payment is accepted in Bitcoin only.          ║
║                                                ║
║  • Send $300 worth of Bitcoin to:              ║
║    13AM4VW2dhxYgXeQepoHkHSQuy6NgaEb4           ║
║                                                ║
║  Time remaining: 03 : 23 : 45 : 12             ║
║                                                ║
╚════════════════════════════════════════════════╝
        """
        print(ransom_note)

# Demonstration
if __name__ == "__main__":
    print("=== WannaCry Attack Simulation ===\n")
    
    wannacry = WannaCrySimulator()
    
    # Step 1: Check kill switch
    if not wannacry.check_kill_switch():
        # Step 2: Scan for vulnerable hosts
        targets = wannacry.scan_smb_vulnerability()
        
        # Step 3: Exploit and spread
        for target in targets:
            wannacry.exploit_and_spread(target)
        
        # Step 4: Encrypt files
        wannacry.encrypt_files()
        
        # Step 5: Display ransom screen
        wannacry.display_ransom_screen()