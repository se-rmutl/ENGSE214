# Week 5 Labs: Network Security & Packet Filtering in Ubuntu VM

**Course:** ENGSE214 - Introduction to Cyber Security  
**Week:** 5 - Network Security & Basic Packet Filtering  
**Platform:** Ubuntu VM (20.04 LTS or higher)  
**Duration:** 3 hours  
**Difficulty:** ⭐⭐⭐ (Intermediate)

---

## 📋 Lab Overview

| Lab | Topic | Duration | Difficulty |
|-----|-------|----------|------------|
| Lab 1 | Basic Firewall with UFW | 45 min | ⭐⭐ Easy |
| Lab 2 | Network Monitoring & Port Scanning | 45 min | ⭐⭐ Easy |
| Lab 3 | Packet Capture with tcpdump | 45 min | ⭐⭐⭐ Medium |
| Lab 4 | Web Server + Firewall Protection | 45 min | ⭐⭐⭐ Medium |

---

## 🎯 Learning Objectives

หลังจากทำ Labs เหล่านี้แล้ว นักศึกษาจะสามารถ:

✅ **CLO2:** Configure และ manage basic firewall rules ใน Ubuntu  
✅ **CLO3:** Monitor network connections และ identify open ports  
✅ **CLO4:** Capture และ analyze network packets  
✅ **CLO5:** Apply security best practices to protect services

---

## 🛠️ Prerequisites

### ซอฟต์แวร์ที่ต้องมี:
- **Ubuntu VM** (20.04 LTS or higher) ที่รันอยู่
- **Internet connection** (สำหรับติดตั้ง packages)
- **Terminal access** (Ctrl+Alt+T)

### ความรู้พื้นฐาน:
- Linux commands พื้นฐาน (cd, ls, sudo, etc.)
- เข้าใจ IP address และ port numbers
- เข้าใจ TCP/IP พื้นฐาน

### เตรียมความพร้อม:
```bash
# Update system
sudo apt update

# Install required tools
sudo apt install -y net-tools nmap tcpdump curl wget nginx
```

---

## 📚 Background Knowledge

### Port Numbers คืออะไร?
Port คือ "ประตู" ที่โปรแกรมใช้ communicate กับเครือข่าย

**Common Ports:**
- Port 22: SSH (Secure Shell)
- Port 80: HTTP (Web)
- Port 443: HTTPS (Secure Web)
- Port 3306: MySQL Database
- Port 5432: PostgreSQL Database

### UFW (Uncomplicated Firewall) คืออะไร?
UFW เป็น firewall frontend ที่ใช้งานง่ายสำหรับ Ubuntu  
ทำงานโดยการกรอง packets ตาม rules ที่เรากำหนด

---

# 🔥 Lab 1: Basic Firewall with UFW

**Duration:** 45 minutes  
**Difficulty:** ⭐⭐ Easy

## Objectives
- เปิด/ปิด UFW firewall
- สร้าง basic rules (allow/deny)
- ตรวจสอบ firewall status
- Test rules ด้วย actual connections

---

## Part 1.1: Understanding UFW Status

### Step 1: ตรวจสอบสถานะปัจจุบัน

```bash
# ดู status ของ UFW
sudo ufw status verbose

# ถ้า UFW ยังไม่เปิด จะขึ้น:
# Status: inactive
```

### Step 2: Enable UFW

```bash
# เปิด UFW (⚠️ ระวัง! อย่าทำถ้าเชื่อมต่อผ่าน SSH)
sudo ufw enable

# Output:
# Firewall is active and enabled on system startup
```

### Step 3: ดู Default Policy

```bash
sudo ufw status verbose

# Output จะคล้าย:
# Status: active
# Logging: on (low)
# Default: deny (incoming), allow (outgoing), disabled (routed)
```

**❓ คำถาม:** Default policy `deny (incoming)` หมายความว่าอย่างไร?

<details>
<summary>คำตอบ</summary>

Default policy `deny (incoming)` หมายความว่า:
- Block traffic ทั้งหมดที่พยายามเข้ามาจากภายนอก
- ยกเว้น traffic ที่เรา explicitly allow ไว้
- นี่คือ **secure by default** approach

</details>

---

## Part 1.2: Creating Basic Firewall Rules

### Step 4: Allow SSH (Port 22)

```bash
# อนุญาต SSH connections
sudo ufw allow 22/tcp

# หรือใช้ชื่อ service
sudo ufw allow ssh

# ดู rules
sudo ufw status numbered
```

**Output:**
```
     To                         Action      From
     --                         ------      ----
[ 1] 22/tcp                     ALLOW IN    Anywhere
[ 1] 22/tcp (v6)                ALLOW IN    Anywhere (v6)
```

### Step 5: Allow HTTP and HTTPS

```bash
# Allow web traffic
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# หรือใช้แบบสั้น
sudo ufw allow http
sudo ufw allow https

# ตรวจสอบ
sudo ufw status numbered
```

### Step 6: Allow Specific Port Range

```bash
# อนุญาต port range 8000-8100 (สำหรับ development servers)
sudo ufw allow 8000:8100/tcp

# ตรวจสอบ
sudo ufw status numbered
```

---

## Part 1.3: Denying and Deleting Rules

### Step 7: Deny Specific Port

```bash
# ปิดกั้น port 23 (Telnet - ไม่ปลอดภัย)
sudo ufw deny 23/tcp

# ตรวจสอบ
sudo ufw status numbered
```

### Step 8: Delete Rule

```bash
# ลบ rule โดยใช้หมายเลข
sudo ufw status numbered  # ดูหมายเลข rule ก่อน

# ลบ rule ที่ 3 (ตัวอย่าง)
sudo ufw delete 3

# หรือลบโดยระบุ rule โดยตรง
sudo ufw delete deny 23/tcp
```

### Step 9: Reset UFW (ลบ rules ทั้งหมด)

```bash
# ⚠️ Reset UFW to default (ลบ rules ทั้งหมด)
sudo ufw reset

# จะถาม confirmation
# Resetting all rules to installed defaults. This may disrupt existing ssh
# connections. Proceed with operation (y|n)? y
```

---

## Part 1.4: Advanced Rules

### Step 10: Allow from Specific IP

```bash
# อนุญาต connection จาก IP เฉพาะ
sudo ufw allow from 192.168.1.100

# อนุญาต specific port จาก specific IP
sudo ufw allow from 192.168.1.100 to any port 22
```

### Step 11: Allow from Subnet

```bash
# อนุญาต entire subnet
sudo ufw allow from 192.168.1.0/24

# อนุญาต subnet access to specific port
sudo ufw allow from 192.168.1.0/24 to any port 3306
```

### Step 12: Deny from Specific IP

```bash
# Block IP ที่น่าสงสัย
sudo ufw deny from 203.0.113.100

# Block subnet
sudo ufw deny from 203.0.113.0/24
```

---

## Part 1.5: Testing Firewall Rules

### Step 13: Test with Python HTTP Server

**Terminal 1 - Start Web Server:**
```bash
# สร้าง directory สำหรับ test
mkdir ~/web-test
cd ~/web-test
echo "<h1>Hello from Lab 1!</h1>" > index.html

# เริ่ม HTTP server บน port 8080
python3 -m http.server 8080
```

**Terminal 2 - Test Access:**
```bash
# Test ก่อน allow port
curl http://localhost:8080
# ถ้า UFW block จะไม่ได้

# Allow port 8080
sudo ufw allow 8080/tcp

# Test อีกครั้ง
curl http://localhost:8080
# ควรเห็น HTML ที่สร้างไว้
```

### Step 14: Test Block

```bash
# ปิด port 8080
sudo ufw deny 8080/tcp

# Test อีกครั้ง
curl http://localhost:8080 --max-time 5
# curl: (28) Connection timed out
```

---

## Part 1.6: UFW Logging

### Step 15: Enable Logging

```bash
# เปิด logging
sudo ufw logging on

# ตั้งระดับ logging
sudo ufw logging medium  # ระดับ: low, medium, high

# ดู logs
sudo tail -f /var/log/ufw.log
```

### Step 16: Analyze Logs

```bash
# ดู blocked connections
sudo grep "UFW BLOCK" /var/log/ufw.log | tail -20

# ดู allowed connections
sudo grep "UFW ALLOW" /var/log/ufw.log | tail -20
```

---

## 📝 Lab 1 Assignment

### Task 1: Create Custom Firewall Configuration

สร้าง firewall rules ตามความต้องการนี้:

1. **Allow:**
   - SSH (22)
   - HTTP (80) และ HTTPS (443)
   - Custom web app บน port 8080
   - MySQL จาก subnet 192.168.1.0/24 เท่านั้น

2. **Deny:**
   - Telnet (23)
   - FTP (21)
   - All traffic from 10.0.0.50

3. **Default:** Deny incoming, allow outgoing

### Task 2: Document Your Rules

สร้างเอกสาร (text file) ที่มี:
```bash
# บันทึก rules ปัจจุบัน
sudo ufw status numbered > ~/lab1-firewall-rules.txt

# บันทึก verbose status
sudo ufw status verbose >> ~/lab1-firewall-rules.txt
```

### Task 3: Take Screenshots

Capture screenshots ของ:
1. `sudo ufw status verbose`
2. `sudo ufw status numbered`
3. Test การเชื่อมต่อ (allow และ deny)

---

## ✅ Lab 1 Verification Checklist

- [ ] UFW enabled และทำงาน
- [ ] สร้าง rules อย่างน้อย 5 rules
- [ ] Test rules ทั้ง allow และ deny
- [ ] Enable logging และตรวจสอบ logs
- [ ] บันทึก configuration ลงไฟล์
- [ ] Capture screenshots

---

# 🔍 Lab 2: Network Monitoring & Port Scanning

**Duration:** 45 minutes  
**Difficulty:** ⭐⭐ Easy

## Objectives
- ใช้ `netstat` และ `ss` ดู network connections
- Scan ports ด้วย `nmap`
- เข้าใจ open/closed/filtered ports
- Identify suspicious connections

---

## Part 2.1: Viewing Active Connections

### Step 1: Using netstat

```bash
# ดู active connections ทั้งหมด
netstat -tuln

# อธิบาย flags:
# -t : TCP connections
# -u : UDP connections
# -l : Listening ports
# -n : Show numerical addresses (ไม่แปลง IP เป็นชื่อ)
```

**Output อธิบาย:**
```
Proto Recv-Q Send-Q Local Address           Foreign Address         State
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN
```

- **Proto:** Protocol (TCP/UDP)
- **Local Address:** IP:Port ที่ listen
- **Foreign Address:** Remote connection
- **State:** LISTEN (รอ connection), ESTABLISHED (connected)

### Step 2: Using ss (Modern Alternative)

```bash
# ss เร็วกว่าและทันสมัยกว่า netstat
ss -tuln

# ดู active connections พร้อม process name
sudo ss -tulnp

# ดูเฉพาะ TCP listening ports
sudo ss -tlnp

# ดูเฉพาะ ESTABLISHED connections
ss -tn state established
```

### Step 3: Filter Specific Port

```bash
# ดู connections บน port 80
sudo ss -tlnp | grep :80

# ดู connections บน port 22 (SSH)
sudo ss -tlnp | grep :22

# ดู all connections บน specific IP
ss -tn dst 8.8.8.8
```

---

## Part 2.2: Identifying Open Ports

### Step 4: List All Listening Services

```bash
# ดู services ที่กำลัง listen
sudo netstat -tlnp

# หรือ
sudo ss -tlnp | grep LISTEN
```

**Output ตัวอย่าง:**
```
LISTEN  0  128  0.0.0.0:22  0.0.0.0:*  users:(("sshd",pid=1234,fd=3))
LISTEN  0  128  127.0.0.53:53  0.0.0.0:*  users:(("systemd-resolve",pid=567,fd=13))
```

### Step 5: Count Connections by State

```bash
# นับ connections แต่ละ state
netstat -tan | awk '{print $6}' | sort | uniq -c | sort -rn

# Output:
#   45 ESTABLISHED
#   12 TIME_WAIT
#    3 LISTEN
```

### Step 6: Find Process Using Specific Port

```bash
# หา process ที่ใช้ port 80
sudo lsof -i :80

# หา process ที่ใช้ port 22
sudo lsof -i :22

# หาทุก process ที่ใช้ network
sudo lsof -i
```

---

## Part 2.3: Port Scanning with Nmap

### Step 7: Basic Port Scan

```bash
# Scan localhost
nmap localhost

# Scan specific IP (ตัวเอง)
nmap 127.0.0.1

# Output:
# PORT     STATE SERVICE
# 22/tcp   open  ssh
# 80/tcp   open  http
```

### Step 8: Scan Specific Ports

```bash
# Scan port เฉพาะ
nmap -p 22,80,443 localhost

# Scan port range
nmap -p 1-1000 localhost

# Scan all 65535 ports (⚠️ ใช้เวลานาน)
nmap -p- localhost
```

### Step 9: Service Version Detection

```bash
# Detect service versions
sudo nmap -sV localhost

# Output:
# PORT     STATE SERVICE VERSION
# 22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5
# 80/tcp   open  http    nginx 1.18.0
```

### Step 10: OS Detection

```bash
# Detect OS (ต้อง sudo)
sudo nmap -O localhost

# Aggressive scan (combines OS detection, version detection, script scanning, and traceroute)
sudo nmap -A localhost
```

---

## Part 2.4: Understanding Nmap Results

### Port States Explained

**Open:**
- Service กำลังรอ connection บน port นี้
- ตัวอย่าง: `22/tcp open ssh`

**Closed:**
- ไม่มี service บน port นี้
- แต่ port เข้าถึงได้ (ไม่มี firewall block)
- ตัวอย่าง: `23/tcp closed telnet`

**Filtered:**
- Firewall block port นี้
- nmap ไม่แน่ใจว่าเปิดหรือปิด
- ตัวอย่าง: `3306/tcp filtered mysql`

### Step 11: Compare Before and After Firewall

**Before UFW:**
```bash
# ปิด UFW
sudo ufw disable

# Scan
nmap -p 1-1000 localhost > scan-without-firewall.txt
cat scan-without-firewall.txt
```

**After UFW:**
```bash
# เปิด UFW
sudo ufw enable
sudo ufw deny 3306  # Block MySQL

# Scan
nmap -p 1-1000 localhost > scan-with-firewall.txt
cat scan-with-firewall.txt

# เปรียบเทียบ
diff scan-without-firewall.txt scan-with-firewall.txt
```

---

## Part 2.5: Advanced Monitoring

### Step 12: Monitor Connections in Real-Time

**Terminal 1 - Monitor:**
```bash
# Watch connections in real-time
watch -n 1 'sudo ss -tulnp | grep LISTEN'

# หรือ
watch -n 1 'netstat -tuln | grep LISTEN'
```

**Terminal 2 - Create Traffic:**
```bash
# Start services to see changes
python3 -m http.server 8080 &
python3 -m http.server 8081 &
```

### Step 13: Network Statistics

```bash
# ดู network interface statistics
netstat -i

# ดู routing table
netstat -r

# หรือ
ip route show

# ดู network interface details
ip addr show
```

### Step 14: Check for Suspicious Connections

```bash
# ดู connections ไป/มาจาก external IPs
sudo netstat -tuln | grep -v "127.0.0.1" | grep ESTABLISHED

# ดู connections จาก foreign IPs
ss -tn state established | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -rn
```

---

## 📝 Lab 2 Assignment

### Task 1: Network Baseline

สร้าง "baseline" ของ network ปกติ:

```bash
# 1. List all listening ports
sudo ss -tulnp | grep LISTEN > ~/baseline-listening-ports.txt

# 2. List all established connections
ss -tn state established > ~/baseline-connections.txt

# 3. Scan yourself
nmap -sV localhost > ~/baseline-nmap-scan.txt
```

### Task 2: Install and Monitor New Service

1. ติดตั้ง service ใหม่:
```bash
sudo apt install apache2
```

2. Monitor การเปลี่ยนแปลง:
```bash
# Before
sudo ss -tulnp | grep LISTEN > before.txt

# Start apache2
sudo systemctl start apache2

# After
sudo ss -tulnp | grep LISTEN > after.txt

# Compare
diff before.txt after.txt
```

3. Scan port ใหม่:
```bash
nmap localhost
```

### Task 3: Firewall Impact Analysis

1. Scan ports โดยไม่มี firewall rules
2. เพิ่ม firewall rules เพื่อ block ports บางตัว
3. Scan อีกครั้งและเปรียบเทียบผล
4. เขียนรายงานสั้น ๆ อธิบายผลที่เกิดขึ้น

---

## ✅ Lab 2 Verification Checklist

- [ ] ใช้ `netstat` และ `ss` ได้
- [ ] เข้าใจ output ของ network monitoring tools
- [ ] ใช้ `nmap` scan ports ได้
- [ ] เข้าใจ port states (open/closed/filtered)
- [ ] สร้าง network baseline
- [ ] Monitor การเปลี่ยนแปลงเมื่อติดตั้ง service ใหม่

---

# 📡 Lab 3: Packet Capture with tcpdump

**Duration:** 45 minutes  
**Difficulty:** ⭐⭐⭐ Medium

## Objectives
- Capture packets ด้วย `tcpdump`
- Filter packets ตาม criteria ต่าง ๆ
- Analyze packet contents
- เปรียบเทียบ HTTP vs HTTPS

---

## Part 3.1: Basic Packet Capture

### Step 1: Check Network Interfaces

```bash
# List network interfaces
ip link show

# หรือ
ifconfig -a

# เลือก interface ที่ active (มักจะเป็น eth0, enp0s3, หรือ wlan0)
```

### Step 2: Simple Capture

```bash
# Capture packets (Ctrl+C เพื่อหยุด)
sudo tcpdump

# Output จะคล้าย:
# 14:23:45.123456 IP ubuntu.local.54321 > dns.google.443: Flags [S], seq 123456, win 65535
```

**⚠️ หมายเหตุ:** tcpdump จะแสดง packets จำนวนมาก! กด Ctrl+C เพื่อหยุด

### Step 3: Limit Number of Packets

```bash
# Capture เพียง 10 packets
sudo tcpdump -c 10

# Capture และบันทึกลงไฟล์
sudo tcpdump -c 100 -w ~/lab3-capture.pcap
```

---

## Part 3.2: Filtering Packets

### Step 4: Filter by Interface

```bash
# Capture จาก interface เฉพาะ
sudo tcpdump -i eth0

# หรือ
sudo tcpdump -i enp0s3

# Capture จาก loopback (localhost)
sudo tcpdump -i lo
```

### Step 5: Filter by Host

```bash
# Capture packets จาก/ไป specific host
sudo tcpdump host 8.8.8.8

# Capture packets จาก host เฉพาะ
sudo tcpdump src host 192.168.1.100

# Capture packets ไป host เฉพาะ
sudo tcpdump dst host 8.8.8.8
```

### Step 6: Filter by Port

```bash
# Capture HTTP traffic (port 80)
sudo tcpdump port 80

# Capture HTTPS traffic (port 443)
sudo tcpdump port 443

# Capture SSH traffic (port 22)
sudo tcpdump port 22

# Multiple ports
sudo tcpdump port 80 or port 443
```

### Step 7: Filter by Protocol

```bash
# TCP only
sudo tcpdump tcp

# UDP only
sudo tcpdump udp

# ICMP (ping) only
sudo tcpdump icmp

# Specific protocol และ port
sudo tcpdump tcp port 80
```

---

## Part 3.3: HTTP Traffic Analysis

### Step 8: Capture HTTP Traffic

**Terminal 1 - Start Capture:**
```bash
# Capture HTTP traffic และแสดง content (-A flag)
sudo tcpdump -i any -A port 80

# หรือแสดงใน hex และ ASCII
sudo tcpdump -i any -X port 80
```

**Terminal 2 - Generate HTTP Traffic:**
```bash
# ทำ HTTP request
curl http://example.com

# หรือ
wget http://example.com
```

**ดู Output:**
```
GET / HTTP/1.1
Host: example.com
User-Agent: curl/7.68.0
Accept: */*
```

### Step 9: See HTTP Response

```bash
# Capture และแสดง response
sudo tcpdump -i any -A 'tcp port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)'
```

**Output จะแสดง HTTP response:**
```
HTTP/1.1 200 OK
Content-Type: text/html
...
<html>
<body>
...
```

---

## Part 3.4: HTTPS vs HTTP Comparison

### Step 10: Capture HTTPS Traffic

**Terminal 1 - Capture HTTPS:**
```bash
# Capture HTTPS (port 443)
sudo tcpdump -i any -A port 443

# บันทึกลงไฟล์
sudo tcpdump -i any -A port 443 -w https-capture.pcap
```

**Terminal 2 - Generate HTTPS Traffic:**
```bash
# ทำ HTTPS request
curl https://example.com
```

**❓ คำถาม:** คุณเห็น content ของ HTTPS traffic หรือไม่?

<details>
<summary>คำตอบ</summary>

**ไม่เห็น!** HTTPS traffic ถูกเข้ารหัสทั้งหมด  

Output จะแสดงแค่:
- IP addresses
- Port numbers
- Encrypted data (ดูเหมือนตัวอักษรสุ่ม)

**ไม่สามารถ** อ่าน:
- URL path
- HTTP headers
- Response body
- Any sensitive data

นี่คือจุดสำคัญของ HTTPS! 🔒
</details>

### Step 11: Side-by-Side Comparison

**HTTP (Port 80):**
```bash
sudo tcpdump -i any -A -c 5 'tcp port 80'
curl http://neverssl.com &
```

**HTTPS (Port 443):**
```bash
sudo tcpdump -i any -A -c 5 'tcp port 443'
curl https://example.com &
```

**สังเกต:**
- HTTP: เห็น plain text ทั้งหมด
- HTTPS: เห็นแต่ encrypted data

---

## Part 3.5: Advanced Filtering

### Step 12: Filter by Network

```bash
# Capture จาก subnet
sudo tcpdump net 192.168.1.0/24

# Capture ยกเว้น subnet
sudo tcpdump not net 192.168.1.0/24
```

### Step 13: Complex Filters

```bash
# HTTP GET requests only
sudo tcpdump -i any -A 'tcp port 80 and tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x47455420'

# SYN packets (connection attempts)
sudo tcpdump 'tcp[tcpflags] & tcp-syn != 0'

# DNS queries
sudo tcpdump -i any port 53
```

### Step 14: Save and Read Captures

```bash
# Save to file
sudo tcpdump -w capture.pcap

# Read from file
tcpdump -r capture.pcap

# Read และ filter
tcpdump -r capture.pcap port 80

# Read และแสดง timestamps
tcpdump -r capture.pcap -tttt
```

---

## Part 3.6: Practical Scenarios

### Step 15: Troubleshoot Connection Issues

**Scenario:** Web server ไม่ respond

```bash
# Capture traffic to web server
sudo tcpdump -i any host <server-ip> and port 80

# ดูว่า:
# 1. มี SYN packet ส่งไปหรือไม่?
# 2. มี SYN-ACK กลับมาหรือไม่?
# 3. มี RST (connection reset) หรือไม่?
```

### Step 16: Monitor Bandwidth Usage

```bash
# Show packet sizes
sudo tcpdump -i any -nn -q

# Count packets per host
sudo tcpdump -i any -nn | awk '{print $3}' | sort | uniq -c | sort -rn
```

### Step 17: Detect Port Scanning

```bash
# Detect SYN scan (port scanning)
sudo tcpdump 'tcp[tcpflags] & (tcp-syn) != 0 and tcp[tcpflags] & (tcp-ack) = 0'

# Monitor ใน Terminal 1
# ทำ nmap scan ใน Terminal 2
nmap -sS localhost
```

---

## 📝 Lab 3 Assignment

### Task 1: HTTP vs HTTPS Analysis

1. **Capture HTTP Traffic:**
```bash
# Terminal 1
sudo tcpdump -i any -A port 80 -w http-capture.pcap

# Terminal 2
curl http://neverssl.com
```

2. **Capture HTTPS Traffic:**
```bash
# Terminal 1
sudo tcpdump -i any -A port 443 -w https-capture.pcap

# Terminal 2
curl https://example.com
```

3. **Analysis:**
   - อ่านทั้ง 2 ไฟล์ด้วย `tcpdump -r`
   - เปรียบเทียบว่าเห็นอะไรบ้าง
   - เขียนรายงาน 1 หน้า อธิบายความแตกต่าง

### Task 2: Monitor Your Own Application

1. สร้าง simple web server:
```bash
python3 -m http.server 8000
```

2. Capture traffic:
```bash
sudo tcpdump -i lo port 8000 -w my-app-capture.pcap
```

3. Generate traffic:
```bash
curl http://localhost:8000
```

4. Analyze:
   - ดู HTTP request/response
   - นับจำนวน packets
   - ดู packet sizes

### Task 3: Security Incident Investigation

**Scenario:** คุณสงสัยว่ามี malware บน system

1. Capture all outbound connections:
```bash
sudo tcpdump -i any 'tcp and dst port 80 or dst port 443' -w suspicious-traffic.pcap
```

2. Generate normal traffic:
```bash
curl http://example.com
curl https://www.google.com
```

3. Analyze:
   - ดู destination IPs
   - ดู destination ports
   - มี connections ที่น่าสงสัยหรือไม่?

---

## ✅ Lab 3 Verification Checklist

- [ ] Capture packets ด้วย tcpdump ได้
- [ ] Filter packets ตาม host, port, protocol
- [ ] เห็นความแตกต่างระหว่าง HTTP และ HTTPS
- [ ] บันทึกและอ่าน .pcap files
- [ ] วิเคราะห์ packet contents
- [ ] เข้าใจ security implications ของ unencrypted traffic

---

# 🌐 Lab 4: Web Server + Firewall Protection

**Duration:** 45 minutes  
**Difficulty:** ⭐⭐⭐ Medium

## Objectives
- ติดตั้งและ configure Nginx web server
- ใช้ firewall ป้องกัน web server
- Test different firewall rules
- Implement security best practices

---

## Part 4.1: Install and Configure Nginx

### Step 1: Install Nginx

```bash
# Install Nginx
sudo apt update
sudo apt install -y nginx

# Check status
sudo systemctl status nginx

# Should show: active (running)
```

### Step 2: Verify Nginx is Running

```bash
# Test locally
curl http://localhost

# Output: HTML from Nginx default page

# Check which port Nginx is using
sudo ss -tlnp | grep nginx
```

### Step 3: Create Custom Web Page

```bash
# Create custom HTML
sudo nano /var/www/html/index.html
```

**Content:**
```html
<!DOCTYPE html>
<html>
<head>
    <title>Lab 4 - My Secure Web Server</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 800px;
            margin: 50px auto;
            padding: 20px;
            background: #f0f0f0;
        }
        .container {
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        h1 { color: #2c3e50; }
        .status { 
            padding: 10px;
            background: #d5e8d4;
            border-left: 4px solid #82b366;
            margin: 20px 0;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ Lab 4: Protected Web Server</h1>
        <div class="status">
            <strong>Status:</strong> Server is running!<br>
            <strong>Security:</strong> Protected by UFW Firewall<br>
            <strong>Time:</strong> <script>document.write(new Date());</script>
        </div>
        <p>This is a demonstration of a web server protected by firewall rules.</p>
        <h2>Server Information:</h2>
        <ul>
            <li><strong>Web Server:</strong> Nginx</li>
            <li><strong>Port:</strong> 80 (HTTP)</li>
            <li><strong>Firewall:</strong> UFW</li>
            <li><strong>OS:</strong> Ubuntu</li>
        </ul>
    </div>
</body>
</html>
```

Save and exit (Ctrl+X, Y, Enter)

### Step 4: Test Custom Page

```bash
# Test
curl http://localhost

# Open in browser (ถ้าอยู่บน VM ที่มี GUI)
firefox http://localhost
```

---

## Part 4.2: Basic Firewall Protection

### Step 5: Configure UFW for Web Server

```bash
# Check current UFW status
sudo ufw status

# ถ้ายัง inactive
sudo ufw enable

# Allow HTTP
sudo ufw allow 80/tcp

# Allow HTTPS (สำหรับอนาคต)
sudo ufw allow 443/tcp

# Allow SSH (important!)
sudo ufw allow 22/tcp

# Check rules
sudo ufw status numbered
```

### Step 6: Test Access

```bash
# Test from localhost
curl http://localhost

# Test from another terminal
wget http://localhost -O -

# Should work!
```

### Step 7: Deny and Test

```bash
# Deny HTTP
sudo ufw deny 80/tcp

# Test again
curl http://localhost --max-time 5
# Should timeout!

# Re-allow
sudo ufw delete deny 80/tcp
sudo ufw allow 80/tcp
```

---

## Part 4.3: Advanced Protection Rules

### Step 8: Rate Limiting (Prevent DDoS)

```bash
# Limit connections from single IP
sudo ufw limit 80/tcp

# This allows max 6 connections per 30 seconds from same IP
```

**Test:**
```bash
# Generate multiple requests quickly
for i in {1..10}; do curl http://localhost & done

# After 6 requests, UFW will start blocking
```

### Step 9: IP Whitelist

```bash
# Scenario: Only allow web access from office network

# Deny all HTTP first
sudo ufw deny 80/tcp

# Allow from office subnet only
sudo ufw allow from 192.168.1.0/24 to any port 80

# Now only IPs in 192.168.1.0/24 can access
```

### Step 10: IP Blacklist

```bash
# Block suspicious IP
sudo ufw deny from 203.0.113.100

# Block entire subnet
sudo ufw deny from 203.0.113.0/24

# View blocked IPs
sudo ufw status numbered | grep DENY
```

---

## Part 4.4: Creating Virtual Hosts

### Step 11: Setup Multiple Sites

```bash
# สร้าง directory สำหรับ site 2
sudo mkdir -p /var/www/admin

# สร้าง admin page
sudo nano /var/www/admin/index.html
```

**Content:**
```html
<!DOCTYPE html>
<html>
<head>
    <title>Admin Panel - RESTRICTED</title>
    <style>
        body {
            background: #2c3e50;
            color: white;
            font-family: monospace;
            padding: 50px;
        }
        .warning {
            background: #e74c3c;
            padding: 20px;
            border-radius: 5px;
        }
    </style>
</head>
<body>
    <div class="warning">
        <h1>⚠️ RESTRICTED AREA</h1>
        <p>This is an admin panel. Access is restricted.</p>
        <p><strong>Only authorized personnel allowed.</strong></p>
    </div>
</body>
</html>
```

### Step 12: Configure Nginx Virtual Host

```bash
# สร้าง config file
sudo nano /etc/nginx/sites-available/admin
```

**Content:**
```nginx
server {
    listen 8080;
    server_name localhost;
    
    root /var/www/admin;
    index index.html;
    
    location / {
        try_files $uri $uri/ =404;
    }
}
```

```bash
# Enable site
sudo ln -s /etc/nginx/sites-available/admin /etc/nginx/sites-enabled/

# Test config
sudo nginx -t

# Reload Nginx
sudo systemctl reload nginx
```

### Step 13: Protect Admin Panel with Firewall

```bash
# Allow port 8080 only from localhost
sudo ufw deny 8080

sudo ufw allow from 127.0.0.1 to any port 8080

# Test
curl http://localhost:8080  # Works!

# จาก external (จะไม่ได้ถ้าไม่ใช่ localhost)
```

---

## Part 4.5: Monitoring and Logging

### Step 14: Monitor Nginx Logs

**Terminal 1 - Watch Access Log:**
```bash
# Monitor access log in real-time
sudo tail -f /var/log/nginx/access.log
```

**Terminal 2 - Generate Traffic:**
```bash
# Make requests
for i in {1..10}; do
    curl http://localhost
    sleep 1
done
```

**Observe:** แต่ละ request จะปรากฏใน access log

### Step 15: Monitor Error Log

```bash
# Watch error log
sudo tail -f /var/log/nginx/error.log

# Simulate error (access non-existent page)
curl http://localhost/nonexistent-page
```

### Step 16: Monitor UFW Log

```bash
# Watch UFW log
sudo tail -f /var/log/ufw.log

# หรือ filter blocked attempts
sudo grep "BLOCK" /var/log/ufw.log | tail -20
```

---

## Part 4.6: Security Testing

### Step 17: Test from Different IPs (Simulation)

```bash
# Simulate request from different IP
# (This is simulation, actual IP won't change)

# Add rule to allow specific IP
sudo ufw allow from 192.168.1.100 to any port 80

# Add rule to deny specific IP
sudo ufw deny from 192.168.1.200 to any port 80

# Test
sudo ufw status numbered
```

### Step 18: Port Scan Defense

**Terminal 1 - Monitor:**
```bash
# Monitor blocked scans
sudo tail -f /var/log/ufw.log | grep "DPT=80"
```

**Terminal 2 - Scan:**
```bash
# Scan yourself
nmap -p 1-100 localhost

# Observe UFW logs
```

### Step 19: Stress Test with Rate Limiting

```bash
# Enable rate limiting
sudo ufw limit 80/tcp

# Stress test
for i in {1..50}; do
    curl http://localhost &
done

# After ~6 requests, remaining will be blocked
```

---

## 📝 Lab 4 Assignment

### Task 1: Complete Web Server Setup

สร้าง web server ที่มี:

1. **Main Site** (port 80):
   - Public access
   - Rate limiting enabled
   - Custom index.html

2. **Admin Panel** (port 8080):
   - Restricted to localhost only
   - Different content

3. **API Service** (port 3000):
   - Allowed from specific subnet only (192.168.1.0/24)

### Task 2: Firewall Configuration

สร้าง firewall rules ที่:
- Allow HTTP (80) และ HTTPS (443) with rate limiting
- Allow SSH (22) from office network only
- Deny all other incoming traffic
- Allow all outgoing traffic
- Block known malicious IPs

บันทึก configuration:
```bash
sudo ufw status numbered > firewall-config.txt
```

### Task 3: Security Monitoring

Setup monitoring script:

```bash
# Create monitoring script
nano ~/monitor.sh
```

**Content:**
```bash
#!/bin/bash

echo "=== Web Server Security Monitor ==="
echo "Date: $(date)"
echo ""

echo "1. Active Connections:"
sudo ss -tn | grep :80

echo ""
echo "2. Recent Access Attempts:"
sudo tail -5 /var/log/nginx/access.log

echo ""
echo "3. Blocked by Firewall:"
sudo tail -5 /var/log/ufw.log | grep BLOCK

echo ""
echo "4. Nginx Status:"
sudo systemctl status nginx | grep Active

echo ""
echo "5. Firewall Status:"
sudo ufw status | head -10
```

```bash
# Make executable
chmod +x ~/monitor.sh

# Run
./monitor.sh
```

### Task 4: Documentation

สร้างเอกสารที่ประกอบด้วย:

1. **Network Diagram:**
   - แสดง topology ของ web server
   - แสดง firewall rules
   - แสดง allowed/denied connections

2. **Security Report:**
   - Firewall rules ที่ใช้
   - อธิบายเหตุผลของแต่ละ rule
   - Testing results

3. **Screenshots:**
   - UFW status
   - Nginx running
   - Access logs
   - Blocked attempts

---

## ✅ Lab 4 Verification Checklist

- [ ] Nginx installed และทำงาน
- [ ] Custom web page สร้างเสร็จ
- [ ] UFW rules configured ถูกต้อง
- [ ] Rate limiting ทำงาน
- [ ] Admin panel restricted อย่างเหมาะสม
- [ ] Monitoring setup เสร็จ
- [ ] ทดสอบทุก scenario สำเร็จ
- [ ] Documentation ครบถ้วน

---

# 📊 Final Lab Report Template

## รูปแบบรายงาน (ส่งเป็น PDF)

### Cover Page
- ชื่อ-นามสกุล
- รหัสนักศึกษา
- รายวิชา ENGSE214
- Week 5 Labs Report
- วันที่ทำ Lab

### Lab 1: Basic Firewall
- UFW configuration (status numbered)
- Screenshot of rules
- Testing results
- Challenges faced

### Lab 2: Network Monitoring
- Network baseline
- Open ports list
- Nmap scan results
- Service identification

### Lab 3: Packet Capture
- HTTP vs HTTPS comparison
- Sample packet captures
- Security insights
- Tools learned

### Lab 4: Web Server Protection
- Server configuration
- Firewall rules explanation
- Security testing results
- Monitoring setup

### Conclusion
- สิ่งที่ได้เรียนรู้
- ความสำคัญของ Network Security
- การนำไปใช้จริง

---

# 🎯 Grading Rubric

| หัวข้อ | คะแนน | รายละเอียด |
|--------|-------|-----------|
| **Lab 1 Completion** | 20 | UFW configuration ถูกต้อง, testing สำเร็จ |
| **Lab 2 Completion** | 20 | Network monitoring, port scanning |
| **Lab 3 Completion** | 20 | Packet capture, HTTP vs HTTPS |
| **Lab 4 Completion** | 20 | Web server + firewall protection |
| **Documentation** | 10 | รายงานครบถ้วน ชัดเจน |
| **Screenshots** | 10 | Quality และความครบถ้วน |
| **รวม** | **100** | |

---

# 💡 Tips & Best Practices

## Do's ✅
- อ่าน instructions ทั้งหมดก่อนเริ่มทำ
- บันทึก commands ที่ใช้ไว้
- Capture screenshots ทุก step สำคัญ
- Test thoroughly ก่อนบันทึกผล
- สำรอง configuration files

## Don'ts ❌
- อย่า `sudo ufw reset` ถ้าไม่แน่ใจ
- อย่า block SSH ถ้าเชื่อมต่อผ่าน SSH
- อย่า capture passwords ใน screenshots
- อย่าทำ port scan ใน production servers
- อย่าแชร์ firewall rules ที่มี internal IPs

---

# 🆘 Troubleshooting Guide

## ปัญหา: UFW ไม่ทำงาน
**Solution:**
```bash
sudo systemctl status ufw
sudo systemctl start ufw
sudo systemctl enable ufw
```

## ปัญหา: Nginx ไม่ start
**Solution:**
```bash
# Check logs
sudo journalctl -u nginx

# Check config
sudo nginx -t

# Check port conflict
sudo ss -tlnp | grep :80
```

## ปัญหา: tcpdump permission denied
**Solution:**
```bash
# ต้องใช้ sudo
sudo tcpdump -i any

# หรือ add user to group
sudo usermod -a -G wireshark $USER
```

## ปัญหา: nmap ช้ามาก
**Solution:**
```bash
# ใช้ faster scan
nmap -F localhost  # Fast scan (100 common ports)
nmap -T4 localhost  # Aggressive timing
```

---

# 📚 Additional Resources

## Commands Reference
```bash
# UFW
sudo ufw status
sudo ufw enable/disable
sudo ufw allow/deny <port>
sudo ufw delete <rule>

# Networking
netstat -tuln
ss -tuln
ip addr show
ip route show

# Monitoring
nmap <target>
tcpdump -i <interface>
lsof -i :<port>

# Web Server
sudo systemctl status nginx
sudo nginx -t
sudo tail -f /var/log/nginx/access.log
```

## Online Tools
- https://nmap.org/book/man.html
- https://www.tcpdump.org/manpages/tcpdump.1.html
- https://www.netfilter.org/documentation/

---

# ✅ Final Checklist

เมื่อทำ Labs เสร็จทั้งหมด ตรวจสอบว่า:

- [ ] Lab 1 เสร็จสมบูรณ์
- [ ] Lab 2 เสร็จสมบูรณ์
- [ ] Lab 3 เสร็จสมบูรณ์
- [ ] Lab 4 เสร็จสมบูรณ์
- [ ] ทุก assignment ทำเสร็จ
- [ ] Screenshots ครบถ้วน
- [ ] รายงานเขียนเสร็จ
- [ ] Review คำตอบทั้งหมด
- [ ] Cleanup VM (optional)
- [ ] Submit ภายในเวลาที่กำหนด

---

**สร้างโดย:** คณะวิศวกรรมศาสตร์ ภาควิชาวิศวกรรมซอฟต์แวร์  
**รายวิชา:** ENGSE214 - Introduction to Cyber Security  
**Version:** 1.0  
**วันที่:** January 2025

---

# 🎉 Good Luck!

ขอให้ทุกคนเรียนรู้และเข้าใจเรื่อง Network Security อย่างลึกซึ้ง  
อย่าลืมว่า Security เป็นทั้ง **Technical Skills** และ **Mindset** 🛡️

**Remember:** *"Security is not a product, but a process"* - Bruce Schneier
