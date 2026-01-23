# Week 5 Labs - Quick Reference Card

**Print this page and keep it handy during labs!** 📋

---

## 🔥 UFW (Firewall) Commands

### Basic Operations
```bash
sudo ufw status              # ดูสถานะ
sudo ufw status verbose      # ดูสถานะแบบละเอียด
sudo ufw status numbered     # ดูสถานะพร้อมหมายเลข rule
sudo ufw enable              # เปิด UFW
sudo ufw disable             # ปิด UFW
sudo ufw reset               # รีเซ็ตเป็นค่าเริ่มต้น
```

### Allow/Deny Rules
```bash
sudo ufw allow 22            # อนุญาต port 22
sudo ufw allow ssh           # อนุญาต SSH (port 22)
sudo ufw allow 80/tcp        # อนุญาต HTTP (TCP only)
sudo ufw allow http          # อนุญาต HTTP
sudo ufw allow https         # อนุญาต HTTPS
sudo ufw deny 23             # ปฏิเสธ port 23
sudo ufw deny telnet         # ปฏิเสธ Telnet
```

### Advanced Rules
```bash
sudo ufw allow from 192.168.1.100                    # อนุญาตจาก IP
sudo ufw allow from 192.168.1.0/24                   # อนุญาตจาก subnet
sudo ufw allow from 192.168.1.100 to any port 22     # IP เฉพาะไป port เฉพาะ
sudo ufw deny from 203.0.113.50                      # block IP
sudo ufw limit 22/tcp                                # rate limit (max 6/30 sec)
```

### Delete Rules
```bash
sudo ufw delete allow 80              # ลบ rule โดยระบุ
sudo ufw delete 3                     # ลบ rule ที่ 3
sudo ufw delete deny from 203.0.113.50  # ลบ rule โดยระบุเต็ม
```

### Logging
```bash
sudo ufw logging on           # เปิด logging
sudo ufw logging off          # ปิด logging
sudo ufw logging low          # logging level: low
sudo ufw logging medium       # logging level: medium
sudo ufw logging high         # logging level: high
tail -f /var/log/ufw.log      # ดู logs real-time
```

---

## 🔍 Network Monitoring Commands

### netstat (Classic)
```bash
netstat -tuln                 # ดู listening ports
netstat -tulnp                # พร้อม process names (ต้อง sudo)
netstat -tan                  # TCP connections ทั้งหมด
netstat -i                    # network interfaces
netstat -r                    # routing table
```

### ss (Modern)
```bash
ss -tuln                      # ดู listening ports
ss -tulnp                     # พร้อม process names (ต้อง sudo)
ss -tn state established      # established connections
ss -tn dst 8.8.8.8            # connections to specific IP
ss -tlnp | grep :80           # filter by port
```

### lsof (List Open Files)
```bash
sudo lsof -i                  # network connections ทั้งหมด
sudo lsof -i :80              # ดู process ใช้ port 80
sudo lsof -i :22              # ดู process ใช้ port 22
sudo lsof -i tcp              # TCP connections
sudo lsof -u username         # connections by user
```

### Other Useful Commands
```bash
ip addr show                  # ดู IP addresses
ip route show                 # ดู routing table
ifconfig                      # network interfaces (old)
hostname -I                   # ดู IP address
ping 8.8.8.8                  # test connectivity
```

---

## 🎯 Nmap (Port Scanning)

### Basic Scans
```bash
nmap localhost                # scan localhost
nmap 127.0.0.1                # same as above
nmap 192.168.1.1              # scan specific IP
nmap 192.168.1.0/24           # scan subnet
```

### Port Scanning
```bash
nmap -p 22 localhost          # scan single port
nmap -p 22,80,443 localhost   # scan specific ports
nmap -p 1-1000 localhost      # scan port range
nmap -p- localhost            # scan ALL ports (slow!)
nmap -F localhost             # fast scan (100 common ports)
```

### Advanced Scans
```bash
sudo nmap -sV localhost       # detect service versions
sudo nmap -O localhost        # detect OS
sudo nmap -A localhost        # aggressive (OS + version + scripts)
sudo nmap -sS localhost       # SYN scan (stealth)
nmap -T4 localhost            # faster timing
```

### Output Options
```bash
nmap localhost -oN scan.txt   # save output to text file
nmap localhost -oX scan.xml   # save output to XML
nmap localhost -v             # verbose output
```

---

## 📡 tcpdump (Packet Capture)

### Basic Capture
```bash
sudo tcpdump                  # capture all packets
sudo tcpdump -i eth0          # capture on eth0
sudo tcpdump -i any           # capture on all interfaces
sudo tcpdump -c 10            # capture 10 packets only
```

### Filtering
```bash
# By Host
sudo tcpdump host 8.8.8.8                    # traffic to/from 8.8.8.8
sudo tcpdump src host 192.168.1.100          # from this IP
sudo tcpdump dst host 8.8.8.8                # to this IP

# By Port
sudo tcpdump port 80                         # HTTP traffic
sudo tcpdump port 443                        # HTTPS traffic
sudo tcpdump port 22                         # SSH traffic
sudo tcpdump port 80 or port 443             # HTTP or HTTPS

# By Protocol
sudo tcpdump tcp                             # TCP only
sudo tcpdump udp                             # UDP only
sudo tcpdump icmp                            # ICMP (ping) only
sudo tcpdump tcp port 80                     # TCP on port 80
```

### Display Options
```bash
sudo tcpdump -A                # show ASCII text
sudo tcpdump -X                # show hex and ASCII
sudo tcpdump -XX               # show hex and ASCII with link level
sudo tcpdump -n                # don't resolve hostnames
sudo tcpdump -nn               # don't resolve hostnames or ports
sudo tcpdump -v                # verbose
sudo tcpdump -vv               # more verbose
sudo tcpdump -q                # quiet (less info)
```

### Save and Read
```bash
sudo tcpdump -w capture.pcap              # save to file
sudo tcpdump -w capture.pcap -c 100       # save 100 packets
tcpdump -r capture.pcap                   # read from file
tcpdump -r capture.pcap port 80           # read and filter
```

### Complex Filters
```bash
# Combinations
sudo tcpdump 'tcp port 80 and host 8.8.8.8'
sudo tcpdump 'tcp port 80 or tcp port 443'
sudo tcpdump 'not port 22'
sudo tcpdump 'net 192.168.1.0/24'

# SYN packets (connection attempts)
sudo tcpdump 'tcp[tcpflags] & tcp-syn != 0'

# HTTP GET requests
sudo tcpdump -A 'tcp port 80 and tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x47455420'
```

---

## 🌐 Nginx Commands

### Service Control
```bash
sudo systemctl start nginx       # เริ่ม Nginx
sudo systemctl stop nginx        # หยุด Nginx
sudo systemctl restart nginx     # รีสตาร์ท Nginx
sudo systemctl reload nginx      # reload config (ไม่หยุด)
sudo systemctl status nginx      # ดูสถานะ
sudo systemctl enable nginx      # auto-start on boot
```

### Configuration
```bash
sudo nginx -t                    # test config
sudo nginx -T                    # test และแสดง config
nginx -v                         # show version
nginx -V                         # show version + compile options
```

### Logs
```bash
sudo tail -f /var/log/nginx/access.log      # access log (real-time)
sudo tail -f /var/log/nginx/error.log       # error log (real-time)
sudo tail -n 50 /var/log/nginx/access.log   # last 50 lines
sudo cat /var/log/nginx/access.log | grep "404"  # filter 404s
```

### File Locations
```
Config:         /etc/nginx/nginx.conf
Sites:          /etc/nginx/sites-available/
Enabled:        /etc/nginx/sites-enabled/
Web Root:       /var/www/html/
Logs:           /var/log/nginx/
```

---

## 🔧 System Commands

### Process Management
```bash
ps aux                        # list all processes
ps aux | grep nginx           # find nginx processes
top                           # interactive process viewer
htop                          # better process viewer (ติดตั้งก่อน)
kill <PID>                    # kill process
killall nginx                 # kill all nginx processes
```

### Service Management (systemd)
```bash
sudo systemctl start <service>       # start service
sudo systemctl stop <service>        # stop service
sudo systemctl restart <service>     # restart service
sudo systemctl status <service>      # check status
sudo systemctl enable <service>      # auto-start on boot
sudo systemctl disable <service>     # disable auto-start
```

### File Operations
```bash
ls -la                        # list files (detailed)
cd /path/to/directory         # change directory
pwd                           # show current directory
cat file.txt                  # show file contents
nano file.txt                 # edit file (easy)
vim file.txt                  # edit file (advanced)
chmod +x script.sh            # make file executable
sudo chown user:group file    # change ownership
```

### Search and Filter
```bash
grep "text" file.txt          # search in file
grep -r "text" /path/         # search in directory
tail -f file.log              # follow log file
head -n 10 file.txt           # first 10 lines
tail -n 10 file.txt           # last 10 lines
wc -l file.txt                # count lines
```

---

## 📊 Quick Troubleshooting

### "Permission Denied"
```bash
# Solution: Use sudo
sudo <command>
```

### "Port Already in Use"
```bash
# Find process using port
sudo lsof -i :80
sudo ss -tlnp | grep :80

# Kill process
sudo kill <PID>
```

### "Cannot Connect"
```bash
# Check if service is running
sudo systemctl status <service>

# Check if port is open
sudo ss -tlnp | grep :<port>

# Check firewall
sudo ufw status
```

### "Command Not Found"
```bash
# Install missing tool
sudo apt install <package>

# Common packages:
sudo apt install net-tools     # netstat
sudo apt install nmap          # nmap
sudo apt install tcpdump       # tcpdump
sudo apt install nginx         # nginx
```

---

## 🎯 Common Port Numbers

| Port | Service | Protocol |
|------|---------|----------|
| 20 | FTP Data | TCP |
| 21 | FTP Control | TCP |
| 22 | SSH | TCP |
| 23 | Telnet | TCP |
| 25 | SMTP | TCP |
| 53 | DNS | TCP/UDP |
| 80 | HTTP | TCP |
| 110 | POP3 | TCP |
| 143 | IMAP | TCP |
| 443 | HTTPS | TCP |
| 445 | SMB | TCP |
| 587 | SMTP (TLS) | TCP |
| 993 | IMAP (SSL) | TCP |
| 995 | POP3 (SSL) | TCP |
| 3306 | MySQL | TCP |
| 3389 | RDP | TCP |
| 5432 | PostgreSQL | TCP |
| 8080 | HTTP Alt | TCP |
| 8443 | HTTPS Alt | TCP |

---

## 📝 Lab Shortcuts

### Start Web Server
```bash
# Python HTTP Server (quick test)
python3 -m http.server 8000

# With specific directory
cd /path/to/files
python3 -m http.server 8080
```

### Quick Network Test
```bash
# Test connectivity
ping -c 4 8.8.8.8

# Test DNS
nslookup google.com

# Test HTTP
curl http://localhost

# Test HTTPS
curl https://example.com
```

### Generate Traffic for Testing
```bash
# Multiple requests
for i in {1..10}; do curl http://localhost; done

# With delay
for i in {1..10}; do curl http://localhost; sleep 1; done

# Background requests
for i in {1..10}; do curl http://localhost & done
```

### Monitor Everything
```bash
# One-liner dashboard
watch -n 1 'echo "=== Connections ===" && sudo ss -tuln && echo -e "\n=== Firewall ===" && sudo ufw status | head -10'
```

---

## ⚠️ Safety Reminders

1. **Always backup before reset**
   ```bash
   sudo ufw status numbered > backup.txt
   ```

2. **Don't lock yourself out**
   ```bash
   # Always allow SSH first!
   sudo ufw allow 22
   ```

3. **Test before deploy**
   ```bash
   # Test Nginx config
   sudo nginx -t
   ```

4. **Monitor logs**
   ```bash
   # Always check logs after changes
   sudo tail /var/log/ufw.log
   ```

---

## 🆘 Emergency Commands

```bash
# If firewall locks you out
sudo ufw disable

# If Nginx won't start
sudo nginx -t
sudo systemctl status nginx
sudo journalctl -u nginx

# If port conflict
sudo lsof -i :<port>
sudo kill <PID>

# Reset everything
sudo ufw reset
sudo systemctl restart nginx
```

---

**พิมพ์หน้านี้ติดไว้ข้างตัวเวลาทำ Lab!** 📋  
**Keep this card handy during labs!**

---

*Version 1.0 - January 2025*  
*ENGSE214 - Introduction to Cyber Security*
