# 🔍 Splunk SPL — Blue Team CTF Cheat Sheet

## Essential Search Syntax
```spl
index=* earliest=-24h latest=now        | Quick time-boxed search
index=main sourcetype=syslog            | Filter by index + sourcetype
index=* | stats count by src_ip         | Top talkers
index=* | table _time, host, source, _raw | Flat view
index=* | head 100                      | First 100 events
index=* | dedup src_ip                  | Unique values
```

---

## 🚨 Incident Response Queries

### Failed Logins / Brute Force
```spl
index=* (EventCode=4625 OR "Failed password" OR "authentication failure")
| stats count as failures by src_ip, user
| where failures > 10
| sort - failures
```

### Successful Login After Multiple Failures
```spl
index=* EventCode=4625
| stats count as fail_count by src_ip, user
| where fail_count > 5
| join user [search index=* EventCode=4624 | table user, src_ip]
```

### New Admin / Privileged Account Created
```spl
index=* (EventCode=4720 OR EventCode=4732 OR "useradd" OR "usermod -aG sudo")
| table _time, host, user, message
```

### Lateral Movement (Pass-the-Hash / RDP)
```spl
index=* EventCode=4624 Logon_Type=3
| stats count by src_ip, dest_host, user
| sort - count
```

### Mimikatz / Credential Dumping
```spl
index=* (EventCode=10 OR "lsass" OR "sekurlsa" OR "credential" OR "dump")
| table _time, host, process, parent_process, CommandLine
```

---

## 📡 Network / Traffic Analysis

### Top Communicating IPs
```spl
index=* | stats count by src_ip, dest_ip | sort - count | head 20
```

### DNS Exfiltration (Long subdomain queries)
```spl
index=* sourcetype=dns
| eval subdomain_len = len(query)
| where subdomain_len > 50
| table _time, src_ip, query, subdomain_len
```

### Beaconing (Regular intervals)
```spl
index=* src_ip=*
| timechart span=1m count by src_ip
| eval stddev = mvstats(count)
```

### Port Scan Detection
```spl
index=* action=blocked OR action=denied
| stats dc(dest_port) as unique_ports by src_ip
| where unique_ports > 20
| sort - unique_ports
```

### C2 Beacon Detection
```spl
index=* dest_port IN (443,80,4444,8080,1337)
| bucket _time span=5m
| stats count by _time, src_ip, dest_ip
| eventstats avg(count) as avg_count, stdev(count) as std by src_ip, dest_ip
| where count > avg_count + 2*std
```

---

## 🖥️ Process / Endpoint Analysis

### Suspicious PowerShell
```spl
index=* (process="powershell*" OR CommandLine="*powershell*")
  (CommandLine="*-enc*" OR CommandLine="*IEX*" OR CommandLine="*DownloadString*"
   OR CommandLine="*bypass*" OR CommandLine="*hidden*")
| table _time, host, user, CommandLine
```

### Living-off-the-Land Binaries (LOLBins)
```spl
index=* process_name IN (
  "certutil.exe","mshta.exe","wscript.exe","cscript.exe",
  "regsvr32.exe","rundll32.exe","msiexec.exe","bitsadmin.exe",
  "wmic.exe","net.exe","net1.exe","nltest.exe"
)
| table _time, host, user, process_name, CommandLine
```

### New Scheduled Task / Cron
```spl
index=* (EventCode=4698 OR "crontab" OR "systemctl enable")
| table _time, host, user, TaskName, CommandLine
```

### Persistence via Registry Run Keys
```spl
index=* EventCode=13
  (TargetObject="*\\CurrentVersion\\Run*" OR TargetObject="*\\CurrentVersion\\RunOnce*")
| table _time, host, user, TargetObject, Details
```

---

## 📁 File System Events

### New Executables Dropped
```spl
index=* EventCode=11
  (TargetFilename="*.exe" OR TargetFilename="*.dll" OR
   TargetFilename="*.ps1" OR TargetFilename="*.bat" OR
   TargetFilename="*.vbs" OR TargetFilename="*.js")
| table _time, host, Image, TargetFilename
```

### Large File Transfers / Exfiltration
```spl
index=* bytes_out > 100000000
| stats sum(bytes_out) as total_out by src_ip, dest_ip
| eval total_MB = round(total_out / 1024 / 1024, 2)
| sort - total_MB
```

---

## 🌐 Web / Application Logs

### SQL Injection Attempts
```spl
index=* (uri_path="*union+select*" OR uri_path="*' OR 1=1*"
         OR uri_path="*;DROP TABLE*" OR uri_path="*xp_cmdshell*")
| table _time, src_ip, uri_path, status
```

### Web Shell Access
```spl
index=* (uri_path="*.php" OR uri_path="*.aspx")
  (uri_query="*cmd=*" OR uri_query="*exec=*" OR uri_query="*shell=*")
| table _time, src_ip, uri_path, uri_query, status
```

### Scanning (404 Storm)
```spl
index=* status=404
| stats count by src_ip, uri_path
| where count > 50
| sort - count
```

---

## 🏆 CTF-Specific Patterns

### Flag Pattern Hunt
```spl
index=* ("ctf{" OR "flag{" OR "HTB{" OR "CTF{")
| table _time, host, source, _raw
```

### Hidden in Base64 (Splunk decode)
```spl
index=* CommandLine="*"
| eval decoded = base64decode(CommandLine)
| search decoded="*flag*" OR decoded="*ctf*"
| table _time, host, CommandLine, decoded
```

### Unusual Outbound Ports
```spl
index=* direction=outbound dest_port NOT IN (80, 443, 22, 53, 25, 587)
| stats count by dest_port, dest_ip
| sort - count
```

### User Account Investigation
```spl
index=* user="<TARGET_USER>"
| transaction user maxspan=1h
| table _time, host, source, user, _raw
```

---

## ⚙️ Useful SPL Functions

| Function | Purpose |
|---|---|
| `stats count by field` | Aggregate count grouped by field |
| `eval x=coalesce(a,b,c)` | First non-null value |
| `rex field=_raw "(?P<name>pattern)"` | Inline regex extraction |
| `transaction field maxspan=Xm` | Group related events |
| `iplocation src_ip` | GeoIP lookup |
| `lookup threat_intel src_ip OUTPUT threat_category` | Threat intel enrichment |
| `timechart span=1h count by src_ip` | Time-series chart |
| `streamstats count as seq by session_id` | Session sequencing |
| `mvexpand field` | Expand multi-value fields |
| `inputlookup` / `outputlookup` | Load/save lookup tables |
