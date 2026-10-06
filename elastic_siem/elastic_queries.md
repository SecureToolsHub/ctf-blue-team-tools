# 🔍 Elastic / Kibana — Blue Team CTF Cheat Sheet

## KQL (Kibana Query Language) Basics
```kql
event.code: "4625"                       # Exact field match
host.name: web* AND process.name: cmd*   # Wildcard + AND
NOT source.ip: 10.0.0.*                  # Negation
event.code: ("4624" OR "4625" OR "4648") # OR list
bytes_out > 1000000                       # Numeric range
@timestamp >= "2026-01-01T00:00:00Z"     # Time range
```

## EQL (Event Query Language) — Correlation
```eql
sequence by host.id, user.name
  [process where process.name == "cmd.exe"]
  [network where destination.port in (4444, 1337, 8080)]
```

---

## 🚨 Incident Response Queries

### Failed Logins
```kql
event.code: "4625" OR event.action: "logon-failed"
```

### Brute Force (ES|QL / Lucene aggregation)
```json
GET winlogbeat-*/_search
{
  "aggs": {
    "by_ip": {
      "terms": { "field": "source.ip" },
      "aggs": {
        "fail_count": { "value_count": { "field": "event.code" } }
      }
    }
  },
  "query": { "term": { "event.code": "4625" } }
}
```

### Privilege Escalation Events
```kql
event.code: ("4672" OR "4673" OR "4674" OR "4688")
  AND winlog.event_data.PrivilegeList: *SeDebugPrivilege*
```

### New User Account Created
```kql
event.code: ("4720" OR "useradd")
```

---

## 📡 Network / Traffic

### Top Talkers
```json
GET filebeat-*/_search
{
  "size": 0,
  "aggs": {
    "top_src": { "terms": { "field": "source.ip", "size": 20 } }
  }
}
```

### Beaconing Detection (long-term periodic connections)
```kql
destination.port: (443 OR 80 OR 8080) AND network.direction: egress
```

### DNS Tunneling (long queries)
```kql
dns.question.name: * AND dns.question.type: A
```
*(Add runtime field `dns.question.name.length` for filtering long subdomains)*

### C2 / Reverse Shell Ports
```kql
destination.port: (4444 OR 1337 OR 9001 OR 6666 OR 8888 OR 31337)
```

---

## 🖥️ Process / Endpoint (Sysmon / Elastic Endpoint)

### Suspicious PowerShell
```kql
process.name: "powershell.exe"
  AND process.command_line: (*-enc* OR *IEX* OR *DownloadString* OR *bypass*)
```

### LOLBins
```kql
process.name: (
  "certutil.exe" OR "mshta.exe" OR "wscript.exe" OR "cscript.exe"
  OR "regsvr32.exe" OR "rundll32.exe" OR "msiexec.exe"
  OR "bitsadmin.exe" OR "wmic.exe"
)
```

### Process Injection (Sysmon Event 10)
```kql
event.code: "10" AND winlog.event_data.TargetImage: *lsass.exe*
```

### Scheduled Task Creation
```kql
event.code: ("4698" OR "4702") OR process.name: "schtasks.exe"
```

### Persistence — Registry Run Keys
```kql
event.code: "13"
  AND winlog.event_data.TargetObject: (*\\CurrentVersion\\Run* OR *\\CurrentVersion\\RunOnce*)
```

---

## 📁 File Events (Sysmon Event 11)

### Executables Written to Temp Dirs
```kql
event.code: "11"
  AND file.path: (*\\Temp\\* OR *\\AppData\\Local\\Temp\\*)
  AND file.extension: (exe OR dll OR ps1 OR bat OR vbs)
```

---

## 🌐 Web Log Analysis (Filebeat / Apache / Nginx)

### SQL Injection
```kql
url.path: (*union+select* OR *' OR 1=1* OR *xp_cmdshell*)
```

### Web Shell
```kql
url.path: (*.php OR *.aspx OR *.jsp)
  AND url.query: (*cmd=* OR *exec=* OR *shell=*)
```

### 404 Storm (Scanning)
```kql
http.response.status_code: 404
```

---

## 🏆 CTF-Specific Patterns

### Flag Pattern Hunt (Lucene)
```
_raw: "ctf{" OR _raw: "flag{" OR _raw: "HTB{"
```

### KQL for Flag Hunt
```kql
message: "ctf{" OR message: "flag{" OR message: "HTB{"
```

### Hunt in Process Command Lines
```kql
process.command_line: (*ctf* OR *flag* OR *secret*)
```

### Base64-encoded Commands
```kql
process.command_line: *powershell* AND process.command_line: *-EncodedCommand*
```

---

## 🛠️ Elastic API Quick Reference

```bash
# List all indices
curl -s http://localhost:9200/_cat/indices?v

# Search with Lucene query
curl -s "http://localhost:9200/winlogbeat-*/_search?q=event.code:4625&size=5&pretty"

# Count events by field (aggregation)
curl -s -X POST "http://localhost:9200/winlogbeat-*/_search?pretty" \
  -H "Content-Type: application/json" \
  -d '{"size":0,"aggs":{"by_host":{"terms":{"field":"host.name","size":10}}}}'

# Get index mapping (discover field names)
curl -s "http://localhost:9200/winlogbeat-000001/_mapping?pretty" | python3 -m json.tool | head -100

# Check cluster health
curl -s "http://localhost:9200/_cluster/health?pretty"

# Get recent 10 documents
curl -s "http://localhost:9200/_search?pretty" \
  -H "Content-Type: application/json" \
  -d '{"size":10,"sort":[{"@timestamp":{"order":"desc"}}]}'
```

---

## 📋 ECS Field Reference (Common)

| Field | Description |
|---|---|
| `@timestamp` | Event time |
| `host.name` | Hostname |
| `host.ip` | Host IP |
| `source.ip` | Source IP |
| `destination.ip` / `destination.port` | Dest network |
| `process.name` | Process executable name |
| `process.pid` | Process ID |
| `process.command_line` | Full command line |
| `process.parent.name` | Parent process |
| `user.name` | Account name |
| `event.code` | Windows Event ID or similar |
| `event.action` | Human-readable action |
| `file.path` | Full file path |
| `file.name` | File basename |
| `dns.question.name` | DNS query |
| `http.request.method` | HTTP verb |
| `url.path` | URL path |
| `winlog.event_data.*` | Windows-specific extra fields |
