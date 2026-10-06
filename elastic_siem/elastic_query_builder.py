#!/usr/bin/env python3
"""
elastic_query_builder.py — Interactive KQL / Elastic REST query generator for Blue Team CTF.

Produces KQL (for Kibana Discover / SIEM) and REST API query bodies (for curl / Dev Tools).

Usage:
    python3 elastic_query_builder.py list
    python3 elastic_query_builder.py build brute_force --threshold 10
    python3 elastic_query_builder.py build flag_hunt --prefix "ctf{"
    python3 elastic_query_builder.py build c2_beacon --dest-ip 1.2.3.4
    python3 elastic_query_builder.py build user_investigation --user jdoe
    python3 elastic_query_builder.py build brute_force --output curl --index winlogbeat-*
"""

import argparse
import json
import sys
import textwrap

TEMPLATES = {}


def template(name, description):
    def decorator(fn):
        TEMPLATES[name] = {"fn": fn, "desc": description}
        return fn
    return decorator


# ---------------------------------------------------------------------------
# Templates — each returns (kql_string, optional_rest_body_dict)
# ---------------------------------------------------------------------------

@template("brute_force", "Failed logins grouped by source IP / user")
def brute_force(threshold=10, **_):
    kql = textwrap.dedent(f"""\
        event.code: "4625" OR event.action: "logon-failed" OR message: "authentication failure"
    """).strip()
    rest = {
        "size": 0,
        "query": {
            "bool": {
                "should": [
                    {"term": {"event.code": "4625"}},
                    {"term": {"event.action": "logon-failed"}},
                    {"match": {"message": "authentication failure"}}
                ]
            }
        },
        "aggs": {
            "by_src_ip": {
                "terms": {"field": "source.ip", "size": 20},
                "aggs": {
                    "by_user": {
                        "terms": {"field": "user.name", "size": 5},
                        "aggs": {
                            "count": {"value_count": {"field": "_id"}}
                        }
                    }
                }
            }
        }
    }
    return kql, rest


@template("lateral_movement", "Network logons (Logon Type 3 / pass-the-hash)")
def lateral_movement(src_ip=None, **_):
    ip_part = f' AND source.ip: "{src_ip}"' if src_ip else ""
    kql = f'event.code: "4624" AND winlog.event_data.LogonType: "3"{ip_part}'
    rest = {
        "size": 0,
        "query": {"bool": {"must": [
            {"term": {"event.code": "4624"}},
            {"term": {"winlog.event_data.LogonType": "3"}}
        ]}},
        "aggs": {
            "by_src": {
                "terms": {"field": "source.ip", "size": 20},
                "aggs": {
                    "unique_dest": {"cardinality": {"field": "host.name"}}
                }
            }
        }
    }
    return kql, rest


@template("privilege_escalation", "Privilege escalation (Event 4672 / sudo)")
def privilege_escalation(user=None, **_):
    user_part = f' AND user.name: "{user}"' if user else ""
    kql = (
        f'(event.code: ("4672" OR "4673" OR "4674") OR '
        f'winlog.event_data.PrivilegeList: *SeDebugPrivilege*){user_part}'
    )
    rest = {
        "size": 100,
        "query": {"bool": {"should": [
            {"terms": {"event.code": ["4672", "4673", "4674"]}},
            {"wildcard": {"winlog.event_data.PrivilegeList": "*SeDebugPrivilege*"}}
        ]}},
        "_source": ["@timestamp", "host.name", "user.name",
                    "winlog.event_data.PrivilegeList", "process.name"]
    }
    return kql, rest


@template("powershell_abuse", "Obfuscated / encoded PowerShell commands")
def powershell_abuse(host=None, **_):
    host_part = f' AND host.name: "{host}"' if host else ""
    kql = textwrap.dedent(f"""\
        process.name: "powershell.exe"{host_part}
          AND process.command_line: (*-enc* OR *-EncodedCommand* OR *IEX* OR
                                     *Invoke-Expression* OR *DownloadString* OR
                                     *bypass* OR *hidden* OR *-nop*)
    """).strip()
    rest = {
        "size": 50,
        "query": {"bool": {"must": [
            {"term": {"process.name": "powershell.exe"}},
            {"bool": {"should": [
                {"wildcard": {"process.command_line": "*-enc*"}},
                {"wildcard": {"process.command_line": "*IEX*"}},
                {"wildcard": {"process.command_line": "*DownloadString*"}},
                {"wildcard": {"process.command_line": "*bypass*"}}
            ]}}
        ]}},
        "_source": ["@timestamp", "host.name", "user.name", "process.command_line"]
    }
    return kql, rest


@template("lolbins", "Living-off-the-land binary abuse")
def lolbins(**_):
    bins = [
        "certutil.exe", "mshta.exe", "wscript.exe", "cscript.exe",
        "regsvr32.exe", "rundll32.exe", "msiexec.exe", "bitsadmin.exe",
        "wmic.exe", "net.exe", "nltest.exe", "forfiles.exe"
    ]
    kql_list = " OR ".join(f'"{b}"' for b in bins)
    kql = f"process.name: ({kql_list})"
    rest = {
        "size": 50,
        "query": {"terms": {"process.name": bins}},
        "_source": ["@timestamp", "host.name", "user.name",
                    "process.name", "process.command_line"]
    }
    return kql, rest


@template("c2_beacon", "Periodic C2 callback / beaconing detection")
def c2_beacon(dest_ip=None, dest_port=None, **_):
    parts = ["network.direction: egress"]
    if dest_ip:
        parts.append(f'destination.ip: "{dest_ip}"')
    if dest_port:
        parts.append(f"destination.port: {dest_port}")
    else:
        parts.append("destination.port: (4444 OR 1337 OR 9001 OR 6666 OR 8888 OR 31337 OR 443 OR 80)")
    kql = " AND ".join(parts)
    rest = {
        "size": 0,
        "aggs": {
            "by_pair": {
                "composite": {
                    "sources": [
                        {"src": {"terms": {"field": "source.ip"}}},
                        {"dst": {"terms": {"field": "destination.ip"}}},
                        {"port": {"terms": {"field": "destination.port"}}}
                    ],
                    "size": 50
                },
                "aggs": {
                    "count": {"value_count": {"field": "_id"}}
                }
            }
        }
    }
    return kql, rest


@template("dns_exfil", "Long DNS subdomain queries (potential exfiltration)")
def dns_exfil(min_len=50, **_):
    kql = f'dns.question.type: "A" AND dns.question.name: *'
    rest = {
        "size": 50,
        "query": {"exists": {"field": "dns.question.name"}},
        "script_fields": {
            "q_len": {
                "script": {
                    "source": "doc['dns.question.name'].value?.length() ?: 0"
                }
            }
        },
        "sort": [{"_script": {
            "type": "number",
            "script": {"source": "doc['dns.question.name'].value?.length() ?: 0"},
            "order": "desc"
        }}],
        "_source": ["@timestamp", "source.ip", "dns.question.name"]
    }
    return kql, rest


@template("exfil", "Large outbound data (exfiltration)")
def exfil(min_bytes=100_000_000, **_):
    kql = f"network.bytes: >{min_bytes} AND network.direction: egress"
    rest = {
        "size": 0,
        "query": {
            "range": {"network.bytes": {"gt": min_bytes}}
        },
        "aggs": {
            "by_pair": {
                "composite": {
                    "sources": [
                        {"src": {"terms": {"field": "source.ip"}}},
                        {"dst": {"terms": {"field": "destination.ip"}}}
                    ]
                },
                "aggs": {
                    "total_bytes": {"sum": {"field": "network.bytes"}}
                }
            }
        }
    }
    return kql, rest


@template("flag_hunt", "Hunt for CTF flags across all documents")
def flag_hunt(prefix="ctf{", **_):
    # Escape curly braces for KQL
    kql = f'message: "{prefix}" OR message: "flag{{" OR message: "HTB{{" OR message: "CTF{{"'
    rest = {
        "size": 20,
        "query": {"bool": {"should": [
            {"match": {"message": prefix}},
            {"match": {"message": "flag{"}},
            {"match": {"message": "HTB{"}},
            {"match": {"message": "CTF{"}}
        ]}},
        "_source": ["@timestamp", "host.name", "message", "source"],
        "sort": [{"@timestamp": {"order": "desc"}}]
    }
    return kql, rest


@template("webshell", "Web shell access detection")
def webshell(**_):
    kql = (
        'url.path: (*.php OR *.aspx OR *.jsp) '
        'AND url.query: (*cmd=* OR *exec=* OR *shell=* OR *system=*)'
    )
    rest = {
        "size": 50,
        "query": {"bool": {"must": [
            {"bool": {"should": [
                {"wildcard": {"url.path": "*.php"}},
                {"wildcard": {"url.path": "*.aspx"}},
                {"wildcard": {"url.path": "*.jsp"}}
            ]}},
            {"bool": {"should": [
                {"wildcard": {"url.query": "*cmd=*"}},
                {"wildcard": {"url.query": "*exec=*"}},
                {"wildcard": {"url.query": "*shell=*"}}
            ]}}
        ]}},
        "_source": ["@timestamp", "source.ip", "url.path", "url.query",
                    "http.response.status_code"]
    }
    return kql, rest


@template("new_service", "New scheduled task or service installed")
def new_service(**_):
    kql = 'event.code: ("4698" OR "4702" OR "7045") OR process.name: "schtasks.exe"'
    rest = {
        "size": 50,
        "query": {"bool": {"should": [
            {"terms": {"event.code": ["4698", "4702", "7045"]}},
            {"term": {"process.name": "schtasks.exe"}}
        ]}},
        "_source": ["@timestamp", "host.name", "user.name",
                    "winlog.event_data.TaskName", "process.command_line"]
    }
    return kql, rest


@template("user_investigation", "Full activity timeline for a specific user")
def user_investigation(user="TARGET_USER", **_):
    kql = f'user.name: "{user}"'
    rest = {
        "size": 200,
        "query": {"term": {"user.name": user}},
        "_source": ["@timestamp", "host.name", "event.code", "event.action",
                    "process.name", "process.command_line", "message"],
        "sort": [{"@timestamp": {"order": "asc"}}]
    }
    return kql, rest


@template("process_injection", "Process injection (Sysmon Event 10 / lsass access)")
def process_injection(**_):
    kql = 'event.code: "10" AND winlog.event_data.TargetImage: *lsass*'
    rest = {
        "size": 50,
        "query": {"bool": {"must": [
            {"term": {"event.code": "10"}},
            {"wildcard": {"winlog.event_data.TargetImage": "*lsass*"}}
        ]}},
        "_source": ["@timestamp", "host.name", "user.name",
                    "process.name", "winlog.event_data.TargetImage"]
    }
    return kql, rest


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def cmd_list(_args):
    print(f"  {'TEMPLATE':<25} DESCRIPTION")
    print("  " + "-" * 65)
    for name, meta in sorted(TEMPLATES.items()):
        print(f"  {name:<25} {meta['desc']}")


def cmd_build(args):
    name = args.template
    if name not in TEMPLATES:
        print(f"Unknown template: '{name}'. Run `list` to see options.", file=sys.stderr)
        sys.exit(1)

    fn = TEMPLATES[name]["fn"]
    import inspect
    params = inspect.signature(fn).parameters

    kwargs = {}
    mapping = {
        "threshold": args.threshold,
        "src_ip": args.src_ip,
        "dest_ip": args.dest_ip,
        "dest_port": args.dest_port,
        "host": args.host,
        "user": args.user,
        "prefix": args.prefix,
        "min_bytes": args.min_bytes,
        "min_len": args.min_len,
    }
    for param in params:
        if param in mapping and mapping[param] is not None:
            kwargs[param] = mapping[param]

    kql, rest = fn(**kwargs)

    print("\n" + "=" * 64)
    print(f"  Template : {name}")
    print("=" * 64)

    if args.output in ("kql", "both"):
        print("\n--- KQL (paste into Kibana Discover filter bar) ---")
        print(kql)

    if args.output in ("rest", "both"):
        index = args.index or "*"
        print(f"\n--- REST API (curl to Elastic) ---")
        print(f"curl -s -X POST 'http://localhost:9200/{index}/_search?pretty' \\")
        print(f"  -H 'Content-Type: application/json' \\")
        print(f"  -d '{json.dumps(rest)}'")

    if args.output == "curl":
        index = args.index or "*"
        cmd = (
            f"curl -s -X POST 'http://localhost:9200/{index}/_search?pretty' "
            f"-H 'Content-Type: application/json' "
            f"-d '{json.dumps(rest)}'"
        )
        print(cmd)

    print("=" * 64)


def main():
    parser = argparse.ArgumentParser(
        description="KQL/Elastic query builder for Blue Team CTF"
    )
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list", help="List all available templates")

    p = sub.add_parser("build", help="Generate a query")
    p.add_argument("template", help="Template name (see `list`)")
    p.add_argument("--index", default="*", help="Elastic index pattern")
    p.add_argument("--user")
    p.add_argument("--src-ip")
    p.add_argument("--dest-ip")
    p.add_argument("--dest-port", type=int)
    p.add_argument("--host")
    p.add_argument("--threshold", type=int)
    p.add_argument("--min-bytes", type=int)
    p.add_argument("--min-len", type=int)
    p.add_argument("--prefix", default="ctf{")
    p.add_argument("--output", choices=["kql", "rest", "both", "curl"],
                   default="both", help="Output format (default: both)")

    args = parser.parse_args()
    if args.cmd == "list":
        cmd_list(args)
    elif args.cmd == "build":
        cmd_build(args)



@template("roundcube_rce", "Hunt for Roundcube RCE exploitation")
def roundcube_rce(**_):
    kql = 'message: (*Subject:* OR *<?php*) OR url.query: *_task=mail* OR message: (*PHP Parse error* OR *PHP Fatal error*)'
    rest = {
        "size": 50,
        "query": {"bool": {"should": [
            {"wildcard": {"message": "*Subject:*"}},
            {"wildcard": {"message": "*<?php*"}},
            {"wildcard": {"url.query": "*_task=mail*"}},
            {"wildcard": {"message": "*PHP Parse error*"}},
            {"wildcard": {"message": "*PHP Fatal error*"}}
        ]}}
    }
    return kql, rest

@template("suid_abuse", "Linux SUID abuse detection")
def suid_abuse(**_):
    kql = 'process.name: (find OR cp OR vim OR python OR bash) AND auditd.data.a0: *suid*'
    rest = {
        "size": 50,
        "query": {"bool": {"must": [
            {"terms": {"process.name": ["find", "cp", "vim", "python", "bash"]}},
            {"wildcard": {"auditd.data.a0": "*suid*"}}
        ]}}
    }
    return kql, rest

@template("reverse_shell", "Detect reverse shell connections")
def reverse_shell(**_):
    kql = 'process.command_line: (*bash*-i* OR */dev/tcp/* OR *nc*-e*)'
    rest = {
        "size": 50,
        "query": {"bool": {"should": [
            {"wildcard": {"process.command_line": "*bash*-i*"}},
            {"wildcard": {"process.command_line": "*/dev/tcp/*"}},
            {"wildcard": {"process.command_line": "*nc*-e*"}}
        ]}}
    }
    return kql, rest

@template("chisel_tunnel", "Detect Chisel tunneling")
def chisel_tunnel(**_):
    kql = 'process.name: "chisel" OR process.command_line: *server*-p* OR process.command_line: *client*'
    rest = {
        "size": 50,
        "query": {"bool": {"should": [
            {"term": {"process.name": "chisel"}},
            {"wildcard": {"process.command_line": "*server*-p*"}},
            {"wildcard": {"process.command_line": "*client*"}}
        ]}}
    }
    return kql, rest

@template("linpeas_exec", "Detect LinPEAS/reconnaissance tools execution")
def linpeas_exec(**_):
    kql = 'process.name: (utils.sh OR linpeas.sh OR linenum.sh) OR file.name: (linpeas.sh OR linenum.sh)'
    rest = {
        "size": 50,
        "query": {"bool": {"should": [
            {"terms": {"process.name": ["utils.sh", "linpeas.sh", "linenum.sh"]}},
            {"terms": {"file.name": ["linpeas.sh", "linenum.sh"]}}
        ]}}
    }
    return kql, rest

@template("systemd_backdoor", "Detect suspicious systemd unit creation/modification")
def systemd_backdoor(**_):
    kql = 'file.path: (/etc/systemd/system/* OR /lib/systemd/system/*) AND event.action: (created OR modified)'
    rest = {
        "size": 50,
        "query": {"bool": {"must": [
            {"bool": {"should": [
                {"wildcard": {"file.path": "/etc/systemd/system/*"}},
                {"wildcard": {"file.path": "/lib/systemd/system/*"}}
            ]}},
            {"terms": {"event.action": ["created", "modified"]}}
        ]}}
    }
    return kql, rest

@template("cron_persistence", "Detect cron-based persistence")
def cron_persistence(**_):
    kql = 'file.path: (/etc/cron* OR /var/spool/cron/*) AND event.action: (created OR modified)'
    rest = {
        "size": 50,
        "query": {"bool": {"must": [
            {"bool": {"should": [
                {"wildcard": {"file.path": "/etc/cron*"}},
                {"wildcard": {"file.path": "/var/spool/cron/*"}}
            ]}},
            {"terms": {"event.action": ["created", "modified"]}}
        ]}}
    }
    return kql, rest

@template("infostealer_artifacts", "Detect infostealer artifacts")
def infostealer_artifacts(**_):
    kql = 'file.path: (*Recycle.Bin* OR *AppData*Local*Google*Chrome*User Data*) AND file.extension: (exe OR lnk OR db)'
    rest = {
        "size": 50,
        "query": {"bool": {"must": [
            {"bool": {"should": [
                {"wildcard": {"file.path": "*Recycle.Bin*"}},
                {"wildcard": {"file.path": "*AppData*Local*Google*Chrome*User Data*"}}
            ]}},
            {"terms": {"file.extension": ["exe", "lnk", "db"]}}
        ]}}
    }
    return kql, rest

@template("lateral_movement_rdp", "RDP-based lateral movement detection")
def lateral_movement_rdp(**_):
    kql = 'event.code: "4624" AND winlog.event_data.LogonType: "10"'
    rest = {
        "size": 50,
        "query": {"bool": {"must": [
            {"term": {"event.code": "4624"}},
            {"term": {"winlog.event_data.LogonType": "10"}}
        ]}}
    }
    return kql, rest

@template("mythic_c2", "Mythic C2 framework detection patterns")
def mythic_c2(**_):
    kql = 'network.protocol: "http" AND (url.path: */api/v1.4/agent_message* OR http.request.body.content: *mythic*)'
    rest = {
        "size": 50,
        "query": {"bool": {"must": [
            {"term": {"network.protocol": "http"}},
            {"bool": {"should": [
                {"wildcard": {"url.path": "*/api/v1.4/agent_message*"}},
                {"wildcard": {"http.request.body.content": "*mythic*"}}
            ]}}
        ]}}
    }
    return kql, rest

if __name__ == "__main__":
    main()
