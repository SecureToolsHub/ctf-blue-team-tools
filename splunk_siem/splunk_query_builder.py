#!/usr/bin/env python3
"""
splunk_query_builder.py — Interactive SPL query generator for Blue Team CTF.

Generates ready-to-paste Splunk SPL queries for common IR scenarios.
Does NOT require network access — purely local helper.

Usage:
    python3 splunk_query_builder.py list
    python3 splunk_query_builder.py build brute_force --user admin --threshold 5
    python3 splunk_query_builder.py build lateral_movement --src-ip 10.1.1.5
    python3 splunk_query_builder.py build flag_hunt --prefix "ctf{"
    python3 splunk_query_builder.py build powershell_abuse
    python3 splunk_query_builder.py build new_process --host WIN-DC01
    python3 splunk_query_builder.py build c2_beacon --dest-ip 1.2.3.4
    python3 splunk_query_builder.py build exfil --min-bytes 10000000
"""

import argparse
import textwrap
import sys

# ---------------------------------------------------------------------------
# Query templates — each is a function returning an SPL string
# ---------------------------------------------------------------------------

TEMPLATES = {}


def template(name, description):
    """Decorator to register a query template."""
    def decorator(fn):
        TEMPLATES[name] = {"fn": fn, "desc": description}
        return fn
    return decorator


@template("brute_force", "Detect brute-force / password spray attempts")
def brute_force(user=None, src_ip=None, threshold=10, index="*", earliest="-24h"):
    filter_parts = []
    if user:
        filter_parts.append(f'user="{user}"')
    if src_ip:
        filter_parts.append(f'src_ip="{src_ip}"')
    extra = (" " + " ".join(filter_parts)) if filter_parts else ""
    return textwrap.dedent(f"""\
        index={index} earliest={earliest}
          (EventCode=4625 OR "Failed password" OR "authentication failure" OR "Invalid user"){extra}
        | stats count as failures by src_ip, user
        | where failures > {threshold}
        | sort - failures
    """).strip()


@template("lateral_movement", "Logon Type 3 / pass-the-hash lateral movement detection")
def lateral_movement(src_ip=None, threshold=3, index="*", earliest="-24h"):
    ip_filter = f'src_ip="{src_ip}"' if src_ip else ""
    return textwrap.dedent(f"""\
        index={index} earliest={earliest} EventCode=4624 Logon_Type=3 {ip_filter}
        | stats dc(dest_host) as unique_dest count as total by src_ip, user
        | where unique_dest >= {threshold}
        | sort - unique_dest
    """).strip()


@template("privilege_escalation", "Detect privilege escalation events")
def privilege_escalation(user=None, index="*", earliest="-24h"):
    user_filter = f'user="{user}"' if user else ""
    return textwrap.dedent(f"""\
        index={index} earliest={earliest}
          (EventCode=4672 OR EventCode=4673 OR EventCode=4674) {user_filter}
        | table _time, host, user, Privileges, ProcessName
        | sort - _time
    """).strip()


@template("powershell_abuse", "Suspicious PowerShell command lines")
def powershell_abuse(host=None, index="*", earliest="-24h"):
    host_filter = f'host="{host}"' if host else ""
    return textwrap.dedent(f"""\
        index={index} earliest={earliest}
          (process="powershell*" OR CommandLine="*powershell*") {host_filter}
          (CommandLine="*-enc*" OR CommandLine="*-EncodedCommand*"
           OR CommandLine="*IEX*" OR CommandLine="*Invoke-Expression*"
           OR CommandLine="*DownloadString*" OR CommandLine="*bypass*"
           OR CommandLine="*hidden*" OR CommandLine="*-nop*")
        | table _time, host, user, CommandLine
        | sort - _time
    """).strip()


@template("lolbins", "Living-off-the-Land Binaries abuse")
def lolbins(host=None, index="*", earliest="-24h"):
    host_filter = f'host="{host}"' if host else ""
    return textwrap.dedent(f"""\
        index={index} earliest={earliest} {host_filter}
        process_name IN (
          "certutil.exe","mshta.exe","wscript.exe","cscript.exe",
          "regsvr32.exe","rundll32.exe","msiexec.exe","bitsadmin.exe",
          "wmic.exe","net.exe","net1.exe","nltest.exe","forfiles.exe",
          "pcalua.exe","xwizard.exe","syncappvpublishingserver.exe"
        )
        | table _time, host, user, process_name, CommandLine
        | sort - _time
    """).strip()


@template("new_process", "New/unusual process execution (Sysmon Event 1)")
def new_process(host=None, user=None, index="*", earliest="-24h"):
    filters = []
    if host:
        filters.append(f'host="{host}"')
    if user:
        filters.append(f'user="{user}"')
    extra = (" " + " ".join(filters)) if filters else ""
    return textwrap.dedent(f"""\
        index={index} earliest={earliest} EventCode=1{extra}
        | stats count by Image, ParentImage, User, host
        | sort - count
    """).strip()


@template("c2_beacon", "C2 beaconing / periodic callback detection")
def c2_beacon(dest_ip=None, dest_port=None, index="*", earliest="-24h"):
    filters = []
    if dest_ip:
        filters.append(f'dest_ip="{dest_ip}"')
    if dest_port:
        filters.append(f'dest_port={dest_port}')
    extra = (" " + " ".join(filters)) if filters else ""
    return textwrap.dedent(f"""\
        index={index} earliest={earliest}{extra}
        | bucket _time span=5m
        | stats count by _time, src_ip, dest_ip, dest_port
        | eventstats avg(count) as avg_c stdev(count) as std_c by src_ip, dest_ip
        | eval z_score = (count - avg_c) / if(std_c=0, 1, std_c)
        | where z_score < 1.5 AND count > 2
        | table _time, src_ip, dest_ip, dest_port, count, z_score
    """).strip()


@template("dns_exfil", "DNS exfiltration (unusually long query names)")
def dns_exfil(min_len=50, index="*", earliest="-24h"):
    return textwrap.dedent(f"""\
        index={index} earliest={earliest} sourcetype IN ("dns", "stream:dns")
        | eval q_len = len(query)
        | where q_len > {min_len}
        | stats count by src_ip, query, q_len
        | sort - q_len
    """).strip()


@template("exfil", "Large outbound data transfer (exfiltration)")
def exfil(min_bytes=100_000_000, index="*", earliest="-24h"):
    return textwrap.dedent(f"""\
        index={index} earliest={earliest}
        | stats sum(bytes_out) as total_out by src_ip, dest_ip
        | where total_out > {min_bytes}
        | eval total_MB = round(total_out / 1048576, 2)
        | sort - total_MB
    """).strip()


@template("flag_hunt", "Hunt for CTF flags in all log sources")
def flag_hunt(prefix="ctf{", index="*", earliest="-7d"):
    escaped = prefix.replace("{", "\\{")
    return textwrap.dedent(f"""\
        index={index} earliest={earliest}
          ("{prefix}" OR "flag{{" OR "HTB{{" OR "CTF{{")
        | table _time, host, source, sourcetype, _raw
        | sort - _time
    """).strip()


@template("webshell", "Web shell access detection")
def webshell(index="*", earliest="-24h"):
    return textwrap.dedent(f"""\
        index={index} earliest={earliest}
          (uri_path="*.php" OR uri_path="*.aspx" OR uri_path="*.jsp")
          (uri_query="*cmd=*" OR uri_query="*exec=*" OR uri_query="*shell=*"
           OR uri_query="*system=*" OR uri_query="*passthru=*")
        | table _time, src_ip, uri_path, uri_query, status, bytes
        | sort - _time
    """).strip()


@template("new_service", "New service/scheduled task created")
def new_service(index="*", earliest="-24h"):
    return textwrap.dedent(f"""\
        index={index} earliest={earliest}
          (EventCode=4698 OR EventCode=4702 OR EventCode=7045 OR "New service")
        | table _time, host, user, ServiceName, TaskName, CommandLine
        | sort - _time
    """).strip()


@template("port_scan", "Port scan detection (many unique ports from one source)")
def port_scan(src_ip=None, threshold=20, index="*", earliest="-1h"):
    ip_filter = f'src_ip="{src_ip}"' if src_ip else ""
    return textwrap.dedent(f"""\
        index={index} earliest={earliest} {ip_filter}
        | stats dc(dest_port) as unique_ports count by src_ip, dest_ip
        | where unique_ports > {threshold}
        | sort - unique_ports
    """).strip()


@template("user_investigation", "Full activity timeline for a specific user")
def user_investigation(user, index="*", earliest="-7d"):
    return textwrap.dedent(f"""\
        index={index} earliest={earliest} user="{user}"
        | eval src = coalesce(src_ip, host)
        | table _time, sourcetype, src, EventCode, CommandLine, _raw
        | sort _time
    """).strip()


@template("roundcube_rce", "Roundcube webmail RCE detection")
def roundcube_rce(index="*", earliest="-24h"):
    return textwrap.dedent(f"""\
        index={index} earliest={earliest} sourcetype=access_combined
          (uri_path="*/bin/sh*" OR uri_path="*perl*" OR uri_path="*python*" OR uri_path="*wget*" OR uri_path="*curl*")
          OR (uri_query="*_task=mail*" AND uri_query="*_action=send*")
        | table _time, src_ip, uri_path, uri_query, status
        | sort - _time
    """).strip()


@template("suid_abuse", "SUID abuse detection via auditd")
def suid_abuse(index="*", earliest="-24h"):
    return textwrap.dedent(f"""\
        index={index} earliest={earliest} sourcetype=auditd
          type=EXECVE (a0="find" OR a0="tar" OR a0="awk" OR a0="sed" OR a0="less" OR a0="more" OR a0="vim" OR a0="nmap")
          (a1="-exec" OR a1="--exec" OR a2="-exec" OR a2="--exec")
        | table _time, host, a0, a1, a2, a3
        | sort - _time
    """).strip()


@template("reverse_shell", "Reverse shell detection (bash -i, /dev/tcp, nc -e)")
def reverse_shell(index="*", earliest="-24h"):
    return textwrap.dedent(f"""\
        index={index} earliest={earliest}
          (CommandLine="*bash -i*" OR CommandLine="*/dev/tcp/*" OR CommandLine="*nc -e*" OR CommandLine="*netcat -e*" OR CommandLine="*mkfifo*")
        | table _time, host, user, CommandLine
        | sort - _time
    """).strip()


@template("chisel_tunnel", "Chisel tunneling detection")
def chisel_tunnel(index="*", earliest="-24h"):
    return textwrap.dedent(f"""\
        index={index} earliest={earliest}
          (CommandLine="*chisel client*" OR CommandLine="*chisel server*" OR process_name="chisel")
        | table _time, host, user, CommandLine, dest_ip, dest_port
        | sort - _time
    """).strip()


@template("linpeas_exec", "LinPEAS/recon tool execution")
def linpeas_exec(index="*", earliest="-24h"):
    return textwrap.dedent(f"""\
        index={index} earliest={earliest}
          (CommandLine="*linpeas.sh*" OR CommandLine="*lse.sh*" OR CommandLine="*pspy*" OR process_name="linpeas" OR process_name="pspy*")
        | table _time, host, user, CommandLine, process_name
        | sort - _time
    """).strip()


@template("systemd_backdoor", "Suspicious systemd unit creation")
def systemd_backdoor(index="*", earliest="-24h"):
    return textwrap.dedent(f"""\
        index={index} earliest={earliest}
          (CommandLine="*systemctl enable*" OR CommandLine="*systemctl link*" OR CommandLine="*systemctl daemon-reload*")
          (CommandLine="*/tmp/*" OR CommandLine="*/var/tmp/*" OR CommandLine="*/dev/shm/*" OR CommandLine="*~/.config/systemd/user/*")
        | table _time, host, user, CommandLine
        | sort - _time
    """).strip()


@template("cron_persistence", "Cron persistence detection")
def cron_persistence(index="*", earliest="-24h"):
    return textwrap.dedent(f"""\
        index={index} earliest={earliest}
          (CommandLine="*crontab -e*" OR CommandLine="*echo * | crontab*" OR CommandLine="*>> /etc/crontab*" OR CommandLine="*>> /var/spool/cron/*")
        | table _time, host, user, CommandLine
        | sort - _time
    """).strip()


@template("gitlab_rce", "GitLab RCE/unauthorized code push detection")
def gitlab_rce(index="*", earliest="-24h"):
    return textwrap.dedent(f"""\
        index={index} earliest={earliest}
          (sourcetype="gitlab:production" OR sourcetype="gitlab:api")
          (uri_path="*/api/v4/projects/*/repository/commits*" OR uri_path="*/api/v4/projects/*/repository/files*")
          (method="POST" OR method="PUT")
        | table _time, src_ip, user, uri_path, method, status
        | sort - _time
    """).strip()


@template("infostealer_artifacts", "Infostealer artifacts (Recycle Bin, browser data theft)")
def infostealer_artifacts(index="*", earliest="-24h"):
    return textwrap.dedent(f"""\
        index={index} earliest={earliest}
          (CommandLine="*rufus.exe*" AND CommandLine="*Recycle.Bin*") OR 
          (CommandLine="*AppData\\\\Local\\\\Google\\\\Chrome\\\\User Data\\\\Default\\\\Login Data*") OR
          (CommandLine="*AppData\\\\Roaming\\\\Mozilla\\\\Firefox\\\\Profiles*")
        | table _time, host, user, CommandLine
        | sort - _time
    """).strip()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def cmd_list(_args):
    print(f"{'TEMPLATE':<25} DESCRIPTION")
    print("-" * 70)
    for name, meta in sorted(TEMPLATES.items()):
        print(f"  {name:<23} {meta['desc']}")


def cmd_build(args):
    name = args.template
    if name not in TEMPLATES:
        print(f"Unknown template: '{name}'. Run `list` to see options.", file=sys.stderr)
        sys.exit(1)

    fn = TEMPLATES[name]["fn"]

    # Build kwargs from CLI args, only passing those the function accepts
    import inspect
    sig = inspect.signature(fn)
    params = sig.parameters

    kwargs = {}
    for param in params:
        cli_key = param.replace("_", "-")
        val = getattr(args, param, None) or getattr(args, cli_key, None)
        if val is not None:
            kwargs[param] = val

    query = fn(**kwargs)
    print("\n" + "=" * 60)
    print(f"  Template : {name}")
    print("=" * 60)
    print(query)
    print("=" * 60)

    if args.copy:
        try:
            import subprocess
            subprocess.run(["xclip", "-selection", "clipboard"],
                           input=query.encode(), check=True)
            print("\n[+] Copied to clipboard (xclip)")
        except Exception:
            try:
                subprocess.run(["xsel", "--clipboard", "--input"],
                               input=query.encode(), check=True)
                print("\n[+] Copied to clipboard (xsel)")
            except Exception:
                print("\n[!] Could not copy to clipboard — xclip/xsel not found")


def main():
    parser = argparse.ArgumentParser(
        description="SPL query builder for Blue Team CTF"
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("list", help="List all available templates")

    p_build = sub.add_parser("build", help="Generate a specific query")
    p_build.add_argument("template", help="Template name (see `list`)")
    p_build.add_argument("--index", default="*")
    p_build.add_argument("--earliest", default="-24h")
    p_build.add_argument("--user")
    p_build.add_argument("--src-ip")
    p_build.add_argument("--dest-ip")
    p_build.add_argument("--dest-port", type=int)
    p_build.add_argument("--host")
    p_build.add_argument("--threshold", type=int)
    p_build.add_argument("--min-bytes", type=int)
    p_build.add_argument("--min-len", type=int)
    p_build.add_argument("--prefix", default="ctf{")
    p_build.add_argument("--copy", action="store_true",
                          help="Copy query to clipboard")

    args = parser.parse_args()

    if args.cmd == "list":
        cmd_list(args)
    elif args.cmd == "build":
        cmd_build(args)


if __name__ == "__main__":
    main()
