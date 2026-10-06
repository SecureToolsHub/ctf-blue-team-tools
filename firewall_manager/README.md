# firewall_manager

A rapid host-level firewall controller designed for defensive incident response and CTF host protection. Automates `iptables`, `ufw`, and `nftables` workflows.

## Features

- **Status & Rule Audit**: Displays active firewall state and open inbound/outbound rules in a clean tabular view.
- **Selective Port Allowlisting**: Restricts inbound connections strictly to specified service ports (e.g. 22, 80, 443) while dropping unauthorized traffic.
- **Instant Malicious IP Banning**: Rapidly inserts drop rules for offending attacker IPs or subnets.
- **Rule Backup & Reversion**: Saves current rule snapshots to allow instantaneous rollback.

## Usage

```bash
# Check current firewall configuration and active rules
sudo python3 firewall_manager.py status

# Allow only critical service ports and drop all other inbound traffic
sudo python3 firewall_manager.py allow --ports 22,80,443 --default-drop

# Block a malicious IP immediately
sudo python3 firewall_manager.py ban 198.51.100.54

# Backup current rule table
sudo python3 firewall_manager.py backup -o /etc/iptables.backup.rules

# Restore previously saved rule table
sudo python3 firewall_manager.py restore -i /etc/iptables.backup.rules
```
