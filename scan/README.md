# scan

A collection of lightweight host and network reconnaissance tools for live systems, mapping active topology and process-network relationships.

## Components

- **`proc_tree.py`**: Visualizes Linux process hierarchies in structured ASCII trees, highlighting parent-child relationships, command-line arguments, executing user IDs, and open network sockets.
- **`net_map.py`**: Local network and subnet discovery utility that scans active hosts and identifies responsive IP addresses without noisy active port scans.
- **`graph_map.py`**: Topological relationship mapper transforming network and host connection tables into structured graph representations.

## Usage

```bash
# Render full host process tree
python3 proc_tree.py

# Show only processes with active listening sockets or established connections
python3 proc_tree.py --conns-only

# Filter process tree by target PID
python3 proc_tree.py --pid 1234

# Scan local subnet for active hosts
python3 net_map.py --range 192.168.1.0/24
```
