# score_calculator

A competition scoring calculator and point simulation tool designed to model, project, and track team performance across SLA availability, IoC submissions, and report quality criteria.

## Features

- **Formula Modeling**: Implements standard CTF scoring logic:
  $$\text{Score} = \text{SLA} + \text{IoC} + (\text{IoC} \times (1 + K_1 + K_2 + K_3))$$
- **What-If Analysis**: Simulates score outcomes based on varying service downtime percentages, IoC counts, and report evaluation scores.
- **Service Weighting**: Factors in individualized service point allocations.

## Usage

```bash
# Calculate score projection
python3 score_calculator.py --sla 92.5 --iocs 16 --k1 0.6 --k2 0.3 --k3 0.1

# Run interactive simulation mode
python3 score_calculator.py --interactive
```
