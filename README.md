# ids-lab

A small network intrusion detection lab. Attacks run between Docker containers, the traffic is captured, and two detectors try to catch them: a set of hand-written rules and a machine learning model.

## Why this exists

I wanted a project where I could break things on purpose without breaking anything that matters. A lab that simulates attacks gives me ground truth for free, because I know exactly when each attack started, where it came from and what it was. That makes it possible to measure a detector properly instead of just claiming it works.

It is also an excuse to work through the whole chain: packet capture, traffic analysis, feature engineering, classic rule-based detection, and machine learning, with the engineering habits around it (tests, typing, CI, security checks) that a real project needs.

## Status

Early development. The repository is being built branch by branch, and most of what is described below does not exist yet. I update this list as pieces get merged.

- [ ] Phase 0: project scaffold, tooling and CI
- [ ] Phase 1: isolated lab, benign traffic, attack scenarios, traffic capture
- [ ] Phase 2: pcap files to flows to per-source window features
- [ ] Phase 3: rule engine, machine learning models, evaluation
- [ ] Phase 4: documentation, published results, first release (`v0.1.0`)

There are no performance numbers here on purpose. They will be added once the evaluation step exists and can produce them reproducibly.

## How it works

1. A Docker network with no route to the outside world hosts four containers: a **victim** (nginx and an SSH server), a **benign** traffic generator, an **attacker**, and a **sensor** that sees everything the victim sees.
2. The attacker runs a scenario described in a YAML file. When it finishes, it writes a small manifest with the attack type, the attacker's IP address and the start and end times.
3. The sensor records the victim's traffic into a pcap file.
4. The `idslab` Python package reads the pcap, groups packets into flows, then groups flows into time windows per source IP (5 seconds by default). Each window gets a handful of features, such as the number of distinct destination ports or the share of connections that never completed.
5. Two detectors look at the same windows. The rule engine applies thresholds from a YAML file. The machine learning side uses a Random Forest, which learns the known attack types, and an Isolation Forest, which is trained on normal traffic only and flags anything unusual.
6. The evaluation step compares the alerts with the manifests and reports precision, recall, F1, and false alarms per hour of normal traffic.

### Attacks covered

| Attack | Tool in the lab | What the detectors look at |
| --- | --- | --- |
| Port scan | nmap | Many distinct destination ports from one source in a short window |
| SYN flood | hping3 | A high rate of SYN packets with few completed handshakes |
| SSH brute force | hydra | Many short connections to port 22 from one source |

## Requirements

- Docker with Compose v2 (Docker Desktop on Windows and macOS)
- Python 3.11 or newer

Capturing and attacking happen inside containers. Reading and analysing pcap files on your own machine does not need elevated privileges.

## Getting started

The commands below describe the interface I am building towards. Names and options may change before `v0.1.0`.

```bash
git clone https://github.com/Azoor/ids-lab.git
cd ids-lab
python -m venv .venv
source .venv/bin/activate        # on Windows PowerShell: .venv\Scripts\Activate.ps1
pip install -e ".[dev]"
```

Start the lab and run an attack:

```bash
docker compose up -d
docker compose run --rm attacker idslab scenario run configs/scenarios/port_scan.yaml
docker compose down
```

Analyse the capture:

```bash
idslab detect data/raw/port_scan.pcap --rules configs/rules.yaml --output alerts.jsonl
idslab train --captures data/raw --labels data/labels --output models/
idslab predict data/raw/port_scan.pcap --model models/random_forest.joblib
idslab evaluate --captures data/raw --labels data/labels --models models/
```

Captures, labels and trained models stay in the `data/` and `models/` folders, which are ignored by Git.

## Safety

This project generates attack traffic, so the lab is built to stay contained:

- The Docker network is internal. Containers cannot reach the internet or the rest of your home network.
- No container publishes a port on the host.
- The scenario runner refuses to target any address outside the lab subnet.
- Containers run with all Linux capabilities dropped except the one they need, with `no-new-privileges` and resource limits.
- The Docker socket is never mounted into a container.
- The victim's accounts and passwords are throwaway values that only exist inside the lab. They are weak on purpose, because the brute force scenario needs something to find. Never reuse a real password there.

Saved models are loaded with `joblib`, which relies on pickle. Each model file comes with a SHA-256 checksum that is verified before loading, and you should only load models you trained yourself.

To report a security problem in this repository, see `SECURITY.md` once it is added.

## Limitations

- The lab traffic is much simpler than traffic on a real network. Good scores here say little about how the detectors would behave in production.
- Windows are labelled using the manifest's start and end times, so labels are slightly imprecise at the edges of each attack.
- Analysis is offline, on pcap files. Real-time detection is not part of the first release.
- Scapy is convenient but slow on very large captures.

## Development

Work is organised in small branches, one per feature, each merged through a Pull Request with a squash merge. Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/), in English.

Before opening a Pull Request:

```bash
pre-commit run --all-files
pytest
```

The checks in CI are `ruff` (lint and format), `mypy` in strict mode, `pytest` with a coverage threshold, `bandit`, `pip-audit`, `gitleaks` and `hadolint`.

## License

MIT. See [LICENSE](LICENSE).
