# ids-lab

A small network intrusion detection lab. Attacks run between Docker containers, the traffic is captured, and three detectors try to catch them: a set of hand-written rules and two machine learning models.

## Why this exists

I wanted a project where I could break things on purpose without breaking anything that matters. A lab that simulates attacks gives me ground truth for free, because I know exactly when each attack started, where it came from and what it was. That makes it possible to measure a detector properly instead of just claiming it works.

It is also an excuse to work through the whole chain: packet capture, traffic analysis, feature engineering, classic rule-based detection, and machine learning, with the engineering habits around it (tests, typing, CI, security checks) that a real project needs.

## Status

All the code is in place. What is left is running the lab on real captures, publishing the numbers, and tagging the first release.

- [x] Phase 0: project scaffold, tooling and CI
- [x] Phase 1: isolated lab, benign traffic, attack scenarios, traffic capture
- [x] Phase 2: pcap files to flows to per-source window features
- [x] Phase 3: rule engine, machine learning models, evaluation
- [ ] Phase 4: documentation, published results, first release (`v0.1.0`)

There are no performance numbers here on purpose. They will be added once the evaluation has run on real captures and can be reproduced.

## How it works

1. A Docker network with no route to the outside world hosts four containers: a **victim** (nginx and an SSH server), a **benign** traffic generator, an **attacker**, and a **sensor** that sees everything the victim sees.
2. The attacker runs a scenario described in a YAML file. When it finishes, it writes a manifest with the attack type, the attacker's IP address and the start and end times.
3. The sensor records the victim's traffic into a pcap file.
4. The `idslab` Python package reads the pcap, groups packets into flows, then groups flows into time windows per source IP (5 seconds by default). Each window gets a handful of features, such as the number of distinct destination ports or the share of connections that never completed. Windows are labelled from the manifests.
5. Three detectors look at the same windows. The rule engine applies thresholds from a YAML file. A Random Forest learns the known attack types. An Isolation Forest is trained on normal traffic only and flags anything unusual.
6. The evaluation step compares the alerts with the labels and reports precision, recall, F1, and false alarms per hour of normal traffic.

[docs/pipeline.md](docs/pipeline.md) describes each step in detail: file formats, the features, how labels are assigned and why the train/test split works the way it does.

### Attacks covered

| Attack | Tool in the lab | What the detectors look at |
| --- | --- | --- |
| Port scan | nmap | Many distinct destination ports from one source in a short window |
| SYN flood | hping3 | A high rate of SYN packets with few completed handshakes |
| SSH brute force | hydra | Many short connections to port 22 from one source |

The port scan scenario is ready to run. The SYN flood and SSH brute force scenarios ship with an empty `command`, to be filled in locally. See [configs/scenarios/README.md](configs/scenarios/README.md).

## Requirements

- Docker with Compose v2 (Docker Desktop on Windows and macOS)
- Python 3.11 or newer

Capturing and attacking happen inside containers. Reading and analysing pcap files on your own machine does not need elevated privileges.

## Getting started

```bash
git clone https://github.com/OWNER/ids-lab.git
cd ids-lab
python -m venv .venv
source .venv/bin/activate        # on Windows PowerShell: .venv\Scripts\Activate.ps1
pip install -e ".[dev]"
```

### Record traffic

Start the lab. The victim and the benign traffic generator come up together:

```bash
docker compose up -d --build --wait
```

Record a minute of normal traffic:

```bash
docker compose --profile capture run --build --rm sensor idslab capture run --duration 60 --output data/raw/benign_1.pcap
```

To record an attack, start the capture in one terminal, then run the scenario from a second one within the next few seconds, so it falls inside the capture:

```bash
docker compose --profile capture run --build --rm sensor idslab capture run --duration 60 --output data/raw/port_scan_1.pcap
docker compose --profile attack run --build --rm attacker idslab scenario run configs/scenarios/port_scan.yaml
```

The scenario writes its manifest to `data/raw`, named after the scenario and its start time. Record several captures of each kind: the train/test split keeps a capture whole, so it needs at least two. When you are done, run `docker compose down`.

Images are not rebuilt by `docker compose run` unless you pass `--build`, which is why the commands above include it.

### Analyse the captures

Turn each capture into labelled windows. Pointing `--manifests` at `data/raw` is enough for every capture: a window is only labelled as an attack when its source and time match a manifest.

```bash
idslab windows build data/raw/benign_1.pcap --output data/windows/benign_1.csv --manifests data/raw
idslab windows build data/raw/port_scan_1.pcap --output data/windows/port_scan_1.csv --manifests data/raw
```

Try the rule engine on a single capture:

```bash
idslab detect data/raw/port_scan_1.pcap --rules configs/rules.yaml --output data/alerts/port_scan_1.jsonl
```

Split the captures into a training and a test set, train the models, and evaluate everything on the test set:

```bash
idslab dataset split data/windows/benign_1.csv data/windows/benign_2.csv data/windows/port_scan_1.csv data/windows/port_scan_2.csv --output-dir data/dataset
idslab train data/dataset/train.csv --output-dir models
idslab evaluate data/dataset/test.csv --model-dir models --output data/report.json
```

A trained model can also be applied to a capture on its own:

```bash
idslab predict data/raw/port_scan_1.pcap --detector random_forest --output data/alerts/port_scan_1_rf.jsonl
```

Every command has `--help`. Captures, windows, alerts and trained models stay in the `data/` and `models/` folders, which are ignored by Git.

## Safety

This project generates attack traffic, so the lab is built to stay contained:

- The Docker network is internal. Containers cannot reach the internet or the rest of your home network.
- No container publishes a port on the host.
- The scenario runner refuses to target any address outside the lab subnet.
- Containers run with all Linux capabilities dropped except the few they need, with `no-new-privileges` and resource limits.
- The Docker socket is never mounted into a container.
- The victim's accounts and passwords are throwaway values that only exist inside the lab. They are weak on purpose, because the brute force scenario needs something to find. Never reuse a real password there.

Saved models are loaded with `joblib`, which relies on pickle. Each model file comes with a SHA-256 checksum that is verified before loading, which catches corruption and mix-ups. It does not make a model from someone else safe: only load models you trained yourself.

To report a security problem in this repository, see [SECURITY.md](SECURITY.md).

## Limitations

- The lab traffic is much simpler than traffic on a real network. Good scores here say little about how the detectors would behave in production.
- Windows are labelled using the manifest's start and end times, so labels are slightly generous at the edges of each attack.
- A window is judged on one source at a time. An attack spread over many sources, such as a distributed flood, is not something the features can see.
- The Isolation Forest cannot tell a far outlier from the most extreme normal window, so its threshold has to be set with some room. It trades missed attacks against false alarms through `--contamination`.
- The rule thresholds are starting values chosen from how each tool behaves. They are meant to be tuned against the evaluation.
- Analysis is offline, on pcap files. Real-time detection is not part of the first release.
- Scapy is convenient but slow on very large captures.

## Development

Work is organised in small branches, one per feature, each merged through a Pull Request with a squash merge. Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/), in English. See [CONTRIBUTING.md](CONTRIBUTING.md).

Before opening a Pull Request:

```bash
pre-commit run --all-files
pytest
```

The checks in CI are `ruff` (lint and format), `mypy` in strict mode, `pytest` with a coverage threshold, `bandit`, `pip-audit`, `gitleaks` and `hadolint`.

## License

MIT. See [LICENSE](LICENSE).
