# ids-lab

A small network intrusion detection lab. Attacks run between Docker containers, the traffic is captured, and three detectors try to catch them: a set of hand-written rules and two machine learning models.

## Why this exists

I wanted a project where I could break things on purpose without breaking anything that matters. A lab that simulates attacks gives me ground truth for free, because I know exactly when each attack started, where it came from and what it was. That makes it possible to measure a detector properly instead of just claiming it works.

It is also an excuse to work through the whole chain: packet capture, traffic analysis, feature engineering, classic rule-based detection, and machine learning, with the engineering habits around it (tests, typing, CI, security checks) that a real project needs.

## Status

The code is complete and has been run on captures recorded in the lab. What is left is tagging the first release.

- [x] Phase 0: project scaffold, tooling and CI
- [x] Phase 1: isolated lab, benign traffic, attack scenarios, traffic capture
- [x] Phase 2: pcap files to flows to per-source window features
- [x] Phase 3: rule engine, machine learning models, evaluation
- [ ] Phase 4: documentation, published results, first release (`v0.1.0`)

The [results](#results) cover one attack type so far, and they need to be read with the caveats next to them.

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

The port scan scenario is ready to run, and it is the only attack recorded and evaluated so far. The SYN flood and SSH brute force scenarios ship with an empty `command`, to be filled in locally. See [configs/scenarios/README.md](configs/scenarios/README.md).

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

Build the images once, then start the lab. The victim and the benign traffic generator come up together:

```bash
docker compose --profile capture --profile attack build
docker compose up -d --wait
```

Record a minute of normal traffic:

```bash
docker compose --profile capture run --rm sensor idslab capture run --duration 60 --output data/raw/benign_1.pcap
```

To record attacks, start a capture in one terminal, then run the scenario from a second one within the next few seconds, so it falls inside the capture. A single scan lasts a fraction of a second and yields one labelled window, so repeat it, leaving a pause between runs so each scan lands in its own window:

```bash
# terminal 1
docker compose --profile capture run --rm sensor idslab capture run --duration 150 --output data/raw/port_scan_1.pcap

# terminal 2, right after
for i in $(seq 8); do
  docker compose --profile attack run --rm attacker idslab scenario run configs/scenarios/port_scan.yaml
  sleep 12
done
```

Each run writes a manifest to `data/raw`, named after the scenario and its start time. Record several captures of each kind: the train/test split keeps a capture whole, so it needs at least two. When you are done, run `docker compose down`.

Do not pass `--build` to `docker compose run` while recording. It rebuilds the victim image and recreates the victim container, which ends the sensor's capture early because the two share a network namespace. Rebuild only after changing code, before starting the lab.

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

Split the captures into a training and a test set, train the models, and evaluate everything on the test set (in PowerShell, pass `(Get-ChildItem data\windows\*.csv).FullName` instead of the glob):

```bash
idslab dataset split data/windows/*.csv --output-dir data/dataset
idslab train data/dataset/train.csv --output-dir models
idslab evaluate data/dataset/test.csv --model-dir models --output data/report.json
```

A trained model can also be applied to a capture on its own:

```bash
idslab predict data/raw/port_scan_1.pcap --detector random_forest --output data/alerts/port_scan_1_rf.jsonl
```

Every command has `--help`. Captures, windows, alerts and trained models stay in the `data/` and `models/` folders, which are ignored by Git.

## Results

Measured on the lab captures described below, with the default settings (5 second windows, seed 42, 30% of the captures held out for testing, contamination 5%).

**Data.** Twelve captures: six of normal traffic (14 minutes in total) and six of port scans (41 scans with nmap, 13 minutes, with the normal traffic still running alongside). Together they give 369 windows, 328 benign and 41 port scan. The split put whole captures on each side:

| | Windows | Benign | Port scan | Captures |
| --- | --- | --- | --- | --- |
| Training | 222 | 197 | 25 | 8 |
| Test | 147 | 131 | 16 | `benign_3`, `benign_6`, `port_scan_2`, `port_scan_3` |

**Scores on the test set.**

| Detector | Precision | Recall | F1 | False alarms per hour |
| --- | --- | --- | --- | --- |
| Rules | 1.000 | 1.000 | 1.000 | 0.0 |
| Random Forest | 1.000 | 1.000 | 1.000 | 0.0 |
| Isolation Forest | 0.533 | 1.000 | 0.696 | 76.9 |

**How to read this.**

- These numbers are not evidence that the detectors are good. A port scan sweeps 1,024 ports within a fraction of a second, while normal traffic in the lab touches a handful, so any threshold between the two separates them. A perfect score on this task is expected.
- The test set holds 16 attack windows from two captures, all of one attack type and one tool. One more or one fewer miss would change the recall noticeably, and a different seed would put different captures in the test set.
- The rule thresholds in `configs/rules.yaml` were set before the captures were recorded and were not tuned on them. The SYN flood and SSH brute force rules have not met real traffic.
- The Isolation Forest finds every scan but also flags about one benign window in ten, roughly 14 false alarms out of 131 benign test windows. It learns what normal looks like without knowing any attack, so it pays for that generality in false alarms, and `--contamination` moves that trade-off in either direction.
- Every attack comes from one attacker address. Normal traffic in the lab is also scripted, so it is far more regular than traffic on a real network.

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
- The rule thresholds are starting values chosen from how each tool behaves. They have not been tuned, and only the port scan rule has been checked against recorded traffic.
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
