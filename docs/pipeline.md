# Pipeline

This page describes what happens to the traffic between the pcap file and the final scores, and the formats of the files in between. The commands themselves are in the [README](../README.md).

```text
pcap  ->  flows  ->  windows  ->  labelled windows  ->  train / test sets
                         |                                     |
                         +--> rules ------+                    |
                         +--> models -----+--> alerts --> evaluation
```

## Capture

The sensor container shares the victim's network namespace and runs `tcpdump`, so it sees exactly what the victim sees and nothing else. A capture is a plain pcap file, named by whoever runs it. Only IPv4 frames are used afterwards; ARP and other link-level traffic is skipped.

## Flows

A flow is a bidirectional conversation: the packets of the same protocol between two endpoints, counted once whichever direction they travel in. The side that sent the first packet is the flow's source, and "forward" means from that side.

A flow ends after 60 seconds without a packet (`--idle-timeout`). A later packet between the same endpoints starts a new flow, which is how a reused source port is told apart from the connection that used it before.

`idslab flows build` writes one row per flow:

| Column | Meaning |
| --- | --- |
| `src_ip`, `dst_ip` | Source and destination addresses |
| `src_port`, `dst_port` | Ports, empty for protocols without ports |
| `protocol` | `tcp`, `udp`, `icmp` or `other` |
| `start_time`, `end_time` | First and last packet, in seconds since the epoch |
| `fwd_packets`, `bwd_packets` | Packets in each direction |
| `fwd_bytes`, `bwd_bytes` | Bytes in each direction |
| `syn_packets` | Connection attempts: SYN set, ACK clear |
| `fin_packets`, `rst_packets` | Packets with FIN or RST set |
| `established` | True if the destination answered a SYN with a SYN-ACK |
| `duration` | `end_time - start_time` |

## Windows

Detectors do not judge single flows. A port scan or a brute force is only visible when many flows from the same source are seen together, so time is cut into fixed windows (5 seconds by default, `--window-size`) and each source IP gets one row per window. A flow belongs to the window in which it started. Windows with no flow are not reported.

| Feature | Meaning | What it helps to see |
| --- | --- | --- |
| `flow_count` | Flows started in the window | Overall activity |
| `distinct_dst_ports` | Different destination ports contacted | Port scans |
| `distinct_dst_ips` | Different destination addresses contacted | Sweeps across hosts |
| `max_flows_to_one_port` | Flows sent to the busiest destination port | Brute force on one service |
| `syn_packets` | Connection attempts | SYN floods |
| `rst_packets` | Packets with RST set | Probes of closed ports |
| `incomplete_ratio` | Share of TCP flows whose handshake never completed | Scans and floods |
| `total_packets`, `total_bytes` | Traffic in both directions | Volume |
| `mean_flow_duration` | Average flow duration, in seconds | Short probes against long sessions |

The CSV written by `idslab windows build` has these columns, preceded by `src_ip` and `window_start` and followed by `label`.

## Labels

The scenario runner writes a manifest for every run: the attack type, the attacker's address, the target, and the start and end times. A window is labelled with the attack type of a manifest when both of these hold:

- the window's source is the manifest's attacker address;
- the window overlaps the time between the manifest's start and end.

Every other window is `benign`, including traffic from other hosts during an attack. If several manifests match, the one that started first wins.

The labels are slightly generous at the edges: a window that overlaps only the first or last moments of an attack still counts as the attack. A manifest records when the command ran, not when each packet was sent, so this is the honest limit of what the lab knows.

## Train and test sets

Consecutive windows of one attack look alike. If they were shuffled and divided at random, a model would see some of them in training and score well on their neighbours in the test set without having learned anything general. `idslab dataset split` therefore keeps each capture, meaning each CSV file, whole on one side. The split is reproducible with `--seed`, and at least one capture goes to each side. A warning is logged if an attack type shows up only in the test set.

## Detectors

All three detectors read the same windows and write alerts in the same format.

**Rule engine.** The rules live in [configs/rules.yaml](../configs/rules.yaml). A rule is a list of conditions on window features, each with `at_least`, `at_most` or both, and it fires when all of them hold. Rules are tried in order and the first match wins, so a window raises at most one alert. Unknown feature names or keys in the file are rejected rather than ignored. The thresholds are starting values chosen from how each tool behaves, not measurements.

**Random Forest.** A classifier trained on all labelled windows. Classes are weighted by how rare they are, because attack windows are far fewer than benign ones and the forest would otherwise answer "benign" every time. It reports the attack type it predicts, with its probability.

**Isolation Forest.** A model trained on benign windows only. It scores how unusual a window is, so it can notice an attack type it never saw, but it cannot name it: its alerts have the type `anomaly`. An Isolation Forest does not isolate a far outlier faster than the most extreme training window, so the threshold needs some room. `--contamination` (5% by default) is the share of normal windows it may flag. Raising it catches more attacks and raises false alarms by about as much.

### Alerts

Alerts are written as JSON Lines, one object per line:

```json
{"src_ip": "172.30.0.30", "window_start": 1761732000.0, "attack_type": "port_scan", "detector": "port_scan", "evidence": {"distinct_dst_ports": 1024.0, "incomplete_ratio": 0.97}}
```

`detector` is the name of the rule that fired, or of the model that flagged the window. `evidence` holds the feature values behind a rule, the probability for the Random Forest, or the anomaly score for the Isolation Forest.

## Evaluation

`idslab evaluate` runs the detectors on the labelled windows of the test set and scores each one per window: a window labelled as an attack is a hit if the detector raised an alert for it, and a benign window with an alert is a false alarm.

| Metric | Meaning |
| --- | --- |
| Precision | Share of alerts that were real attacks |
| Recall | Share of attack windows that were caught |
| F1 | Harmonic mean of the two |
| False alarms per hour | False alarms divided by the hours of normal traffic, where each benign window counts as one window length |
| Recall by attack | Recall of each attack type on its own |

The false alarm rate counts source-windows, not wall-clock time, so a lab with several sources produces more normal windows per hour than the clock does. It is meant for comparing detectors with each other, not as an absolute figure.

The evaluation refuses a test set without benign windows or without attack windows, since the rates would mean nothing.

## Model files

Models are saved in `models/` as `random_forest.joblib` and `isolation_forest.joblib`, each with a `.sha256` file next to it. Loading checks the checksum first, then that the model is of the expected kind and was trained on the features the current code produces. A model trained before a change to the features has to be trained again.
