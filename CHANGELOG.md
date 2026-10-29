# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-10-29

### Added

- Python package layout with a `src/` directory, tooling configuration and a smoke test.
- Pre-commit hooks, a CI workflow (lint, type check, tests, security checks, secret scanning) and Dependabot updates.
- Contribution guide, security policy, and issue and pull request templates.
- Isolated Docker network and a victim container running nginx and SSH.....
- Benign traffic generator and container: web requests and SSH logins against the victim.
- Attack scenario framework: target guard, scenario loader, manifest writer, and the idslab scenario run command.
- Sensor container and the idslab capture run command, using tcpdump to write pcap files.
- Pcap reader, flow builder and the idslab flows build command.
- Per-source window features and the idslab windows build command.
- Ground-truth labelling of windows from scenario manifests, and the attacker address in the manifest.
- Threshold-based rule engine and the idslab detect command.
- Reading of labelled window files and a capture-level train/test split with idslab dataset split.
- Random Forest and Isolation Forest training with checksum-verified model storage, and the idslab train command.
- Detection with the trained models through idslab predict, and one-line error messages in the CLI.
- Evaluation of the rules and the models against ground-truth labels with idslab evaluate.
- Scenario manifests are named after the scenario and its start time, so a second run no longer overwrites the first.
- README with the full command sequence, pipeline reference in docs/pipeline.md, and a note on rebuilding lab images in CONTRIBUTING.md.
