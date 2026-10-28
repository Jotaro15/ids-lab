# Scenario configuration

Each file here describes one attack scenario: its name, the label it gets in
the manifest, a description, which lab host it targets, and how long it may
run. `idslab scenario run <file>` loads it, confirms the target resolves
inside the lab subnet, runs `command`, and records a manifest with the start
and end time next to the capture.

`port_scan.yaml` is ready to run as it stands.

`syn_flood.yaml` and `ssh_brute_force.yaml` ship with an empty `command`.
Fill it in locally before running them, using the tool's own documentation
(`hping3 --help`, `hydra -h`). These two are left for you to configure on
purpose; see `CONTRIBUTING.md` for why. Keep `data/` untouched by Git either
way: a filled-in scenario file still only configures what already runs
inside the isolated lab network, but there is no reason to track it.

To add a scenario of your own, copy an existing file and change its fields.
`attack_type` is what ends up in the trained model's labels, so keep it
short and stable.
