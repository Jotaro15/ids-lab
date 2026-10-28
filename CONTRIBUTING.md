# Contributing to ids-lab

This is a personal project, but it is run the way a team project would be, and the same rules apply to everyone who touches it, including me. Issues and pull requests are welcome.

## Setting up

You need Python 3.11 or newer. Docker is only needed for the lab itself, which arrives in a later release.

```bash
git clone https://github.com/Azoor/ids-lab.git
cd ids-lab
python -m venv .venv
source .venv/bin/activate        # on Windows PowerShell: .venv\Scripts\Activate.ps1
pip install -e ".[dev]"
pre-commit install
```

## Workflow

1. Pick or open an issue. One issue describes one piece of work.
2. Create a branch from an up-to-date `main`. Nobody commits to `main` directly, and the pre-commit hook refuses it.
3. Make small commits, push, and open a pull request. A draft is fine while the work is in progress.
4. Wait for CI to pass, then squash and merge. The branch is deleted automatically.

### Branch names

`type/short-description`, in lowercase, with hyphens between words.

| Type | Use it for |
| --- | --- |
| `feature` | New behaviour |
| `fix` | A bug fix |
| `docs` | Documentation only |
| `chore` | Tooling, CI, dependencies, repository upkeep |
| `refactor` | Restructuring without changing behaviour |
| `test` | Tests only |

Examples: `feature/rule-engine`, `fix/pcap-truncated-packet`, `docs/lab-safety`.

### Commit messages and pull request titles

Both follow [Conventional Commits](https://www.conventionalcommits.org/): `type: short summary in the imperative`, for example `feat: add port scan rule`. The pull request title becomes the commit message on `main`, so write it with care. Use the same types as above, with `feat` instead of `feature`.

## Before you open a pull request

```bash
pre-commit run --all-files
mypy
pytest
```

CI runs the same checks on Python 3.11 and 3.12, plus `bandit`, `pip-audit` and `gitleaks`. A pull request is ready when all of them pass.

## Code guidelines

- The code, comments, documentation and commit messages are in English.
- Public functions and classes have type hints and a short Google-style docstring. `mypy` runs in strict mode.
- Comments explain why something is done, not what the line does.
- New behaviour comes with tests. Tests that need Docker are marked `integration` and are skipped by default.
- No dead code, no commented-out code, no unused dependencies. If something is not used, it is removed.
- Dependencies are added to `pyproject.toml` with a reason in the pull request description.

## Safety rules for a project that generates attacks

- Scenarios may only target addresses inside the lab network. Do not weaken or bypass the target check.
- Do not commit captures, trained models, credentials or tokens. `data/` and `models/` are ignored on purpose.
- Do not mount the Docker socket into a container or add Linux capabilities without a documented reason.

## Reporting a security problem

Please do not open a public issue. Follow the steps in [SECURITY.md](SECURITY.md).
