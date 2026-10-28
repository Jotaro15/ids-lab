Add this to `pyproject.toml`, right after the `dependencies = [...]` block (same indentation level, top-level table):

```toml
[project.scripts]
idslab = "idslab.cli:main"
```

This registers the `idslab` command, so `pip install -e ".[dev]"` puts it on your PATH.
