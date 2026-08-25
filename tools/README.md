# Tools

Python CLIs live in the `cybergrok` package (`python/cybergrok/`) and are
installed onto PATH by `./setup.sh` / `pip install -e .`.

| Command | Module |
| :--- | :--- |
| `smart_pipe` | `cybergrok.stream` |
| `secret_scan` | `cybergrok.secrets` |
| `search_knowledge` | `cybergrok.search` |
| `aggregate_reports` | `cybergrok.report` |

`update_tools.sh` / `update_tools.ps1` download ProjectDiscovery binaries into
`tools/bin/` (gitignored). Wordlists stay in `tools/wordlists/`.
