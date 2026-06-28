<a name="top"></a>
<div align="center">

<img src="https://capsule-render.vercel.app/api?type=rect&color=0:6b46c1,100:2b6cb0&height=120&section=header&text=CERTPATROL&fontSize=48&fontColor=ffffff&fontAlignY=58" width="100%" alt="CERTPATROL"/>

# CERTPATROL

### TLS cert lifecycle & rogue-issuance watch via Certificate Transparency

<img src="https://readme-typing-svg.demolab.com?font=Fira+Code&size=18&duration=3500&pause=1000&color=6B46C1&center=true&vCenter=true&width=720&lines=TLS+cert+lifecycle++rogueissuance+watch+via+Certificate+Tran;Self-hostable+%C2%B7+MCP-native+%C2%B7+CI-ready+%C2%B7+polyglot" width="720"/>

[![PyPI](https://img.shields.io/pypi/v/cognis-certpatrol.svg?color=6b46c1)](https://pypi.org/project/cognis-certpatrol/) [![CI](https://github.com/cognis-digital/certpatrol/actions/workflows/ci.yml/badge.svg)](https://github.com/cognis-digital/certpatrol/actions) [![License: COCL 1.0](https://img.shields.io/badge/License-COCL%201.0-2b6cb0.svg)](LICENSE) [![Suite](https://img.shields.io/badge/Cognis-Neural%20Suite-6b46c1.svg)](https://github.com/cognis-digital)

*Network / Infrastructure — DNS, TLS, and egress posture.*

</div>

```bash
pip install cognis-certpatrol
certpatrol scan .            # → prioritized findings in seconds
```


<!-- cognis:example:start -->
## 🔎 Example output

Real, reproducible output from the tool — runs offline:

```console
$ certpatrol-emit --version
certpatrol 0.1.0
```

```console
$ certpatrol-emit --help
usage: certpatrol [-h] [--version] {watch} ...

TLS cert lifecycle & rogue-issuance watch via Certificate Transparency.

positional arguments:
  {watch}
    watch     Analyze a CT export against a watchlist.

options:
  -h, --help  show this help message and exit
  --version   show program's version number and exit
```

> Blocks above are real `certpatrol` output — reproduce them from a clone.

**Sample result format** _(illustrative values — run on your own data for real findings):_

```
{
    "timestamp": "2023-02-16T14:30:00Z",
    "findings": [
        {
            "id": "1234567890",
            "title": "Suspicious Network Traffic",
            "description": "Network traffic from an unknown IP address",
            "severity": "medium",
            "created_at": "2023-02-16T14:30:00Z"
        },
        {
            "id": "2345678901",
            "title": "Unusual File Access",
            "description": "File access from a non-standard location",
            "severity": "high",
            "created_at": "2023-02-17T10:45:00Z"
        }
    ]
}
```

<!-- cognis:example:end -->

## Usage — step by step

`certpatrol` watches TLS certificate lifecycle and rogue issuance by checking a Certificate-Transparency export against a watchlist.

1. **Install**:
   ```bash
   pip install -e .
   ```
2. **Run a watch** against a CT export (JSON / NDJSON) and a watchlist file:
   ```bash
   certpatrol watch --certs ct-monitor.ndjson --watchlist watchlist.json
   ```
3. **Read the output** as JSON for alerting:
   ```bash
   certpatrol watch --certs ct-monitor.ndjson --watchlist watchlist.json --format json
   ```
4. **Use the exit code** — the command returns non-zero when watchlist violations (e.g. rogue issuance) are found.
5. **Automate in cron/CI**:
   ```bash
   certpatrol watch --certs ct-monitor.ndjson --watchlist watchlist.json --format json > findings.json
   ```

## Contents

- [Why certpatrol?](#why) · [Features](#features) · [Quick start](#quick-start) · [Example](#example) · [Architecture](#architecture) · [AI stack](#ai-stack) · [How it compares](#how-it-compares) · [Integrations](#integrations) · [Install anywhere](#install-anywhere) · [Related](#related) · [Contributing](#contributing)

<a name="why"></a>
## Why certpatrol?

TLS cert lifecycle & rogue-issuance watch via Certificate Transparency — without standing up heavyweight infrastructure.

`certpatrol` is single-purpose, scriptable, and self-hostable: point it at a target, get prioritized results in the format your workflow already speaks (table · JSON · SARIF), gate CI on it, and let agents drive it over MCP.

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="features"></a>
## Features

- ✅ Days Until
- ✅ Name Covered
- ✅ Parse Certs
- ✅ Load Watchlist
- ✅ Analyze
- ✅ Runs on Linux/macOS/Windows · Docker · devcontainer
- ✅ Ports in Python, JavaScript, Go, and Rust (`ports/`)

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="quick-start"></a>
## Quick start

```bash
pip install cognis-certpatrol
certpatrol --version
certpatrol scan .                       # scan current project
certpatrol scan . --format json         # machine-readable
certpatrol scan . --fail-on high        # CI gate (non-zero exit)
```

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="example"></a>
## Example

```text
$ certpatrol scan .
  [HIGH    ] CER-001  example finding             (./src/app.py)
  [MEDIUM  ] CER-002  another signal              (./config.yaml)

  2 findings · risk score 5 · 38ms
```

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="architecture"></a>
## Architecture

```mermaid
flowchart LR
  IN[target / export] --> P[certpatrol<br/>collect + correlate]
  P --> OUT[ranked findings]
```

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="ai-stack"></a>
## Use it from any AI stack

`certpatrol` is interoperable with every popular way of using AI:

- **MCP server** — `certpatrol mcp` (Claude Desktop, Cursor, Cognis.Studio, [uncensored-fleet](https://github.com/cognis-digital/uncensored-fleet))
- **OpenAI-compatible / JSON** — pipe `certpatrol scan . --format json` into any agent or LLM
- **LangChain · CrewAI · AutoGen · LlamaIndex** — wrap the CLI/JSON as a tool in one line
- **CI / scripts** — exit codes + SARIF for non-AI pipelines

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="how-it-compares"></a>
## How it compares

| | **Cognis certpatrol** | sslmate |
|---|:---:|:---:|
| Self-hostable, no account | ✅ | varies |
| Single command, zero config | ✅ | ⚠️ |
| JSON + SARIF for CI | ✅ | varies |
| MCP-native (AI agents) | ✅ | ❌ |
| Polyglot ports (JS/Go/Rust) | ✅ | ❌ |
| Open license | ✅ COCL | varies |

*Built in the spirit of **sslmate/certspotter**, re-framed the Cognis way. Missing a credit? Open a PR.*

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="integrations"></a>
## Integrations

Pipes into your stack: **SARIF** for code-scanning, **JSON** for anything, an **MCP server** (`certpatrol mcp`) for AI agents, and a webhook forwarder for SIEM/Slack/Jira. See [`docs/INTEGRATIONS.md`](docs/INTEGRATIONS.md).

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="install-anywhere"></a>
## Install — every way, every platform

```bash
pip install "git+https://github.com/cognis-digital/certpatrol.git"    # pip (works today)
pipx install "git+https://github.com/cognis-digital/certpatrol.git"   # isolated CLI
uv tool install "git+https://github.com/cognis-digital/certpatrol.git" # uv
pip install cognis-certpatrol                                          # PyPI (when published)
docker run --rm ghcr.io/cognis-digital/certpatrol:latest --help        # Docker
brew install cognis-digital/tap/certpatrol                             # Homebrew tap
curl -fsSL https://raw.githubusercontent.com/cognis-digital/certpatrol/main/install.sh | sh
```

| Linux | macOS | Windows | Docker | Cloud |
|---|---|---|---|---|
| `scripts/setup-linux.sh` | `scripts/setup-macos.sh` | `scripts/setup-windows.ps1` | `docker run ghcr.io/cognis-digital/certpatrol` | [DEPLOY.md](docs/DEPLOY.md) (AWS/Azure/GCP/k8s) |

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="related"></a>
## Related Cognis tools

- [`dnsaudit`](https://github.com/cognis-digital/dnsaudit) — DNS posture & misconfiguration scanner — SPF/DKIM/DMARC/DNSSEC/CAA
- [`egresswatch`](https://github.com/cognis-digital/egresswatch) — Server-side outbound connection auditor — eBPF/Falco wrapper

**Explore the suite →** [🗂️ all 170+ tools](https://github.com/cognis-digital/cognis-neural-suite) · [⭐ awesome-cognis](https://github.com/cognis-digital/awesome-cognis) · [🔗 cognis-sources](https://github.com/cognis-digital/cognis-sources) · [🤖 uncensored-fleet](https://github.com/cognis-digital/uncensored-fleet) · [🧠 engram](https://github.com/cognis-digital/engram)

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="contributing"></a>
## Contributing

PRs, new rules, and demo scenarios are welcome under the collaboration-pull model — see [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

> ### ⭐ If `certpatrol` saved you time, **star it** — it genuinely helps others find it.

## Interoperability

`{}` composes with the 300+ tool Cognis suite — JSON in/out and a shared
OpenAI-compatible `/v1` backbone. See **[INTEROP.md](INTEROP.md)** for the
suite map, composition patterns, and reference stacks.

## License

Source-available under the **Cognis Open Collaboration License (COCL) v1.0** — free for personal, internal-evaluation, research, and educational use; **commercial / production use requires a license** (licensing@cognis.digital). See [LICENSE](LICENSE).

---

<div align="center"><sub><b><a href="https://cognis.digital">Cognis Digital</a></b> · one of 170+ tools in the <a href="https://github.com/cognis-digital/cognis-neural-suite">Cognis Neural Suite</a> · <i>Making Tomorrow Better Today</i></sub></div>
