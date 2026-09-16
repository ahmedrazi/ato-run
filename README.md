# ATO Run

A terminal game that walks you through the FedRAMP authorization lifecycle: **Prepare → Document → Assess → Authorize → Monitor**.

You play the platform lead at a SaaS company seeking a Moderate authorization. Every decision costs months, money, or agency trust:

- Rev5 or FedRAMP 20x
- How to draw the boundary and whether to inherit controls
- How to build the evidence package
- How to handle 3PAO findings
- Six months of continuous monitoring with remediation deadlines and a significant-change event

> Simplified training model. Remediation windows use the classic Rev5 30/90/180-day timelines, rounded to months. Check [fedramp.gov](https://www.fedramp.gov) for current rules.

## Run it

**Play in the browser:** https://<your-username>.github.io/ato-run/ (the web version lives in `docs/index.html`).

**Download an executable** from the [Releases](../../releases) page. No Python needed.

| OS | File | Run |
|----|------|-----|
| Linux | `ato-run-linux` | `chmod +x ato-run-linux && ./ato-run-linux` |
| macOS | `ato-run-macos` | `chmod +x ato-run-macos && ./ato-run-macos` (first run: right-click → Open, since the binary is unsigned) |
| Windows | `ato-run-windows.exe` | Double-click, or run it from a terminal |

**Or run from source** with Python 3.9 or newer. There are no dependencies.

```bash
python3 ato_run.py
```

Set `NO_COLOR=1` to turn off colors.

## Test

```bash
python3 -m unittest discover -s tests -t .
```

The tests play 500 random games end to end and check the core rules: open highs block authorization, and past-due items are counted once.

## Build and release

- Every push and pull request runs the tests (`.github/workflows/ci.yml`).
- Pushing a tag that starts with `v` builds single-file executables for Linux, macOS, and Windows with PyInstaller, then attaches them to a GitHub Release (`.github/workflows/release.yml`).

```bash
git tag v1.0.0
git push origin v1.0.0
```

To build locally:

```bash
pip install pyinstaller
pyinstaller --onefile --name ato-run ato_run.py   # output in dist/
```

## Repo layout

```
ato_run.py            terminal game
tests/                 unit tests
docs/index.html        web version (GitHub Pages)
linkedin/              carousel PDF and post caption
.github/workflows/     CI and release builds
```

## Author

Razi | [linkedin.com/in/raziahmed](https://www.linkedin.com/in/raziahmed)
