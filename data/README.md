# Data

This directory holds the Cowrie capture data consumed by the analysis pipeline.

## Expected files

| File | Description |
|---|---|
| `cowrie.json` | Your real Cowrie capture (line-delimited JSON). **Not committed** — see note below. |
| `sample/cowrie_sample.json` | A small **synthetic** sample committed for reproducibility so reviewers can run the pipeline without the full dataset. |

## Record schema (Cowrie JSON)

Each line is a JSON object. The fields used by the analyser:

```json
{
  "eventid": "cowrie.login.failed",
  "timestamp": "2026-03-14T09:12:04.512Z",
  "username": "root",
  "password": "xc3511",
  "src_ip": "192.168.56.20",
  "session": "a1b2c3d4"
}
```

Relevant `eventid` values: `cowrie.login.failed`, `cowrie.login.success`, `cowrie.session.connect`, `cowrie.command.input`, `cowrie.session.file_download`.

## Sanitisation policy

Real captures may contain source IP addresses. Before committing any real data:

- Confirm the data contains **no live host-identifying information** you do not wish to publish.
- The repository `.gitignore` excludes `data/*.json` by default (the synthetic sample is whitelisted). Commit real captures only deliberately and after review.

## Running the analyser against your data

```bash
# point the script's input filename(s) at your capture, then:
python3 ../analysis/enhanced_credential_analyzer.py
```
