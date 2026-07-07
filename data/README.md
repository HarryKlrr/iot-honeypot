# Data

Cowrie capture data consumed by the analysis pipeline.

## Record schema (Cowrie JSON)

Each line is a JSON object. Fields used by the analyser:

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

A short example log demonstrating the record structure is in [`sample/cowrie_sample.json`](sample/cowrie_sample.json).
