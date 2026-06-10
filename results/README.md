# Results

Generated analysis outputs are written here by
[`../analysis/enhanced_credential_analyzer.py`](../analysis/enhanced_credential_analyzer.py).

Expected artifacts:

| File | Content |
|---|---|
| `credential_analysis_run_1.png` | SSH brute-force dashboard: top usernames, top passwords, success/failure pie, attack timeline, top source IPs, session distribution |
| `web_analysis_run_1.png` | Web-probing dashboard: top paths, HTTP status codes, tool fingerprint (Nikto/Dirb), request timeline, methods, error rate |
| `run_comparison.png` | Side-by-side comparison of capture runs |

> Drop the exported charts from your project (and/or re-run the analyser against
> `data/cowrie.json`) into this folder so they render in the repository.
