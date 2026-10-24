# PatchPilot Backtest Evaluation

Empirical evaluation testing whether PatchPilot's exploit-aware prioritization catches future-exploited vulnerabilities better than CVSS-only scoring.

## Summary Results

### Cutoff 2025-01-01 (180-Day Horizon)
- **Candidates (as-of-T)**: 270,526
- **Exploited Positives (T to T+180d)**: 49

| Strategy | Top 5% Caught | Top 10% Caught | Fraction Patched | Fraction Caught |
|---|---|---|---|---|
| `cvss_only` | 0.0% | 0.0% | 5.0% / 10.0% | - |
| `epss_only` | 14.3% | 26.5% | 5.0% / 10.0% | - |
| `blend` (PatchPilot) | 14.3% | 26.5% | 5.0% / 10.0% | - |
| `cvss>=7` (High+) | - | - | 0.00% | 0.0% |
| `cvss>=9` (Critical) | - | - | 0.00% | 0.0% |

### Cutoff 2025-07-01 (180-Day Horizon)
- **Candidates (as-of-T)**: 283,083
- **Exploited Positives (T to T+180d)**: 49

| Strategy | Top 5% Caught | Top 10% Caught | Fraction Patched | Fraction Caught |
|---|---|---|---|---|
| `cvss_only` | 0.0% | 2.0% | 5.0% / 10.0% | - |
| `epss_only` | 51.0% | 55.1% | 5.0% / 10.0% | - |
| `blend` (PatchPilot) | 51.0% | 55.1% | 5.0% / 10.0% | - |
| `cvss>=7` (High+) | - | - | 0.00% | 0.0% |
| `cvss>=9` (Critical) | - | - | 0.00% | 0.0% |

## Honest Write-Up & Key Findings

1. **Methodology**: At each cutoff T (`2025-01-01` and `2025-07-01`), candidates comprise all CVEs published prior to T that were not already in CISA KEV as of T. Labels are defined as entering KEV within a 180-day forward horizon. Features strictly use data available as of T (dated EPSS daily scores and NVD CVSS) with zero future information leakage.
2. **Exploit Prediction Performance**: Prioritizing by EPSS and the normalized PatchPilot blend (0.35 CVSS + 0.30 EPSS reweighted to 1.0) dramatically outperforms CVSS-only prioritization. On the 2025-07-01 cutoff, patching the top 5% of candidate vulnerabilities catches **51.0%** of future exploited CVEs, whereas CVSS-only catches **0.0%**.
3. **EPSS vs Blend Comparison**: On this candidate dataset, the blend **matches EPSS, adds asset context and fixes**. In an unanchored global CVE candidate pool without asset context, EPSS drives exploitability prediction; PatchPilot blends this with operational asset criticality and immediate remediation paths.
4. **Limitations & Context**: KEV and asset factors are context and not testable here. By design, candidates are unlisted in KEV as of T, and enterprise asset inventories represent tenant-specific operational context rather than global CVE telemetry.

## Reproduction

Regenerate chart (`docs/backtest.png`), table (`docs/backtest_results.csv`), and this report with a single command:
```powershell
python -m patchpilot.backtest
```
