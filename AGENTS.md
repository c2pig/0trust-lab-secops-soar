# Agent & Contributor Instructions (`0trust-lab-secops-soar`)

## Two-Way Architecture Diagram Sync (Global <-> Local)

This repository powers **Lab 6 (`Live SecOps Detection & Automated SOAR` — `/secops-soar`)** on [`0trust.dev`](https://github.com/c2pig/0trust.dev/blob/main/docs/ECOSYSTEM_MAP.md), hosted at `https://lab.0trust.dev/secops-soar`.

Whenever you modify code, edge functions, or infrastructure under `src/`, `functions/`, `infra/`, or `.github/workflows/`:
1. **Local Sync**: Update [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) and [`docs/diagrams/secops_soar_architecture.svg`](docs/diagrams/secops_soar_architecture.svg) in the same Pull Request (enforced by [`.github/workflows/diagram-check.yml`](.github/workflows/diagram-check.yml)).
2. **Global Sync**: If public contracts (`lab.manifest.json`, `seats`, `apiEndpoints`, `kvPrefixes`), Sigma rule schemas, or SOAR webhook interfaces change, also update `docs/labs/secops-soar.md`, `docs/diagrams/platform_capability_zoomin.svg`, and `src/contracts/labManifest.ts` in [`c2pig/0trust.dev`](https://github.com/c2pig/0trust.dev).
