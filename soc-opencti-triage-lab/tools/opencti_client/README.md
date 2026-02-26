# OpenCTI Ingestion Client

Push case IOCs (from `iocs.json` or `expected-iocs.json`) into OpenCTI as a Report with observables. Uses the OpenCTI API via `pycti`.

## Setup

```bash
pip install -r requirements.txt
cp config.example.yml config.yml
# Edit config.yml: set opencti.url and opencti.token (from OpenCTI Settings > Access token)
```

## Usage

```bash
# Push case-01 IOCs (auto-discovers expected-iocs.json and alert.json)
python3 push_observables.py --config config.yml --case ../../scenarios/case-01

# Override title and use explicit IOC file
python3 push_observables.py --config config.yml --case ../../scenarios/case-02 --iocs ../../scenarios/case-02/iocs.json --title "LockBit 3.0"
```

Options: `--config`, `--case`, `--iocs`, `--title`, `--description`, `--confidence`, `--label`.
