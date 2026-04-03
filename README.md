# tmxcaliber

`tmxcaliber` is a command-line toolkit for refining, querying, and transforming TrustOnCloud ThreatModels. It helps engineers work with large model files more efficiently by filtering JSON, exporting threats and controls, mapping control objectives to frameworks, generating DFD artifacts, and comparing model versions without writing custom scripts for each task.

## Highlights

- Filter ThreatModel JSON files by IDs, severity, IAM permissions, and events.
- List threats, controls, services, and feature classes from a single model or an entire directory.
- Map control objectives to SCF-supported frameworks or your own custom framework.
- Write mapping data back into a ThreatModel JSON.
- Generate threat-focused and feature-class-focused DFD XML and PNG outputs.
- Create structured change logs in JSON or Markdown.
- Scan control descriptions with regex patterns or the built-in `guardduty_findings` alias.

## Quickstart

`tmxcaliber` supports Python `3.8+`.

```sh
git clone https://github.com/trustoncloud/tmxcaliber.git
cd tmxcaliber
python -m venv .venv
```

Activate the environment:

```sh
# PowerShell
.venv\Scripts\Activate.ps1

# bash / zsh
source .venv/bin/activate
```

Install and verify:

```sh
pip install .
tmxcaliber -h
```

First commands to try:

```sh
tmxcaliber list threats path/to/threatmodel.json
tmxcaliber filter path/to/threatmodel.json --severity high --output filtered.json
tmxcaliber map path/to/threatmodel.json --scf 2025.3.1 --framework-name "NIST CSF v2.0"
```

## Installation

### Install from source

This is the recommended setup for most users and contributors:

```sh
git clone https://github.com/trustoncloud/tmxcaliber.git
cd tmxcaliber
python -m venv .venv
pip install .
```

### Install a tagged release

To install a specific release directly from Git:

```sh
pip install "git+https://github.com/trustoncloud/tmxcaliber.git@{VERSION_TAG}"
```

### Docker

The repository includes a Dockerfile for containerized use:

```sh
docker build -t tmxcaliber .
docker run --rm -it tmxcaliber -h
```

### Requirement note for `generate`

The `generate` command depends on `drawio`. If the binary is not automatically detected, provide it explicitly with `--bin`.

## Command Overview

| Command | Purpose | Typical output |
| --- | --- | --- |
| `filter` | Produce a refined ThreatModel JSON based on filters. | JSON |
| `list threats` | Export threat rows from one model or a directory. | CSV |
| `list controls` | Export control rows from one model or a directory. | CSV |
| `list services` | List service names and their source files. | CSV or JSON |
| `list feature-classes` | Inspect feature classes in a single ThreatModel. | CSV or JSON |
| `map` | Generate a framework mapping from ThreatModel control objectives. | CSV or JSON |
| `add-mapping` | Insert mapping data into the ThreatModel JSON. | JSON |
| `scan` | Find controls whose descriptions match a pattern. | JSON |
| `generate` | Generate XML and PNG DFD artifacts. | Files on disk |
| `create-change-log` | Compare two ThreatModels and summarize differences. | JSON or Markdown |

## Core Workflows

### Filter a ThreatModel

Use `filter` when you want a refined ThreatModel JSON as the output.

```sh
tmxcaliber filter path/to/threatmodel.json \
  --severity high \
  --output filtered.json
```

Create a filtered file and a companion file containing everything removed:

```sh
tmxcaliber filter path/to/threatmodel.json \
  --permissions s3:GetObject \
  --output filtered.json \
  --output-removed
```

Use `--exclude` to invert an ID-based filter:

```sh
tmxcaliber filter path/to/threatmodel.json \
  --ids S3.T12,S3.CO1 \
  --exclude \
  --output filtered.json
```

### List threats and controls

List threats from a single model:

```sh
tmxcaliber list threats path/to/threatmodel.json
```

List only high and very-high severity threats from a directory:

```sh
tmxcaliber list threats path/to/threatmodels \
  --severity high \
  --output threats.csv
```

List controls from a directory:

```sh
tmxcaliber list controls path/to/threatmodels --output controls.csv
```

List only AWS data perimeter controls:

```sh
tmxcaliber list controls path/to/threatmodels \
  --type AWS_DATA_PERIMETER \
  --output perimeter_controls.csv
```

List services across a directory of models:

```sh
tmxcaliber list services path/to/threatmodels --format json
```

List feature classes from a single ThreatModel:

```sh
tmxcaliber list feature-classes path/to/threatmodel.json
```

### Map to a supported or custom framework

Generate a mapping to an SCF-supported framework:

```sh
tmxcaliber map path/to/threatmodel.json \
  --scf 2025.3.1 \
  --framework-name "ISO 27001 v2013" \
  --format csv
```

Use the exact framework name from the selected SCF version header when targeting a built-in framework.

Generate a mapping to your own framework using the starter CSVs in [`template/`](template):

```sh
tmxcaliber map path/to/threatmodel.json \
  --scf 2025.3.1 \
  --framework-name "My Framework" \
  --framework-map template/myframework.csv \
  --framework-metadata template/mymetadata.csv \
  --format json
```

### Add mapping data back into a ThreatModel

If you want the mapping persisted directly into the ThreatModel output:

```sh
tmxcaliber add-mapping path/to/threatmodel.json \
  --scf 2025.3.1 \
  --framework-name "My Framework" \
  --framework-map template/myframework.csv \
  --framework-metadata template/mymetadata.csv \
  --output enriched-threatmodel.json
```

### Generate DFD artifacts

`generate` accepts either:

- a ThreatModel JSON containing base64-encoded XML in `dfd.body`
- a raw XML file from the main ThreatModel DFD

Generate XML and PNG outputs from JSON:

```sh
tmxcaliber generate path/to/threatmodel.json \
  --threat-dir out/threat-xml \
  --fc-dir out/feature-class-xml \
  --out-dir out/png
```

Generate from XML with an explicit `drawio` binary:

```sh
tmxcaliber generate path/to/provider_service_DFD.xml \
  --bin "C:\Program Files\draw.io\draw.io.exe" \
  --out-dir out/png
```

### Scan control descriptions

Search control descriptions with a regex:

```sh
tmxcaliber scan path/to/threatmodel.json --pattern UnauthorizedAccess
```

Use the built-in GuardDuty findings alias:

```sh
tmxcaliber scan path/to/threatmodel.json --pattern guardduty_findings
```

### Create change logs

Compare two ThreatModel versions and output JSON:

```sh
tmxcaliber create-change-log path/to/new_tm.json path/to/old_tm.json
```

Generate a Markdown report:

```sh
tmxcaliber create-change-log path/to/new_tm.json path/to/old_tm.json \
  --format md \
  --output changes.md
```

You can also scope the comparison to specific IDs and invert the selection with `--exclude`.

## Common Examples

```sh
# List all threats across a directory
tmxcaliber list threats path/to/threatmodels

# Keep only specific controls and objectives in a filtered JSON
tmxcaliber filter path/to/threatmodel.json --ids S3.C12,S3.CO5 --output filtered.json

# Exclude known noisy threats from a threat export
tmxcaliber list threats path/to/threatmodel.json --ids S3.T2,S3.T9 --exclude

# Export services for inventory or reporting
tmxcaliber list services path/to/threatmodels --output services.csv

# Produce a custom-framework mapping
tmxcaliber map path/to/threatmodel.json --scf 2025.3.1 --framework-name "My Framework" --framework-map template/myframework.csv

# Create a Markdown change log between releases
tmxcaliber create-change-log new.json old.json --format md --output changes.md
```

## Help Reference

Use the built-in help to inspect the full CLI surface:

```sh
tmxcaliber -h
tmxcaliber filter -h
tmxcaliber map -h
tmxcaliber add-mapping -h
tmxcaliber scan -h
tmxcaliber generate -h
tmxcaliber list threats -h
tmxcaliber list controls -h
tmxcaliber list services -h
tmxcaliber list feature-classes -h
tmxcaliber create-change-log -h
```

## Development

Set up a local development environment:

```sh
python -m venv .venv
pip install -r requirements.txt
pip install -e .
```

Run the test suite:

```sh
pytest -q test
```

## Contributing

Contributions are welcome. If you want to improve the CLI, add tests, or extend the documentation, open an issue or submit a pull request with a clear description of the change and its intended user impact.
