# CodeForesight Implementation

This folder contains the initial implementation scaffolding for the
three-stage security analysis system.

## Quick start

1. Ensure Python 3.10+ is installed.
2. From this directory, set the module path and run the CLI:

```
set PYTHONPATH=src
python -m codeforesight.cli --input "path/to/file.py" --pretty
```


### LLM explanations (Groq)

Set your Groq API key in the environment:

```
set GROQ_API_KEY=your_key_here
```

Run with explanations:

```
python -m codeforesight.cli --input "path/to/file.py" --pretty --explain
```

### LLM-only mode

Use LLM-only analysis (skips rule/ML detection):

```
python -m codeforesight.cli --input "path/to/file.py" --pretty --explain --llm-only
```

### Stage 1 only output

Return only Stage 1 results:

```
python -m codeforesight.cli --input "path/to/file.py" --pretty --explain --stage1-only
```

### Stage 2 only output

Return only Stage 2 results:

```
python -m codeforesight.cli --input "path/to/file.py" --pretty --explain --stage2-only
```

### Short aliases

```
python -m codeforesight.cli --input "path/to/file.py" --pretty --explain --stage1
python -m codeforesight.cli --input "path/to/file.py" --pretty --explain --stage2
```

### Stage 3 only output

```
python -m codeforesight.cli --input "path/to/file.py" --pretty --explain --stage3-only
```

Alias:

```
python -m codeforesight.cli --input "path/to/file.py" --pretty --explain --stage3
```

## Data location

By default, the code expects the dataset folder at the workspace root:
`../data/` relative to this project directory.

You can override this with:

```
set CODEFORESIGHT_DATA_DIR=C:\path\to\data
```

## Scripts

Run the optional preprocessing scripts:

```
python scripts/build_cve_index.py
python scripts/build_curated_manifest.py
python scripts/expand_curated_pairs.py --max 50
python scripts/train_stage1_model.py
python scripts/train_stage3_temporal.py
python scripts/evaluate_stage1_model.py
```

## Jenkins demo pipeline

This repo includes a `Jenkinsfile` that implements a gated pipeline:

1) Stage 1 blocks the build if known vulnerabilities are found.  
2) Stage 2 blocks the build if unknown vulnerabilities are found.  
3) Stage 3 generates a future-risk report.

Required Jenkins setup:

- Define a pipeline job that uses this `Jenkinsfile`.
- Provide the Groq API key as an environment variable (`GROQ_API_KEY`).
- Run once: `python scripts/train_stage3_temporal.py` (temporal model).

The pipeline uses `scripts/ci_stage_gate.py` to run each gate and write
JSON reports into `ci_reports/` as build artifacts.
"# CodeForesight" 
