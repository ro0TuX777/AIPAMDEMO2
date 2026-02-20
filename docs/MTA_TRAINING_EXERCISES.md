## Malware-Traffic-Analysis.net training exercises (local download + training usage)

### What we download
We mirror the **training exercise index**, then for each exercise we download:
- the exercise page HTML
- linked “same-folder” pages (often answer keys / alternate pages like `index2.html`)
- linked assets from the main page (commonly `*.pcap.zip` and “forensic analysis” zip bundles)

Some exercises also link **answer-key ZIPs** (e.g. `*-answers.pdf.zip`) from a linked page
like `page2.html`. To fetch those, enable `--download-linked-answer-assets`.

Download location (local only, ignored by git):
- `finetuning/data/raw/training_exercises/`

### Download command
```bash
python finetuning/download_training_exercises.py --min-year 2014 --sleep 1.0 --max-linked-pages 10
```

To also download answer-key assets referenced from linked pages:

```bash
python finetuning/download_training_exercises.py --min-year 2014 --sleep 1.0 --max-linked-pages 10 --download-linked-answer-assets
```

### Extract PCAPs from downloaded ZIPs
This extracts only `*.pcap` / `*.pcapng` into `.../pcaps/` next to each exercise.

```bash
python finetuning/extract_training_exercise_pcaps.py
```

ZIP passwords commonly used by MTA are tried automatically:
- `infected_YYYYMMDD`
- `infected`

### Recommended best use for model training
Use these exercises primarily for **supervised “incident reasoning”** rather than only
malware-family classification.

1) **PCAP → structured evidence**
   - Run Zeek and/or Suricata over each extracted PCAP.
   - Convert outputs into compact evidence packs (DNS/HTTP/TLS summaries, timelines).

2) **Supervision from exercise Q/A**
   - Build training examples where the input is (questions + evidence), and the output is
     (answer key / analyst conclusion).

3) **Avoid leakage**
   - Hold out a slice of exercises as evaluation-only (e.g., newest 10–15).

4) **Modeling approach**
   - Start with LoRA SFT on Q/A + evidence tasks.
   - Mix with existing TrafficLLM training data to avoid forgetting.

### Safety note
PCAPs and attachments may relate to real malware activity. Handle in an isolated environment.

