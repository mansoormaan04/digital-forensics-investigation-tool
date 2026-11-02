# Digital Forensics Investigation Tool

A command-line tool for basic digital evidence analysis: file hashing, metadata extraction, integrity verification, and evidence reporting.

Built by **Muhammad Mansoor** — November 2026, as a self-directed cybersecurity learning project.

## Features

- **Cryptographic hashing** — MD5 + SHA-256 of any file (streamed, works on large files)
- **Metadata extraction** — size, MIME type, created/modified timestamps (UTC), plus EXIF data for images when Pillow is installed
- **Integrity manifests** — snapshot a directory's hashes, then verify later to detect **changed**, **missing**, or **new** files (tamper detection)
- **Evidence reports** — machine-readable JSON report for a file or a whole directory, with generation timestamp

## Requirements

Python 3.8+. Standard library only — no installation needed. (Optional: `pip install Pillow` for image EXIF extraction.)

## Usage

Hash a file:

```bash
python forensics.py hash document.pdf
```

Show full metadata + hashes:

```bash
python forensics.py metadata photo.jpg
```

Create an integrity manifest of an evidence folder:

```bash
python forensics.py manifest-create ./evidence -o manifest.json
```

Later, verify nothing was tampered with:

```bash
python forensics.py manifest-verify ./evidence manifest.json
```

Write a JSON evidence report:

```bash
python forensics.py report ./evidence -o evidence_report.json
```

## Example: tamper detection

```bash
$ python forensics.py manifest-create ./evidence -o manifest.json
Manifest created: 3 files -> manifest.json

$ echo "edited" >> ./evidence/note.txt
$ python forensics.py manifest-verify ./evidence manifest.json
Verified 3 recorded files against ./evidence:
  Unchanged : 2
  Changed   : 1
    ! note.txt
  Missing   : 0
  New       : 0

Integrity check FAILED — evidence may have been tampered with.
```

## How it works

1. **Hashing** reads files in 64 KB chunks through `hashlib`, so even large files are hashed without loading them fully into memory.
2. **Metadata** comes from the filesystem (`os.stat`) plus MIME-type guessing; image EXIF tags are read with Pillow when available.
3. **Manifests** store `{relative_path: {sha256, md5, size}}` as JSON. Verification re-hashes everything and classifies each file as unchanged, changed, missing, or new.
4. All timestamps are recorded in UTC (ISO 8601) so reports are timezone-unambiguous — standard practice for evidence handling.

## Limitations

This is a learning/demo project, not a certified forensic suite. It does not do disk imaging, deleted-file recovery, or write-blocking. Hashes prove a file hasn't changed since the manifest was made — they say nothing about a file's origin or authenticity before that point.
