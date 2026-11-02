#!/usr/bin/env python3
"""
Digital Forensics Investigation Tool
====================================
For digital evidence analysis:
  - Compute cryptographic hashes (MD5, SHA-256) of files
  - Extract file metadata (size, timestamps, type; EXIF for images
    when Pillow is installed)
  - Build an integrity manifest of a directory and verify it later
    to detect tampering (changed / missing / new files)
  - Produce a JSON evidence report for a file or a whole directory

Built by Muhammad Mansoor — November 2026
Self-directed cybersecurity learning project (demo/educational use).
Standard library only (Pillow optional, for EXIF extraction).
"""

import argparse
import hashlib
import json
import mimetypes
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

CHUNK_SIZE = 65536


def _hash_file(path, algo):
    h = hashlib.new(algo)
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(CHUNK_SIZE), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_of(path):
    return _hash_file(path, "sha256")


def md5_of(path):
    return _hash_file(path, "md5")


def utc_iso(ts):
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def file_metadata(path):
    """Collect hashes + metadata for a single file (the evidence record)."""
    p = Path(path)
    st = p.stat()
    meta = {
        "path": str(p),
        "name": p.name,
        "size_bytes": st.st_size,
        "mime_type": mimetypes.guess_type(str(p))[0],
        "created_utc": utc_iso(st.st_ctime),
        "modified_utc": utc_iso(st.st_mtime),
        "sha256": sha256_of(p),
        "md5": md5_of(p),
    }
    # EXIF metadata for images, only if Pillow is available.
    try:
        from PIL import Image
        from PIL.ExifTags import TAGS
        if (meta["mime_type"] or "").startswith("image/"):
            with Image.open(p) as img:
                meta["image_dimensions"] = f"{img.width}x{img.height}"
                exif = img.getexif()
                if exif:
                    meta["exif"] = {TAGS.get(k, k): str(v) for k, v in exif.items()}
    except ImportError:
        pass
    return meta


def iter_files(directory):
    """Yield all regular files under a directory (sorted, deterministic)."""
    root = Path(directory)
    return sorted(
        (p for p in root.rglob("*") if p.is_file()),
        key=lambda p: str(p),
    )


def create_manifest(directory, output):
    """Hash every file under DIRECTORY and save the manifest as JSON."""
    directory = Path(directory)
    entries = {}
    for p in iter_files(directory):
        rel = str(p.relative_to(directory))
        entries[rel] = {
            "sha256": sha256_of(p),
            "md5": md5_of(p),
            "size_bytes": p.stat().st_size,
        }
    manifest = {
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "directory": str(directory),
        "files": entries,
    }
    Path(output).write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"Manifest created: {len(entries)} files -> {output}")
    return manifest


def verify_manifest(directory, manifest_path):
    """Re-hash DIRECTORY and compare against a saved manifest."""
    directory = Path(directory)
    manifest = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    recorded = manifest["files"]

    current = {}
    for p in iter_files(directory):
        rel = str(p.relative_to(directory))
        current[rel] = sha256_of(p)

    ok, changed, missing, new = [], [], [], []
    for rel, info in recorded.items():
        if rel not in current:
            missing.append(rel)
        elif current[rel] != info["sha256"]:
            changed.append(rel)
        else:
            ok.append(rel)
    for rel in current:
        if rel not in recorded:
            new.append(rel)

    result = {"ok": ok, "changed": changed, "missing": missing, "new": new}
    print(f"Verified {len(recorded)} recorded files against {directory}:")
    print(f"  Unchanged : {len(ok)}")
    print(f"  Changed   : {len(changed)}")
    for r in changed:
        print(f"    ! {r}")
    print(f"  Missing   : {len(missing)}")
    for r in missing:
        print(f"    - {r}")
    print(f"  New       : {len(new)}")
    for r in new:
        print(f"    + {r}")
    if not changed and not missing:
        print("\nIntegrity check PASSED — no tampering detected.")
    else:
        print("\nIntegrity check FAILED — evidence may have been tampered with.")
    return result


def evidence_report(target, output):
    """Write a JSON evidence report for one file or a whole directory."""
    target = Path(target)
    if target.is_file():
        items = [file_metadata(target)]
    else:
        items = [file_metadata(p) for p in iter_files(target)]
    report = {
        "tool": "Digital Forensics Investigation Tool",
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "target": str(target),
        "item_count": len(items),
        "items": items,
    }
    Path(output).write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"Evidence report: {len(items)} item(s) -> {output}")
    return report


def main():
    parser = argparse.ArgumentParser(description="Digital Forensics Investigation Tool")
    sub = parser.add_subparsers(dest="command", required=True)

    p_hash = sub.add_parser("hash", help="Print MD5 + SHA-256 of a file")
    p_hash.add_argument("file")

    p_meta = sub.add_parser("metadata", help="Show metadata + hashes of a file")
    p_meta.add_argument("file")

    p_mc = sub.add_parser("manifest-create", help="Create an integrity manifest of a directory")
    p_mc.add_argument("directory")
    p_mc.add_argument("-o", "--output", default="manifest.json")

    p_mv = sub.add_parser("manifest-verify", help="Verify a directory against a manifest")
    p_mv.add_argument("directory")
    p_mv.add_argument("manifest")

    p_rep = sub.add_parser("report", help="Write a JSON evidence report")
    p_rep.add_argument("target", help="File or directory to document")
    p_rep.add_argument("-o", "--output", default="evidence_report.json")

    args = parser.parse_args()

    if args.command == "hash":
        print(f"MD5    : {md5_of(args.file)}")
        print(f"SHA-256: {sha256_of(args.file)}")
    elif args.command == "metadata":
        print(json.dumps(file_metadata(args.file), indent=2))
    elif args.command == "manifest-create":
        create_manifest(args.directory, args.output)
    elif args.command == "manifest-verify":
        result = verify_manifest(args.directory, args.manifest)
        sys.exit(1 if (result["changed"] or result["missing"]) else 0)
    elif args.command == "report":
        evidence_report(args.target, args.output)


if __name__ == "__main__":
    main()
