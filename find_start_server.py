#!/usr/bin/env python3
import argparse
import contextlib
import io
import json
import re
import sys
from pathlib import Path

import pefile

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from pe_signature_finder import analyze_symbols, format_bytes  # type: ignore

KNOWN_START_SERVER_SIGNATURES = {
    "msedge.dll": bytes.fromhex(
        "41 57 41 56 41 54 56 57 55 53 48 83 EC 50 "
        "44 89 CD 4C 89 C3 48 89 D7 48 89 CE 48 8B 05 9D"
    ),
    "chrome.dll": bytes.fromhex(
        "41 57 41 56 56 57 55 53 48 83 EC 48 "
        "44 89 CD 4D 89 C6 48 89 D3 48 89 CE 48 8B 05 41"
    ),
}


def load_text_section(pe_path: Path):
    pe = pefile.PE(str(pe_path))
    for section in pe.sections:
        name = section.Name.rstrip(b"\x00").decode("ascii", errors="ignore")
        if name == ".text":
            return pe, section, section.get_data()
    raise RuntimeError(f"{pe_path} has no .text section")


def verify_unique(pattern: bytes, haystack: bytes) -> int:
    return len(list(re.finditer(re.escape(pattern), haystack)))


def main():
    parser = argparse.ArgumentParser(
        description="Find StartRemoteDebuggingServer and emit a reusable unique signature."
    )
    parser.add_argument("pe", type=Path, help="Path to chrome.dll/msedge.dll")
    parser.add_argument("pdb", type=Path, nargs="?", help="Optional path to matching PDB")
    args = parser.parse_args()

    pe, _text_section, text_data = load_text_section(args.pe)

    known_sig = KNOWN_START_SERVER_SIGNATURES.get(args.pe.name.lower())
    if known_sig is None:
        raise SystemExit(f"no built-in signature for {args.pe.name}; provide a PDB for ground truth")

    pattern_hits = [m.start() for m in re.finditer(re.escape(known_sig), text_data)]
    if len(pattern_hits) != 1:
        raise SystemExit(f"expected exactly one StartRemoteDebuggingServer signature hit, got {len(pattern_hits)}")

    matched_offset = pattern_hits[0]
    matched_rva = _text_section.VirtualAddress + matched_offset

    output = {
        "binary": str(args.pe),
        "signature_rva": f"0x{matched_rva:08X}",
        "signature_va": f"0x{pe.OPTIONAL_HEADER.ImageBase + matched_rva:016X}",
        "signature_length": len(known_sig),
        "signature_hex": format_bytes(known_sig),
        "text_hits": 1,
    }

    if args.pdb:
        with contextlib.redirect_stderr(io.StringIO()):
            results = list(
                analyze_symbols(
                    str(args.pe),
                    str(args.pdb),
                    "*StartRemoteDebuggingServer*",
                    min_sig=8,
                    max_sig=64,
                )
            )
        good = [r for r in results if r.signature and r.match_count == 1]
        if good:
            result = good[0]
            signature = result.signature
            assert signature is not None
            output["pdb"] = str(args.pdb)
            output["symbol"] = result.symbol.name
            output["pdb_rva"] = f"0x{result.symbol.rva:08X}"
            output["pdb_va"] = f"0x{pe.OPTIONAL_HEADER.ImageBase + result.symbol.rva:016X}"
            output["pdb_signature_hex"] = format_bytes(signature)
            output["pdb_signature_text_hits"] = verify_unique(signature, text_data)
            output["signature_matches_pdb_rva"] = matched_rva == result.symbol.rva

    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
