#!/usr/bin/env python3
import subprocess
import sys
import os
import re

def run(cmd):
    try:
        return subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, text=True)
    except subprocess.CalledProcessError as e:
        return e.output

def write(out, title, content):
    out.write("\n" + "="*80 + "\n")
    out.write(f"== {title}\n")
    out.write("="*80 + "\n")
    out.write(content + "\n\n")

def detect_vulnerabilities(all_data):
    vuln = []

    # --- STACK BUFFER OVERFLOW ---
    bof_patterns = [
        r"gets", r"strcpy", r"strcat", r"sprintf",
        r"strncpy", r"memcpy", r"read\(.*\,.*\, [1-9][0-9]{3,}\)"
    ]
    if any(re.search(p, all_data) for p in bof_patterns):
        vuln.append("🟥 Possible Stack Buffer Overflow")

    # --- FORMAT STRING ---
    if re.search(r"printf\s*\(\s*[a-zA-Z0-9_]+\s*\)", all_data):
        vuln.append("🟥 Possible Format String Vulnerability")

    # --- WIN / BACKDOOR ---
    if "win" in all_data or "/bin/sh" in all_data or "system" in all_data:
        vuln.append("🟧 Suspicious backdoor function (win/system/binsh)")

    # --- HEAP ---
    if "malloc" in all_data or "free" in all_data:
        vuln.append("🟨 Possible Heap Exploitation (malloc/free used)")

    # --- RELRO / GOT ---
    if "No RELRO" in all_data:
        vuln.append("🟧 GOT Overwrite possible (No RELRO)")

    # --- CANARY ---
    if "Canary: No" in all_data or "Canary                        : No" in all_data:
        vuln.append("🟧 No Canary – Overflow easier")

    # --- NX ---
    if "NX: ENABLED" in all_data or "NX                        : Yes" in all_data:
        vuln.append("🟦 NX Enabled – ROP or ret2libc required")

    # --- PIE ---
    if "PIE: No" in all_data or "PIE                        : No" in all_data:
        vuln.append("🟩 PIE disabled – Static addresses → ret2win/ROP easier")

    # --- FORMAT STRING SPECIFIC ---
    if re.search(r"%[0-9]*\$[sdxpn]", all_data):
        vuln.append("🟥 Format String specifiers detected")

    # --- DOUBLE FREE / UAF ---
    if re.search(r"free\s*\(.*\)\s*free\s*\(.*\)", all_data):
        vuln.append("🟥 Potential Double-Free")

    return vuln


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 analyze_binary_v2.py <binary>")
        return

    target = sys.argv[1]
    if not os.path.isfile(target):
        print("File tidak ditemukan:", target)
        return

    output_file = "output_analysis.txt"

    with open(output_file, "w") as out:

        # Collect all text for vulnerability detection
        combined = ""

        sections = [
            ("FILE TYPE", f"file {target}"),
            ("CHECKSEC", f"checksec --file={target}"),
            ("READ ELF", f"readelf -a {target}"),
            ("SYMBOL TABLE", f"readelf -s {target}"),
            ("RELOCATIONS", f"readelf -r {target}"),
            ("DISASSEMBLY", f"objdump -d -M intel {target}"),
            ("STRINGS", f"strings -a {target} | head -n 200"),
            ("LTRACE", f"timeout 3 ltrace ./{target} < /dev/null"),
            ("STRACE", f"timeout 3 strace ./{target} < /dev/null"),
            ("ROP GADGETS", f"ROPgadget --binary {target} 2>/dev/null"),
        ]

        for title, cmd in sections:
            result = run(cmd)
            combined += result
            write(out, title, result)

        # --- vulnerability detection ---
        vuln_list = detect_vulnerabilities(combined)
        vuln_text = "\n".join(vuln_list) if vuln_list else "No obvious vulnerabilities detected."

        write(out, "AUTOMATIC VULNERABILITY ANALYSIS", vuln_text)

    print(f"[✓] Analisis selesai → output disimpan di: {output_file}")
    print("[!] Termasuk deteksi otomatis jenis kerentanan.")


if __name__ == "__main__":
    main()
