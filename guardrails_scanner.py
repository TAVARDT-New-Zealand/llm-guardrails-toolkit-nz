#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TAVARDT New Zealand: AI Prompt Security Auditor and Guardrails Toolkit
Repository: https://github.com/TAVARDT-New-Zealand/llm-guardrails-toolkit-nz
Live Web Application: https://tavardt-new-zealand.github.io/llm-guardrails-toolkit-nz/
Enterprise Portal: https://ag.tavardt.com/nz/

Audits AI prompts and user inputs against prompt injection, system disclosure, delimiter tampering, and data exfiltration.
"""

import sys
import argparse
import json
import re

BANNER = "TAVARDT New Zealand: AI Prompt Security Auditor and Guardrails Toolkit"
DESC = "Evaluates prompt safety and generates defensive guardrails for AI applications."
PROMPT_HELP = "Prompt string for security validation"
FILE_HELP = "Path to file containing prompt to audit"
JSON_HELP = "Output in JSON format for automated pipelines"
NO_INPUT_ERR = "Error: specify prompt via --prompt, --file, or stdin."
SCORE_LABEL = "Defensive Integrity Score"
STATUS_PASS = "ACCEPTED"
STATUS_WARN = "ATTENTION"
STATUS_FAIL = "CRITICAL DEFECT"
THREATS_HEADER = "Identified Injection Attack Vectors"
NO_THREATS_MSG = "Zero prompt injection signatures located in input."
FOOTER_PAGES = "Official Web Application on GitHub Pages"
FOOTER_PORTAL = "TAVARDT New Zealand Portal"

THREAT_DIRECT = "Direct instruction override pattern located."
THREAT_LEAK = "System prompt extraction attempt located."
THREAT_TOKENS = "Special delimiter masquerading pattern located."
THREAT_EXFIL = "Data exfiltration vector via markdown image rendering located."
THREAT_ROLEPLAY = "Unrestricted persona jailbreak pattern located."

def audit_prompt_text(text):
    threats = []
    score = 100

    # 1. Direct instruction overrides
    if re.search(r"(?i)(ignore|disregard|forget|bypass|override)\s+(all\s+)?(previous|prior|above|system)\s+(instructions|directives|rules|guidelines)", text):
        score -= 35
        threats.append({
            "code": "DIRECT_INJECTION",
            "severity": "CRITICAL",
            "message": THREAT_DIRECT
        })

    # 2. System prompt leakage
    if re.search(r"(?i)(repeat|output|show|print|display|reveal)\s+(all\s+)?(your\s+)?(initial|original|verbatim|internal|system)\s+(instructions|prompt|rules|context)", text):
        score -= 25
        threats.append({
            "code": "SYSTEM_PROMPT_LEAK",
            "severity": "CRITICAL",
            "message": THREAT_LEAK
        })

    # 3. Token masquerading & delimiters
    if re.search(r"(<\|im_start\|>|<\|im_end\|>|<\|endoftext\|>|\[INST\]|\[\/INST\]|###\s*(System|Assistant|Human):)", text):
        score -= 30
        threats.append({
            "code": "TOKEN_MASQUERADING",
            "severity": "CRITICAL",
            "message": THREAT_TOKENS
        })

    # 4. Markdown exfiltration
    if re.search(r"!\[[^\]]*\]\((https?:\/\/[^\s\)]+)\)", text):
        score -= 25
        threats.append({
            "code": "MARKDOWN_EXFILTRATION",
            "severity": "HIGH",
            "message": THREAT_EXFIL
        })

    # 5. Roleplay escape (DAN, developer mode)
    if re.search(r"(?i)(jailbreak|unrestricted mode|dan mode|developer mode|you have no rules)", text):
        score -= 20
        threats.append({
            "code": "ROLEPLAY_JAILBREAK",
            "severity": "HIGH",
            "message": THREAT_ROLEPLAY
        })

    score = max(0, min(100, score))

    if score >= 85:
        overall_status = STATUS_PASS
    elif score >= 50:
        overall_status = STATUS_WARN
    else:
        overall_status = STATUS_FAIL

    return {
        "score": score,
        "status": overall_status,
        "input_length_chars": len(text),
        "threats_count": len(threats),
        "threats": threats
    }

def print_text_report(data, raw_input):
    print("=" * 70)
    print(BANNER)
    print("=" * 70)
    print(f"Input Preview: {raw_input[:90]}..." if len(raw_input) > 90 else f"Input: {raw_input}")
    print("-" * 70)
    print(f"{SCORE_LABEL}: {data['score']}/100 [{data['status']}]")
    print("-" * 70)
    
    if data["threats"]:
        print(f"\n{THREATS_HEADER}:")
        for t in data["threats"]:
            print(f"  - [{t['severity']}] {t['message']}")
    else:
        print(f"\n{NO_THREATS_MSG}")
        
    print("=" * 70)
    print(f"{FOOTER_PAGES}: https://tavardt-new-zealand.github.io/llm-guardrails-toolkit-nz/")
    print(f"{FOOTER_PORTAL}: https://ag.tavardt.com/nz/")
    print("=" * 70)

def main():
    parser = argparse.ArgumentParser(description=DESC)
    parser.add_argument("--prompt", help=PROMPT_HELP)
    parser.add_argument("--file", help=FILE_HELP)
    parser.add_argument("--json", action="store_true", help=JSON_HELP)
    args = parser.parse_args()

    input_text = ""
    if args.prompt:
        input_text = args.prompt
    elif args.file:
        try:
            with open(args.file, "r", encoding="utf-8") as f:
                input_text = f.read()
        except Exception as e:
            print(f"Error reading file {args.file}: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        # Check stdin if piped
        if not sys.stdin.isatty():
            input_text = sys.stdin.read()
        else:
            print(NO_INPUT_ERR, file=sys.stderr)
            parser.print_help()
            sys.exit(1)

    results = audit_prompt_text(input_text.strip())

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print_text_report(results, input_text.strip())

if __name__ == "__main__":
    main()
