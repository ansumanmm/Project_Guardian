#!/usr/bin/env python3
import argparse
import csv
import hashlib
import json
import os
import re
import sys
import ipaddress
from typing import Any, Dict, Tuple

EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
UPI = re.compile(r"\b[\w.\-]{2,}@[A-Za-z]{2,}\b")
PASSPORT = re.compile(r"\b[A-Z][0-9]{7}\b")
PHONE = re.compile(r"(?:\+?91[\s-]?|0[\s-]?)?([6-9][0-9]{9})\b")
PIN = re.compile(r"\b[1-9][0-9]{5}\b")
IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

ADDRESS_HINTS = {"street","lane","sector","nagar","block","plot","phase","village","district"}

def normalize_digits(s: Any) -> str:
    return re.sub(r"\D", "", str(s))

def alias(text: str, salt: str = "Ansuman2003") -> str:
    h = hashlib.md5((salt + text).encode()).hexdigest()[:6]
    return f"X{h.upper()}"

def aadhaar_valid(num: str) -> bool:
    if len(num) != 12 or not num.isdigit():
        return False
    weights = [2,3,4,5,6,7,8,9,2,3,4,5]
    return sum(int(d)*w for d,w in zip(num,weights)) % 10 == 0

def mask_email(s: str) -> str:
    return EMAIL.sub(lambda m: m.group(0)[0]+"***@"+m.group(0).split("@")[1], s)

def mask_upi(s: str) -> str:
    return UPI.sub(lambda m: m.group(0)[:2]+"***@"+m.group(0).split("@")[1], s)

def mask_passport(s: str) -> str:
    return PASSPORT.sub(lambda m: m.group(0)[0]+"*****"+m.group(0)[-1], s)

def mask_phone(s: str) -> str:
    return PHONE.sub(lambda m: m.group(1)[:3]+"****"+m.group(1)[-2:], s)

def mask_aadhaar(s: str) -> str:
    digits = normalize_digits(s)
    if aadhaar_valid(digits):
        return digits[:2]+"****"+digits[-2:]
    return s

def mask_ip(s: str) -> str:
    def repl(m):
        ip = m.group(0)
        try:
            ipaddress.ip_address(ip)
            return ip.split(".")[0]+".x.x.x"
        except:
            return "x.x.x.x"
    return IP.sub(repl, s)

RULES = [
    ("email", EMAIL, mask_email),
    ("upi", UPI, mask_upi),
    ("passport", PASSPORT, mask_passport),
    ("phone", PHONE, mask_phone),
    ("aadhaar", re.compile(r"\b\d{12}\b"), mask_aadhaar),
    ("ip", IP, mask_ip),
]

def looks_like_name(val: str) -> bool:
    if not val or any(ch.isdigit() for ch in val):
        return False
    return len(val.split()) >= 2

def looks_like_address(d: Dict[str,Any]) -> bool:
    addr = str(d.get("address","")).lower()
    return any(w in addr for w in ADDRESS_HINTS) or bool(PIN.search(addr))

def mask_quasi(d: Dict[str,Any]) -> Dict[str,Any]:
    if "name" in d:
        d["name"] = alias(d["name"])
    if "address" in d:
        d["address"] = "[REDACTED]"
    if "device_id" in d:
        d["device_id"] = alias(d["device_id"])
    return d

def redact(record: Dict[str,Any]) -> Tuple[Dict[str,Any], bool]:
    hit = False
    for k,v in list(record.items()):
        if not isinstance(v,str):
            continue
        for _,regex,mask in RULES:
            if regex.search(v):
                record[k] = mask(v)
                hit = True
    score = 0
    if looks_like_name(record.get("name","")):
        score += 1
    if looks_like_address(record):
        score += 1
    if "device_id" in record:
        score += 1
    if score >= 2:
        record = mask_quasi(record)
        hit = True
    return record, hit

def parse_json(s: str) -> Dict[str,Any]:
    try:
        return json.loads(s)
    except:
        s = s.replace("'",'"')
        try:
            return json.loads(s)
        except:
            return {}

def process_file(path: str) -> str:
    out = os.path.join(os.path.dirname(path),"redacted_output_Ansuman_Mohapatra.csv")
    with open(path,encoding="utf-8") as fin, open(out,"w",encoding="utf-8",newline="") as fout:
        reader = csv.DictReader(fin)
        writer = csv.DictWriter(fout, fieldnames=["record_id","redacted_data_json","is_pii"])
        writer.writeheader()
        for row in reader:
            rid = row.get("record_id") or row.get("id") or ""
            data = parse_json(row.get("data_json") or row.get("Data_json") or "{}")
            red, flag = redact(data)
            writer.writerow({"record_id": rid, "redacted_data_json": json.dumps(red, ensure_ascii=False), "is_pii": str(flag)})
    return out

def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("input_csv")
    args = ap.parse_args(argv)
    try:
        out = process_file(args.input_csv)
        print(out)
        return 0
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

if __name__=="__main__":
    raise SystemExit(main())

