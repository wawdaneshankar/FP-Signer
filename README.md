# FP-Signer Burp Extension
Automated Signature Generation for Fynd Apps

## Requirements

- Burp Suite Professional
- Jython standalone jar
- Python extension enabled in Burp

## How to Install

1. Open Burp Suite
2. Go to Extensions → Installed
3. Click Add
4. Select:
   - Extension Type: Python
   - Select this fp_signer.py file
5. Click Next

## Configuration

After loading the extension:

1. Enter your application Secret Key
2. Set Target Host Regex (example: ^example\.com(:443)?$)
3. Choose where to apply:
   - Proxy
   - Repeater
   - Intruder
   - Scanner

## What It Does

- Adds signature headers automatically
- Matches based on host regex
