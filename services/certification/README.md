# Cryptographic Sanitization Certificate & PKI Engine

## Overview
This service generates tamper-evident, cryptographically signed Data Sanitization Certificates compliant with **NIST SP 800-88 Rev 1** and legal provenance standards.

## Key Capabilities
1. **Asymmetric Key Pairs (RSA 2048 / RSA-PSS)**: Issues signed certificate digests with `.sig` verification files.
2. **Merkle Tree Audit Root**: Computes Merkle root hashes across wiping pass traces to ensure immutable audit trails.
3. **Visual Certificate Rendering**: Synthesizes verified digital certificates into formatted visual `.png` and structured `.json` formats.

## Core Files
- `certificate.py`: Core certificate generation script.
- `verify.py`: Interactive CLI certificate validator checking RSA signatures and Merkle roots against public keys.
- `sha.py`: High-performance hashing helper.
- `registry.json` & `diverse_drive_hashes.json`: Device and certificate registry metadata.

## Verification Command
```powershell
python verify.py
```
