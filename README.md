# AES-256 JSON Field Tool

A browser-only React/Vite utility that can either encrypt/decrypt the **entire JSON payload as one value** or encrypt/decrypt selected **string leaf fields** anywhere in arbitrary JSON.

## What it supports

- Objects
- Arrays
- Nested objects
- Nested arrays
- Arrays of objects
- Objects containing arrays
- Arbitrarily deep combinations
- Selecting individual JSON paths
- Encrypting or decrypting multiple fields in one operation

## Cryptography

This implementation uses the browser Web Crypto API with **AES-256-GCM**.

- Key: exactly 32 bytes
- IV: cryptographically random 12 bytes for every encrypted field
- Authentication tag: 128 bits
- Output format: `v1:<base64 IV>:<base64 ciphertext+tag>`

Example:

```text
v1:3q2+7w8v0aBcDeFg:Z2VuZXJhdGVkY2lwaGVydGV4dA...
```

The IV is intentionally different for every encryption operation even when the same plaintext and key are used.

## Run

```bash
npm install
npm run dev
```

Then open the local Vite URL.

## Important compatibility note

If this tool needs to encrypt/decrypt payloads used by an existing backend, the backend must use the **same algorithm, key interpretation, IV handling, authentication tag handling, and ciphertext encoding**.

AES-256 by itself does not define those details. If your API specification says AES-256-CBC, a fixed IV, PKCS#5/PKCS#7 padding, a particular IV derivation, or a particular ciphertext format, this frontend should be adapted to those exact rules rather than assuming AES-GCM.


## Processing modes

### Entire JSON

The tool serializes the complete JSON payload and encrypts it as a single AES-256-GCM value.

Output is a JSON string containing the ciphertext:

```text
"v1:<base64 IV>:<base64 ciphertext+tag>"
```

For decryption, paste that ciphertext string into the input and choose **Entire JSON → Decrypt**. The tool decrypts it and parses the original JSON.

### Specific values

The tool discovers leaf fields throughout the JSON and lets the user select individual string values. The JSON structure stays intact and only selected values are replaced with ciphertext.
