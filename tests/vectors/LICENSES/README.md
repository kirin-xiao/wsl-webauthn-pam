# Third-party licenses for consulted references

These projects were consulted only to validate TPM/packed verification semantics; no binary
or source fixtures are vendored. Their licenses are recorded here for provenance.

---

## webauthn4j

- Source: https://github.com/webauthn4j/webauthn4j
- License: Apache License 2.0
- Used for: TPM attestation statement semantics (pubArea layout, Name derivation,
  extraData hash choice, AIK signature verification).

```
                                 Apache License
                           Version 2.0, January 2004
                        http://www.apache.org/licenses/
```

The full license text is available at
<https://www.apache.org/licenses/LICENSE-2.0>.

---

## Yubico java-webauthn-server

- Source: https://github.com/Yubico/java-webauthn-server
- License: Apache License 2.0 (see the repository `LICENSE`)
- Used for: packed / none attestation statement shapes.

The full license text is available at
<https://www.apache.org/licenses/LICENSE-2.0>.

---

## W3C WebAuthn Level 2

- Source: https://www.w3.org/TR/webauthn-2/
- License: W3C Document License
- Used for: normative reading of §7.2, §8.2, §8.3, §8.3.1. No text is copied into this
  repository.
