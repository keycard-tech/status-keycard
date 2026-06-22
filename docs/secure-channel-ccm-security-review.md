# Secure Channel Protocol v2 (AES-CCM) — Security Review Brief

## At a glance

TLS 1.3-style secure channel for JavaCard 3.0.5. ECDHE on secp256k1 for key agreement, HKDF-SHA256 for derivation, ECDSA-SHA256 for card authentication, AES-128-CCM for AEAD. Two independent session keys (h2c / c2h). Implicit per-session nonce counter — no IV on the wire.

## Cryptographic primitives

| Layer | Algorithm | Notes |
|---|---|---|
| Key exchange | ECDHE / secp256k1 | `KeyAgreement.ALG_EC_SVDP_DH_PLAIN` |
| KDF | HKDF-SHA256 (extract + expand) | Client-provided 32-byte salt |
| Card auth | ECDSA-SHA256 / secp256k1 | Signs the full key exchange transcript |
| AEAD | AES-128-CCM (T=8, Q=2) | Built from AES-ECB (CTR) + AES-CBC-MAC |

CCM is not a native JavaCard primitive on most cards; it's assembled from `ALG_AES_BLOCK_128_ECB_NOPAD` and `ALG_AES_MAC_CBC`.

## Phase 0 — Trust bootstrap

Each card holds a persistent secp256k1 ECDSA key pair (the *authentikey*), loaded during the card production stage. The public key is distributed via a 98-byte custom certificate:

```
compressed_pubkey (33B) || r (32B) || s (32B) || v (1B)
```

`r`, `s`, `v` form a CA ECDSA signature over the compressed pubkey, using public-key recovery so the CA key need not be transmitted. The client recovers the CA key, validates it against one of the known anchors, then verifies the signature. No expiry dates, no serial numbers.

The certificate is returned in cleartext on applet SELECT.

## Phase 1 — Handshake

```
Client → Card:  hkdf_salt (32B) || client_eph_pub (65B uncompressed)
Card   → Client: card_eph_pub (65B) || sig (DER, ≤72B)
```

Card generates an ephemeral key pair, computes `shared_X = (client_eph_pub × card_eph_priv).x`, then derives keys:

```
PRK  = HMAC-SHA256(hkdf_salt, shared_X)
OKM  = HKDF-Expand(PRK, "sc_v2_ccm", 32)
key_h2c = OKM[0..15]
key_c2h = OKM[16..31]
```

The card signs the transcript `"sc_v2_ccm" || hkdf_salt || client_eph_pub || card_eph_pub` with its authentikey. The client verifies this signature against the certified public key. This binds the card's identity to the exact keys used, preventing active key substitution.

## Phase 2 — Encrypted commands

All traffic after the handshake is wrapped in a single command type:

```
[0x80 | 0x18 | 0x00 | 0x00 | LC'] || ciphertext || tag(8B)
```

The inner APDU — including `CLA`, `INS`, `P1`, `P2`, `LC`, and data — is fully encrypted. No AAD. The ISO-level SW is always `0x9000` (decrypt OK) or `0x6982` (decrypt error); the real command SW is inside the encrypted response payload. When the card responds anything other than `0x9000` the secure channel session is immediately reset.

### Nonce handling

A single 13-byte counter starts at zero for each session. Both directions use the same nonce value per round-trip (command at N, reply at N), then increment. Two independent keys guarantee distinct `(key, nonce)` pairs even though the nonce value is shared between directions. No nonce bytes are transmitted.

Counter overflow (2^104 round-trips) forces session teardown and fresh handshake.

### CCM construction

Flags byte: `0x19` (F=0, M=3, T=8, L=1, Q=2). B0 is `[Flags | Nonce(13) | MessageLen(2)]`. Authenticate-then-encrypt: CBC-MAC over plaintext blocks, then CTR encryption. Tag is 8 bytes. Messages up to 2^16-1 bytes.

## What is visible on the wire

- **Handshake:** `hkdf_salt`, `client_eph_pub`, `card_eph_pub`, ECDSA signature (all public data)
- **Encrypted phase:** wrapper header `0x80 0x18 0x00 0x00`, `LC'` (ciphertext length), ciphertext+tag payload, ISO SW (`0x9000`/`0x6982`)
- **Not visible:** inner command type (although this is guessable), inner parameters, inner SW, response data

## Key design choices and trade-offs

1. **Implicit counters instead of random nonces.** Saves 13 bytes/message. Enforces strict ordering (out-of-order messages fail tag check). No per-message nonce exchange needed because keys are session-unique via ECDHE.

2. **No AAD, full encryption.** The inner APDU header is encrypted rather than authenticated-in-plaintext. This leaks less (command type, parameters) at the cost of a few extra bytes of ciphertext.

3. **Single counter for both directions.** Works because the protocol is strict request-response: no message types other than command/reply exist, so the two sides are always in lockstep. Reflection is prevented by key separation, not nonce separation.

4. **Transcript-binding signature.** The card signs `domain || salt || client_pub || card_pub`. If a MITM substitutes `client_pub`, the client's verification uses its *own* `client_pub` in the transcript — mismatch detected. This is the same approach as TLS 1.3's `Finished` messages.

5. **Authentication tag.** The 64-bit authentication tag (T=8) bounds forgery to 2⁻⁶⁴ per attempt. This is acceptable because a tag-verification failure immediately resets the session (see Phase 2), limiting an online attacker to a single forgery attempt per handshake. 

6. **Certificate format.** Compact (98 bytes) but non-standard. No expiry. Acceptable for a closed ecosystem with hardware-protected CA key and updatable client software.

7. **Error codes.** Only two SWs returned: `0x6982` for any secure-channel failure, `0x9000` for success. No timing or error-type side channels from the protocol layer.

## Known limitations

- If the CA key is compromised, it invalidates all certificates.

## Protocol constants

```
PROTOCOL_LABEL   = "sc_v2_ccm"           (9B)
CCM_T            = 8                     (tag length)
CCM_Q            = 2                     (length field width)
CCM_N            = 13                    (nonce length)
CCM_FLAGS        = 0x19
INS_OPEN_CHANNEL = 0x10
INS_SECURED      = 0x18
```

## References

RFC 8446 (§4.2.8, §4.4.3), RFC 5869, RFC 3610, NIST SP 800-38C, JavaCard 3.0.5 API.
