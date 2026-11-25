# Diagnostic scanning

`redact.Scan` detects patterns in bytes and returns rule IDs, one-based lines and zero-based byte offsets. `BundleGuard` accepts a zip or gzip-compressed tar stream and reports archive paths and per-file statistics. Pass the current home user explicitly in `Options`; the package does not read the environment. Treat any guard error as a failed verification. Archives and their total uncompressed data are limited to 64 MiB. Non-regular entries fail verification.

Rule IDs: `jwt`, `bearer`, `openai_key`, `github_token`, `slack_token`, `aws_access_key`, `pem_private_key`, `inline_secret`, `high_entropy`, `url_userinfo`, `url_query`, `foreign_home`, and `own_home`. The home rules identify paths that may require normalization. The high-entropy rule ignores exactly 64 hexadecimal characters as a SHA-256 digest allowance; secrets of that shape therefore require another detector. A match never includes its value, although archive paths themselves are returned as locations.

These detectors are heuristics, not proof that a bundle is safe. Unrecognized secrets, encodings, split tokens and values shorter than thresholds may be missed. Scan all diagnostic inputs before release and handle findings and errors as verification failures.
