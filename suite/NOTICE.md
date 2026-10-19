# Upstream notice — the vectors in this directory are not ours

`suite/vectors/*.json` and `suite/SUITE-MANIFEST.json` are **copied verbatim** from
[decentralized-identity/kya-os-mcp](https://github.com/decentralized-identity/kya-os-mcp)
(`conformance/vectors/`), suite version **1.2.0**, 49 vectors across 9 categories.

They are included rather than fetched so that a reviewer can reproduce the run with **no
network access and no package install** — the zero-dependency property is the point of this
repository, and a verifier that must phone home to be tested is not one.

Integrity is checkable without trusting this copy:

```bash
node kyaos_verify.cjs --suite-hash
```

recomputes the vector-set hash from these bytes using this repository's own JCS and SHA-256
and compares it to the pinned `vectorSetHash` in `SUITE-MANIFEST.json`. If a byte of any
vector file were altered, that command fails.

Upstream is MIT-licensed, and MIT requires the notice below to travel with the copies.

---

MIT License

Copyright (c) 2026 KYA-OS

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
