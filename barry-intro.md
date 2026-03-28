# Barry: AI-Powered Security Code Review for GitHub Pull Requests

Classic static analysis tools are good at what they do —
pattern matching, taint tracking, dataflow analysis. But they
operate within rigid rule sets. They don't understand intent,
can't reason about context, and struggle with vulnerability
classes that span multiple functions or require semantic
understanding of the code.

[Barry](https://github.com/ccojocar/barry) is an open-source
GitHub Action that uses LLMs to review pull requests for
security vulnerabilities. It is built in Go using Google's
[ADK-Go](https://google.github.io/adk-docs/) framework and
powered by Gemini.

## Why an AI Security Scanner?

Traditional scanners work by matching known patterns — a
`strcpy` call, an unsanitized SQL query, a missing bounds
check. They are effective for well-defined vulnerability
classes but fall short in several areas:

**Language and framework agnostic.** Barry doesn't need
language-specific rules or parsers. It reads the diff the same
way a human reviewer would. C buffer overflows, Go path
traversals, SQL injection in a web framework — same pipeline,
no configuration per language.

**Contextual understanding.** An LLM can reason about *why*
code is vulnerable, not just *that* it matches a pattern. It
can follow data flow across function boundaries, understand
the semantic meaning of a refactoring, and catch logic errors
that no regex will find.

**Actionable suggestions.** Each finding includes a plain
language explanation of the vulnerability, an exploit scenario,
and an autofix — a concrete code suggestion in the scope of
the issue, not a generic recommendation.

**PR-scoped analysis.** Barry reviews only the code that
changed. This keeps the signal-to-noise ratio manageable and
fits naturally into an existing development workflow.

## Architecture

Barry runs a multi-agent pipeline where each stage reads the
output of the previous one:

![Barry Multi-Agent Security Pipeline](https://raw.githubusercontent.com/ccojocar/barry/2f80e89c7227ce1fed3d70edd27c04b18d0cbe04/docs/architecture.png)

**Scanner Agent** — Gemini receives the PR diff, the list of
changed files, and a system prompt instructing it to act as a
senior security engineer. The response is constrained by a
structured JSON schema, which eliminates fragile output
parsing.

**Hard Filter Agent** — A deterministic, regex-based filter
that removes common false positive categories: denial of
service, rate limiting, resource leaks, memory safety findings
in non-C/C++ code, and others. This runs in pure Go — no LLM
calls, no latency, no cost.

**Validator Agent** *(optional)* — Each remaining finding is
re-examined by a second LLM pass. The validator decides
whether the finding is a true positive or a false positive,
with a justification. This significantly reduces noise.

**Autofixer Agent** *(optional)* — For confirmed findings, a
final LLM pass generates an idiomatic code fix that is
included in the PR review comment.

The pipeline is wired using ADK-Go's `SequentialAgent`, with
each agent reading and writing typed structs through session
state.

### Customization

Barry supports two customization mechanisms that give you
control over the scan without modifying the tool itself:

**Custom scan instructions** — A text file with additional
vulnerability categories to check for, tailored to your
codebase. For example, you might ask Barry to look for
[TOCTOU issues in directory exclusion logic or injection in
SARIF report generation](https://github.com/ccojocar/barry/blob/main/examples/custom-gosec-security-scan-instructions.txt)
if you're scanning a security tool.

**Custom false positive filtering** — A text file that
provides context about your codebase so the validator can make
better decisions. For instance: "MD5 is used only for
non-cryptographic cache keys" or "test files with
`InsecureSkipVerify` are intentional." See the
[example for gosec](https://github.com/ccojocar/barry/blob/main/examples/custom-gosec-false-positive-filtering.txt).

**Exceptions file** — A JSON file defining specific findings
to exclude, useful for suppressing known accepted risks.

## In Action

Below are real examples of Barry scanning pull requests
against well-known open source projects. These PRs contain
intentionally introduced vulnerabilities to demonstrate what
the scanner can detect.

### Buffer Overflow in curl (C)

**PR:** [ccojocar/curl#2](https://github.com/ccojocar/curl/pull/2)
— *"vauth/digest: refactor key-value unescaping into helper"*

The refactoring changes a length check from `if(len >= buflen)`
to `if(len > buflen)` in the digest authentication code. This
off-by-one error allows a source string exactly equal to the
buffer size to be copied, and when the null terminator is
appended, it writes one byte past the end of the stack buffer.

A malicious HTTP 401 response with a digest challenge value of
exactly 128 characters (matching the internal buffer size)
would trigger this. Barry flagged it as HIGH severity with
100% confidence and recommended reverting to the original
bound check.

This is the kind of bug that is easy to miss in review — the
change looks like a harmless refactoring, and the off-by-one
only manifests with an exact-length input.

### Heap Overflow in curl (C)

**PR:** [ccojocar/curl#3](https://github.com/ccojocar/curl/pull/3)
— *"cookie: ensure path always starts with a slash"*

The `sanitize_cookie_path()` function allocates `len + 1`
bytes for a new path but needs to store a leading `/`, the
original path, and a null terminator — that's `len + 2` bytes.
The null terminator is written one byte past the allocated
heap buffer.

Barry identified this as a HIGH severity heap-based buffer
overflow. The fix is straightforward (allocate `len + 2`
instead of `len + 1`), but the bug is subtle because the
allocation arithmetic *looks* correct at first glance.

### Path Traversal in Prometheus (Go)

**PR:** [ccojocar/prometheus#2](https://github.com/ccojocar/prometheus/pull/2)
— *"Refactor console path handling and normalize label values"*

A new `SafeResolvePath` utility validates paths for directory
traversal (`..` sequences) *before* URL-unescaping the input.
The subsequent `NormalizeLabelValue()` call decodes
percent-encoded characters, so an attacker can bypass the
check with `%2e%2e%2f` (which decodes to `../`).

Barry flagged this as a path traversal vulnerability. The fix
is to unescape first, then validate. This is a classic
order-of-operations bug that a traditional scanner would
likely miss because the vulnerability depends on understanding
the semantic relationship between two functions.

### SQL Injection in Grafana (Go)

**PR:** [ccojocar/grafana#2](https://github.com/ccojocar/grafana/pull/2)
— *"Add annotation summary endpoint with pivot-by-tag support"*

The `executePivotQuery` function builds SQL using
`fmt.Sprintf` with tag values retrieved from the database.
Since those values were originally supplied by users creating
annotations, this is a second-order SQL injection — the
malicious payload is stored first, then executed later when
interpolated into a query.

Barry identified this with 95% confidence. Second-order SQL
injection is particularly hard for traditional scanners
because the taint source is a database read, not a direct
user input. A human reviewer might also miss it if they assume
database values are trusted.

## Challenges

AI-powered security scanning is promising but comes with real
limitations:

**Non-determinism.** The same PR may produce different
findings on different runs. LLMs are stochastic — temperature,
sampling, and model updates all affect output. The structured
output schema and multi-stage pipeline help stabilize results,
but they don't eliminate variance entirely.

**False positives.** Despite the multi-layer filtering
(hard filter → LLM validator → custom rules), false positives
still occur. The custom filtering instructions help, but
tuning them requires effort and domain knowledge.

**Cost and latency.** Each scan involves multiple LLM calls.
The validator and autofixer run per-finding, so a scan with
many initial findings can be slow and expensive. The optional
flags for these stages exist for this reason.

**Context window limits.** Large diffs may exceed the model's
context window. Barry handles this with a fallback (retry
without the diff), but this degrades scan quality. Very large
PRs are better split into smaller ones — which is good
practice regardless.

**No execution or proof.** Barry reasons about code
statically. It cannot run the code, execute a proof of
concept, or verify that a vulnerability is actually
exploitable. The confidence scores help prioritize, but
manual verification is still necessary for any finding.

## Getting Started

Add Barry to your repository in a few lines of workflow YAML:

```yaml
name: Security Review
on:
  pull_request_target:
    types: [opened, synchronize]

permissions:
  contents: read
  pull-requests: write

jobs:
  security-review:
    runs-on: ubuntu-latest
    environment: security-review
    steps:
      - uses: ccojocar/barry@v1
        with:
          google-api-key: ${{ secrets.GOOGLE_API_KEY }}
          github-token: ${{ secrets.GITHUB_TOKEN }}
```

Barry also produces SARIF output for integration with GitHub's
Security tab. See the
[README](https://github.com/ccojocar/barry) for full
configuration options.

The project is Apache 2.0 licensed. Contributions and feedback
are welcome.

---

*Barry is named after the
[Saint Bernard](https://en.wikipedia.org/wiki/Barry_(dog))
— a rescue dog known for finding people in trouble.*
