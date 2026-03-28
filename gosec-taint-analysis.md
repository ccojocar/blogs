# Taint Analysis in gosec: Tracking Data Flow from Source to Sink

[gosec](https://github.com/securego/gosec) is a static
analysis tool that inspects Go source code for security
vulnerabilities. It scans the Go AST and SSA form to
find issues like SQL injection, command injection, XSS,
and other common vulnerability classes.

Until recently, gosec relied on two approaches: AST-based
pattern matching (rules) and SSA-based analyzers. Both
work well for certain classes of bugs, but they struggle
with a fundamental question: *does user-controlled data
actually reach this dangerous function call?*

gosec now ships a **taint analysis engine** that answers
this question directly. It traces data flow from sources
(user input) through the program's SSA form and call
graph to sinks (dangerous functions), with support for
sanitizers that break the taint chain. The engine powers
10 new analyzers covering SQL injection, command
injection, XSS, SSRF, path traversal, and more.

This post covers how it works, when to use it, and what
trade-offs it makes.

## How It Works

The taint engine lives in the
[`taint/`](https://github.com/securego/gosec/tree/master/taint)
package and is built on top of Go's
`golang.org/x/tools/go/ssa` and
`golang.org/x/tools/go/callgraph` packages — no external
dependencies beyond what gosec already uses.

### Architecture

![Taint Analysis Architecture](https://raw.githubusercontent.com/ccojocar/blogs/refs/heads/main/gosec-taint-architecture.png)

The analysis pipeline has four stages:

1. **SSA construction** — Go source is compiled to
   Static Single Assignment form via `buildssa.Analyzer`.
   SSA gives every value a single definition point,
   making data flow explicit.

2. **Call graph construction** — A Class Hierarchy
   Analysis (CHA) call graph is built once per package
   and shared across all taint analyzers. CHA is sound
   (no false negatives) but conservative — it resolves
   every interface method call to all implementations.

3. **Taint configuration** — Each analyzer defines its
   own `taint.Config` specifying sources, sinks, and
   sanitizers. This is the only part that differs between
   analyzers.

4. **Taint checking** — For each sink call found in the
   SSA, the engine walks backward through the SSA
   definition chain to determine if any argument
   originates from a source.

### The Core Model: Sources, Sinks, Sanitizers

Every taint analyzer is defined by three lists:

**Sources** are where tainted data enters the program.
gosec supports two kinds:

- **Type sources** — function parameters whose type
  matches a known input type (e.g., `*http.Request`).
  Only parameters received from external callers are
  tainted; locally constructed values of the same
  type are not.
- **Function sources** — calls that return tainted
  data (e.g., `os.Getenv`, `os.Args`).

```go
Sources: []taint.Source{
    // Type: tainted when received as a parameter
    {Package: "net/http", Name: "Request", Pointer: true},
    // Function: return value is always tainted
    {Package: "os", Name: "Getenv", IsFunc: true},
}
```

**Sinks** are dangerous functions that should not receive
tainted data. Sinks support two precision mechanisms:

- `CheckArgs` — specifies which argument positions to
  check, so you can skip the receiver, context
  parameters, or prepared statement placeholders.
- `ArgTypeGuards` — constrains sinks by argument type.
  For example, `fmt.Fprintf` is only a sink when the
  writer is an `http.ResponseWriter`, not when writing
  to `os.Stdout`.

```go
Sinks: []taint.Sink{
    // Only check the query string (arg 1), not
    // the receiver or prepared statement params
    {
        Package:  "database/sql",
        Receiver: "DB",
        Method:   "Query",
        Pointer:  true,
        CheckArgs: []int{1},
    },
    // Only flag when writing to an HTTP response
    {
        Package:       "fmt",
        Method:        "Fprintf",
        CheckArgs:     []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
        ArgTypeGuards: map[int]string{
            0: "net/http.ResponseWriter",
        },
    },
}
```

**Sanitizers** break the taint chain. When tainted data
passes through a sanitizer, the result is considered
clean.

```go
Sanitizers: []taint.Sanitizer{
    {Package: "html", Method: "EscapeString"},
    {Package: "path/filepath", Method: "Clean"},
    {Package: "strconv", Method: "Atoi"},
}
```

### Backward Taint Propagation

The core algorithm is `isTainted()` — a recursive
function that walks backward through SSA value
definitions. Given a value at a sink call site, it traces
the value's origin through the SSA graph:

- **Constants** — always safe. Compile-time literals
  cannot carry attacker-controlled data.
- **Parameters** — tainted if their type matches a
  source type, or if any caller passes tainted data
  (checked via the call graph).
- **Function calls** — sanitizers break the chain,
  source functions produce taint, and for other calls
  the engine checks whether tainted arguments actually
  flow to the return value.
- **Field access** — field-sensitive tracking. Not all
  fields of a struct are tainted just because the
  struct came from a source. The engine traces stores
  to specific field indices.
- **Phi nodes** — SSA merge points from control flow.
  A value is tainted if it is tainted on any incoming
  edge.
- **Operations** — binary ops, type conversions, slices,
  and index operations propagate taint through.

The recursion is bounded by a depth limit of 50 and a
visited set to prevent cycles.

### Interprocedural Analysis

The engine does not stop at function boundaries. When it
encounters a call to an internal function (one with an
available SSA body), it checks whether tainted arguments
actually influence the return value — not just whether
they are passed at all.

This is critical for reducing false positives. Consider:

```go
func newHandler(input string, logger *log.Logger) *Handler {
    logger.Printf("received: %s", input)
    return &Handler{name: "default"}
}
```

A naive analysis would propagate taint through
`newHandler` because it receives a tainted argument. The
engine's `doTaintedArgsFlowToReturn` function detects
that `input` is only logged, not returned, and correctly
marks the result as untainted.

For external functions (no SSA body available), the
engine conservatively assumes tainted arguments taint the
return value. This is sound for stdlib data-transformation
functions like string operations and `fmt.Sprintf`.

### Call Graph and Parameter Analysis

When checking if a parameter is tainted, the engine uses
the CHA call graph to inspect callers. If any caller
passes tainted data to the parameter position, the
parameter is considered tainted.

CHA over-approximates interface method resolution — every
interface call fans out to all implementations. To keep
analysis tractable, caller edges are capped at 32 per
function. Real taint flows come from direct or nearby
callers; the 33rd CHA-generated edge is unlikely to
matter.

Parameter taint results are memoized per-package for
performance.

### Context Handling

`context.Context` is explicitly excluded from taint
propagation. It carries deadlines, cancellation signals,
and request-scoped values — control flow, not user data.
A function like `db.QueryContext(ctx, query)` should
check `query` for taint, not `ctx`.

## When to Use Taint Analysis

gosec now has three analysis approaches. Each has
different strengths.

### AST-Based Rules

AST rules match syntax patterns. They are fast, simple,
and work well for detecting dangerous function calls or
insecure configurations. But they have no data flow
visibility.

Consider the AST-based SQL injection rule (G201). It
looks for string concatenation in SQL query arguments:

```go
// AST rule detects this — string concat with variable
query := "SELECT * FROM users WHERE id=" + userID
db.Query(query)
```

But it cannot trace data through function calls:

```go
func buildQuery(id string) string {
    return "SELECT * FROM users WHERE id=" + id
}

// AST rule misses this — no visible concatenation
// at the call site
db.Query(buildQuery(r.URL.Query().Get("id")))
```

And it produces false positives on safe patterns:

```go
// AST rule flags this — variable in query argument
// But the variable is a constant, not user input
query := "SELECT * FROM users WHERE active=true"
db.Query(query)
```

### SSA-Based Analyzers

SSA analyzers work on the intermediate representation and
can reason about value flow within a function. gosec uses
these for integer overflow detection (G115), slice bounds
checking (G602), and hardcoded nonces (G407).

SSA is more precise than AST for intra-function analysis,
but standard SSA analyzers still lack the source-sink
framework that taint analysis provides.

### Taint Analyzers

Taint analysis combines SSA with call graph analysis and
the source-sink-sanitizer model. It is the right choice
when the vulnerability depends on **where the data comes
from** and **where it goes**.

Here is how the taint-based SQL injection analyzer (G701)
handles the cases above:

```go
// Taint analyzer detects this:
// r.URL.Query().Get("id") → *http.Request source
// → flows through buildQuery → reaches db.Query sink
db.Query(buildQuery(r.URL.Query().Get("id")))

// Taint analyzer ignores this:
// "SELECT ... WHERE active=true" is a constant
// No source type flows to the sink
query := "SELECT * FROM users WHERE active=true"
db.Query(query)
```

### Current Taint Analyzers

gosec ships 10 taint-based analyzers:

| ID   | Vulnerability              | Severity |
|------|----------------------------|----------|
| G701 | SQL injection              | High     |
| G702 | Command injection          | Critical |
| G703 | Path traversal             | High     |
| G704 | SSRF                       | High     |
| G705 | XSS                        | Medium   |
| G706 | Log injection              | Low      |
| G707 | SMTP injection             | High     |
| G708 | Server-side template injection | Critical |
| G709 | Unsafe deserialization     | High     |
| G120 | Unbounded form parsing     | Medium   |

Each is defined as a `taint.Config` with sources, sinks,
and sanitizers tailored to the vulnerability class. Adding
a new analyzer is straightforward — define the
configuration and register it.

### Concrete Example: XSS Detection

The XSS analyzer (G705) demonstrates the precision of
taint analysis. Its configuration uses type guards to
distinguish between writing to an HTTP response (a
security risk) and writing to stdout (not a risk):

```go
// Flagged: tainted data written to HTTP response
func handler(w http.ResponseWriter, r *http.Request) {
    name := r.URL.Query().Get("name")
    fmt.Fprintf(w, "<h1>Hello %s</h1>", name)
}

// Not flagged: same fmt.Fprintf, but writing to stdout
func logInput(r *http.Request) {
    name := r.URL.Query().Get("name")
    fmt.Fprintf(os.Stdout, "received: %s", name)
}

// Not flagged: sanitized before writing
func safeHandler(w http.ResponseWriter, r *http.Request) {
    name := html.EscapeString(r.URL.Query().Get("name"))
    fmt.Fprintf(w, "<h1>Hello %s</h1>", name)
}
```

An AST rule cannot make these distinctions. It either
flags all `fmt.Fprintf` calls (noisy) or none (unsound).

## Trade-offs

Taint analysis is not free. Here are the trade-offs:

**Precision vs. performance** — taint analysis is slower
than AST matching. It requires SSA construction, call
graph computation, and recursive backward traversal.
The CHA call graph is shared across analyzers to
amortize the cost, and parameter taint results are
memoized.

**Soundness vs. false positives** — CHA produces a
sound but imprecise call graph. Interface method calls
fan out to all implementations, which can cause false
positives. The 32-edge cap on caller analysis limits
this at the cost of potential false negatives in large
codebases.

**Configuration scope** — the engine tracks taint
through Go's standard library and internal functions,
but third-party frameworks may introduce sources or
sinks it does not know about. Adding custom sources
and sinks requires modifying the analyzer configuration.

**Depth limits** — the 50-level recursion cap and
32-edge caller cap are practical bounds that work well
for most codebases but may miss deep call chains or
highly polymorphic code.

Despite these trade-offs, taint analysis catches
vulnerability patterns that AST and basic SSA analysis
simply cannot express. For injection-class vulnerabilities
where the question is "does user input reach this
dangerous call?", it is the right tool.

## Conclusion

gosec's taint analysis engine adds data flow tracking
to a tool that previously relied on syntactic patterns.
The source-sink-sanitizer model maps directly to how
injection vulnerabilities work: untrusted input enters
the program, flows through transformations, and reaches
a dangerous operation.

The implementation makes practical trade-offs — CHA over
pointer analysis, depth caps over unbounded recursion,
memoization over repeated computation — that keep
analysis fast enough for CI pipelines while catching
real vulnerabilities.

The engine is extensible. Each analyzer is a
configuration of sources, sinks, and sanitizers. Adding
coverage for a new vulnerability class means defining
what constitutes input, what constitutes danger, and what
neutralizes the risk.

The taint analyzers are available in gosec starting from
the latest release. Run them alongside the existing AST
and SSA rules for the best coverage.

**Links:**

- [gosec project](https://github.com/securego/gosec)
- [Taint engine source](https://github.com/securego/gosec/tree/master/taint)
- [Taint-based analyzers](https://github.com/securego/gosec/tree/master/analyzers)
