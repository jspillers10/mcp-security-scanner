# Phase 3 engineering-review appendix

This appendix records why the final Phase 3 implementation differs from the
first uncommitted candidate. The authoritative result is
`docs/phase3-results.md`.

The review identified three unsound suppressions:

1. An arbitrary decorator on one MCP tool was treated as transport-wide
   authentication evidence.
2. A guard was treated as protective based on presence and source-line order,
   without structural dominance.
3. `abspath()` and `normpath()` were treated as sufficient canonicalization
   despite residual symlink traversal.

The final implementation removes decorator-based RDY002 suppression, accepts
explicit `auth=` only on recognized `FastMCP(...)` construction with an enabled
value, requires direct sibling rejecting guards that structurally dominate the
sink, and accepts only `Path.resolve()` or `os.path.realpath()` for containment
suppression. Regression tests cover unrelated and disabled auth configuration,
nested and exception-handled guards, conditional and non-terminating exits,
and lexical-only normalization.

Reviewer-packet Case 15 remains disputed and Case 16 remains a potential
ground-truth gap. Neither label was changed. Superseded round-one candidate
directories are excluded from the proposed commit; the reasoning is preserved
here instead.
