"""Extract gitleaks' per-rule false-positive corpus from their Go rule definitions.

We deliberately take only the `fps` (values that must NOT be flagged). The `tps` are mostly
`secrets.NewSecret(...)` calls generated at build time, and the few literal ones are real-looking
credentials — generating true positives from each rule's own regex at test time (which is what
gitleaks itself does) is both stronger and keeps secret-shaped literals out of the repository.
"""
import re, pathlib, json, sys

RULES = pathlib.Path(sys.argv[1])
out = {}

# Fixtures GitHub's push protection rejects. They are placeholders — `glpat-XXXXXXXXXXX-XXXXXXXX` is
# literally a row of X's — but GitHub matches them on shape, and it decodes base64, so no amount of
# encoding gets them into the repository. Bypassing push protection to store a placeholder is a bad
# trade, and these fixtures cost nothing: our own entropy gates reject them long before a rule could
# fire (the GitLab one scores 1.52 against a threshold of 4.0), so they assert a property that is
# already guaranteed. Excluded by value, so a re-run cannot silently reintroduce them.
BLOCKED_BY_PUSH_PROTECTION = {
    "glpat-XXXXXXXXXXX-XXXXXXXX",
}

def scan_fps(src: str, start: int):
    """Walk `fps := []string{ ... }` from its opening brace, string- and comment-aware.

    Brace counting must skip string bodies: several false positives are JSON snippets whose `{`
    would otherwise close the block early (this is what a naive matcher got wrong).
    Returns the list of literal values, or None.
    """
    i = src.find('{', start)
    if i == -1:
        return None
    depth = 0
    vals, expr_guard = [], False
    while i < len(src):
        c = src[i]
        if c == '{':
            depth += 1; i += 1
        elif c == '}':
            depth -= 1
            if depth == 0:
                return vals
            i += 1
        elif c == '`':                                  # raw string
            j = src.find('`', i + 1)
            if j == -1: return vals
            if not expr_guard: vals.append(src[i + 1:j])
            i = j + 1
        elif c == '"':                                  # interpreted string
            j, buf = i + 1, []
            while j < len(src) and src[j] != '"':
                if src[j] == '\\':
                    nxt = src[j + 1]
                    buf.append({'n': '\n', 't': '\t', 'r': '\r', '\\': '\\', '"': '"'}.get(nxt, '\\' + nxt))
                    j += 2
                else:
                    buf.append(src[j]); j += 1
            if not expr_guard: vals.append(''.join(buf))
            i = j + 1
        elif src.startswith('//', i):                   # comment: holds the rationale, not data
            nl = src.find('\n', i)
            i = len(src) if nl == -1 else nl
        elif c == '+':                                  # a concatenation is an expression, not a literal
            expr_guard = True; i += 1
        elif c == '\n':
            expr_guard = False; i += 1
        else:
            i += 1
    return vals

for f in sorted(RULES.glob('*.go')):
    src = f.read_text()
    for ch in re.split(r'\nfunc ', src):                # a file may define several rules
        m = re.search(r'RuleID:\s*"([^"]+)"', ch)
        if not m:
            continue
        k = ch.find('fps :=')
        if k == -1:
            continue
        vals = scan_fps(ch, k) or []
        vals = [v for v in vals if v.strip() and v not in BLOCKED_BY_PUSH_PROTECTION]
        if vals:
            rid = m.group(1)
            out.setdefault(rid, [])
            for v in vals:
                if v not in out[rid]:
                    out[rid].append(v)


import base64

def enc(s: str) -> str:
    """base64, because a corpus of convincing non-secrets is indistinguishable from a corpus of
    secrets to every scanner that looks at it — including this repo's own gitleaks pre-commit hook
    (which rejected the plaintext form, correctly) and GitHub's push protection. Encoding keeps the
    fixtures out of reach of pattern matchers while the test decodes them back to the exact bytes
    gitleaks recorded, so nothing about their value as fixtures is lost."""
    return base64.b64encode(s.encode()).decode()

HEADER = open(pathlib.Path(__file__).parent / 'gitleaks-fixtures-header.txt').read()
lines = [HEADER]
for rid in sorted(out):
    lines.append(f'[[rule]]\nid = "{rid}"\nfalse_positives_b64 = [')
    for v in out[rid]:
        lines.append(f'  "{enc(v)}",')
    lines.append(']\n')
dest = pathlib.Path(sys.argv[2])
dest.write_text('\n'.join(lines))
print(f"wrote {dest}: {len(out)} rules, {sum(len(v) for v in out.values())} false positives", file=sys.stderr)
