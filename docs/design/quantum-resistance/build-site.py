#!/usr/bin/env python3
"""Build an interactive multi-page HTML site from the quantum-resistance markdown docs.

Each .md becomes a styled page; a shared left sidebar (grouped, filterable) links them all.
Requires pandoc. Output: ./site/  (open site/index.html).

    python3 build-site.py
"""
import html
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
OUT = HERE / "site"

# (filename, nice title, group). Order within a group is presentation order.
DOCS = [
    # group: Decisions (the landing/home is first)
    ("decisions-for-the-team.md", "Decisions for the team", "Decisions"),
    ("deposit-term-policy-decision.md", "Deposit-term policy (Option 3)", "Decisions"),
    ("strategy-decision.md", "Strategy decision", "Decisions"),
    ("strategy-SUMMARY.md", "Strategy summary", "Decisions"),
    # group: Reports & measurements
    ("poc-vs-mainnet-report.md", "PoC vs mainnet report", "Reports & measurements"),
    ("pq-scheme-landscape.md", "PQ scheme landscape (research)", "Reports & measurements"),
    ("pq-ringsig-verdict.md", "PQ ring-sig verdict (ELRS vs lattice)", "Reports & measurements"),
    ("gao-bench-notes.md", "Gao RingCT benchmark (notes)", "Reports & measurements"),
    ("measured-numbers.md", "Measured numbers", "Reports & measurements"),
    ("STATUS.md", "Status & architecture", "Reports & measurements"),
    ("REMAINING-WORK.md", "Remaining work", "Reports & measurements"),
    # group: Implementation
    ("deposit-freeze-impl.md", "Deposit freeze (impl)", "Implementation"),
    ("deposits-mldsa.md", "ML-DSA deposits (design)", "Implementation"),
    ("deposits-mldsa-impl.md", "ML-DSA deposits (impl)", "Implementation"),
    ("pq-deposit-wallet-blueprint.md", "PQ deposit wallet (blueprint)", "Implementation"),
    ("messages-mlkem.md", "ML-KEM messages (design)", "Implementation"),
    ("messages-mlkem-impl.md", "ML-KEM messages (impl)", "Implementation"),
    ("ringsig-hardening.md", "Ring-sig hardening", "Implementation"),
    ("hardening-notes.md", "Hardening notes", "Implementation"),
    ("wallet-v2-impl.md", "Wallet v2 (impl)", "Implementation"),
    ("wallet-address-v2.md", "Wallet address v2", "Implementation"),
    ("wallet-pq-transfers.md", "Wallet PQ transfers", "Implementation"),
    ("matrict-integration-plan.md", "MatRiCT-Au integration plan", "Implementation"),
    ("rpc-get-pq-outputs.md", "RPC: get_pq_outputs", "Implementation"),
    ("serialization-format-spec.md", "Serialization format spec", "Implementation"),
    ("pow-grover-widening.md", "PoW Grover widening", "Implementation"),
    # group: Strategy notes
    ("strategy-crypto-modernization.md", "Crypto modernization", "Strategy notes"),
    ("strategy-greenfield-design.md", "Greenfield design", "Strategy notes"),
    ("strategy-rust-port.md", "Rust port", "Strategy notes"),
]

GROUP_ORDER = ["Decisions", "Reports & measurements", "Implementation", "Strategy notes"]


def slug(filename: str) -> str:
    return filename[:-3] if filename.endswith(".md") else filename


def pandoc_body(md_path: Path) -> str:
    """Render markdown body + in-page TOC via pandoc."""
    res = subprocess.run(
        ["pandoc", str(md_path), "-f", "gfm", "-t", "html",
         "--toc", "--toc-depth=3", "--no-highlight"],
        capture_output=True, text=True,
    )
    if res.returncode != 0:
        sys.stderr.write(f"pandoc failed for {md_path}: {res.stderr}\n")
        return f"<p>render error</p><pre>{html.escape(res.stderr)}</pre>"
    out = res.stdout
    # pandoc emits the TOC as <nav id="TOC">...</nav> first, then the body. Split so we can
    # place the TOC in a styled "On this page" box.
    toc, body = "", out
    if '<nav id="TOC"' in out:
        start = out.index('<nav id="TOC"')
        end = out.index("</nav>", start) + len("</nav>")
        toc = out[start:end]
        body = out[:start] + out[end:]
    return toc, body


def build_nav(active_file: str) -> str:
    by_group = {g: [] for g in GROUP_ORDER}
    for fn, title, group in DOCS:
        by_group.setdefault(group, []).append((fn, title))
    parts = []
    for group in GROUP_ORDER:
        items = by_group.get(group, [])
        if not items:
            continue
        parts.append(f'<div class="nav-group"><div class="nav-group-title">{html.escape(group)}</div><ul>')
        for fn, title in items:
            cls = "active" if fn == active_file else ""
            href = slug(fn) + ".html"
            parts.append(f'<li class="{cls}"><a href="{href}" data-title="{html.escape(title.lower())}">{html.escape(title)}</a></li>')
        parts.append("</ul></div>")
    return "\n".join(parts)


PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title} — Conceal PQ docs</title>
<style>{css}</style>
</head>
<body>
<button id="menu-toggle" aria-label="Menu">☰</button>
<aside id="sidebar">
  <div class="brand"><span class="dot"></span> Conceal &middot; Post-Quantum</div>
  <input id="filter" type="search" placeholder="Filter docs…" autocomplete="off">
  <nav>{nav}</nav>
  <div class="sidebar-foot">CIP-0001 &middot; generated from <code>docs/design/quantum-resistance</code></div>
</aside>
<main>
  <article class="content">
    {toc_box}
    {body}
  </article>
</main>
<script>
  // sidebar filter
  var f = document.getElementById('filter');
  if (f) f.addEventListener('input', function() {{
    var q = this.value.toLowerCase();
    document.querySelectorAll('#sidebar nav li').forEach(function(li) {{
      var a = li.querySelector('a');
      var hit = !q || (a && a.getAttribute('data-title').indexOf(q) !== -1);
      li.style.display = hit ? '' : 'none';
    }});
    document.querySelectorAll('#sidebar .nav-group').forEach(function(g) {{
      var any = Array.from(g.querySelectorAll('li')).some(function(li){{return li.style.display !== 'none';}});
      g.style.display = any ? '' : 'none';
    }});
  }});
  // mobile menu
  var t = document.getElementById('menu-toggle'), sb = document.getElementById('sidebar');
  if (t) t.addEventListener('click', function(){{ sb.classList.toggle('open'); }});
</script>
</body>
</html>
"""

CSS = """
:root{--bg:#0f1220;--panel:#171a2b;--panel2:#1d2136;--text:#e6e8f0;--muted:#9aa3c0;--accent:#6ea8fe;--accent2:#7ee2c8;--border:#2a2f4a;--code:#11142a;}
*{box-sizing:border-box}
html{scroll-behavior:smooth}
body{margin:0;font:16px/1.65 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;color:var(--text);background:var(--bg);}
#sidebar{position:fixed;top:0;left:0;bottom:0;width:300px;background:var(--panel);border-right:1px solid var(--border);overflow-y:auto;padding:20px 0;}
.brand{font-weight:700;letter-spacing:.2px;padding:4px 22px 14px;font-size:15px;display:flex;align-items:center;gap:9px;}
.brand .dot{width:10px;height:10px;border-radius:50%;background:linear-gradient(135deg,var(--accent),var(--accent2));box-shadow:0 0 10px var(--accent);}
#filter{width:calc(100% - 44px);margin:0 22px 14px;padding:9px 12px;border-radius:9px;border:1px solid var(--border);background:var(--panel2);color:var(--text);font-size:14px;}
#filter:focus{outline:none;border-color:var(--accent);}
.nav-group{margin:2px 0 10px;}
.nav-group-title{font-size:11px;text-transform:uppercase;letter-spacing:.09em;color:var(--muted);padding:8px 22px 4px;font-weight:700;}
nav ul{list-style:none;margin:0;padding:0;}
nav li a{display:block;padding:7px 22px;color:var(--text);text-decoration:none;font-size:14px;border-left:3px solid transparent;}
nav li a:hover{background:var(--panel2);color:#fff;}
nav li.active a{border-left-color:var(--accent);background:var(--panel2);color:#fff;font-weight:600;}
.sidebar-foot{color:var(--muted);font-size:11px;padding:16px 22px 4px;line-height:1.5;}
.sidebar-foot code{font-size:10px;}
main{margin-left:300px;padding:46px 6vw;}
.content{max-width:860px;margin:0 auto;}
.content h1{font-size:2em;line-height:1.2;margin:0 0 .5em;padding-bottom:.3em;border-bottom:1px solid var(--border);}
.content h2{font-size:1.45em;margin:1.9em 0 .6em;padding-top:.3em;}
.content h3{font-size:1.18em;margin:1.5em 0 .5em;color:#cfd5f0;}
.content a{color:var(--accent);text-decoration:none;}
.content a:hover{text-decoration:underline;}
.content p,.content li{color:var(--text);}
.content strong{color:#fff;}
.content code{background:var(--code);padding:.15em .42em;border-radius:5px;font-size:.88em;font-family:"SF Mono",ui-monospace,Menlo,Consolas,monospace;color:#cfe1ff;}
.content pre{background:var(--code);border:1px solid var(--border);border-radius:11px;padding:16px 18px;overflow:auto;}
.content pre code{background:none;padding:0;color:#dfe6ff;}
.content table{border-collapse:collapse;width:100%;margin:1.2em 0;font-size:.93em;display:block;overflow-x:auto;}
.content th,.content td{border:1px solid var(--border);padding:9px 12px;text-align:left;vertical-align:top;}
.content th{background:var(--panel2);color:#fff;font-weight:600;}
.content tr:nth-child(even) td{background:rgba(255,255,255,.018);}
.content blockquote{margin:1.2em 0;padding:.6em 1.1em;border-left:4px solid var(--accent);background:var(--panel2);border-radius:0 8px 8px 0;color:#dfe4f7;}
.content hr{border:none;border-top:1px solid var(--border);margin:2em 0;}
.toc-box{background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:8px 20px 14px;margin:0 0 2em;}
.toc-box::before{content:"On this page";display:block;font-size:11px;text-transform:uppercase;letter-spacing:.09em;color:var(--muted);font-weight:700;margin:10px 0 2px;}
.toc-box ul{list-style:none;margin:.2em 0;padding-left:14px;}
.toc-box>ul{padding-left:0;}
.toc-box a{color:var(--muted);text-decoration:none;font-size:.9em;display:block;padding:2px 0;}
.toc-box a:hover{color:var(--accent);}
#menu-toggle{display:none;position:fixed;top:14px;left:14px;z-index:20;background:var(--panel2);color:var(--text);border:1px solid var(--border);border-radius:9px;width:42px;height:42px;font-size:20px;cursor:pointer;}
@media(max-width:900px){
  #sidebar{transform:translateX(-100%);transition:transform .2s;z-index:15;}
  #sidebar.open{transform:none;}
  main{margin-left:0;padding:70px 6vw 40px;}
  #menu-toggle{display:block;}
}
"""


def main():
    if shutil.which("pandoc") is None:
        sys.exit("pandoc not found")
    if OUT.exists():
        shutil.rmtree(OUT)
    OUT.mkdir(parents=True)
    present = [(fn, t, g) for (fn, t, g) in DOCS if (HERE / fn).exists()]
    missing = [fn for (fn, _, _) in DOCS if not (HERE / fn).exists()]
    if missing:
        sys.stderr.write("skipping missing: " + ", ".join(missing) + "\n")
    for fn, title, _group in present:
        toc, body = pandoc_body(HERE / fn)
        toc_box = f'<div class="toc-box">{toc}</div>' if toc and "<li" in toc else ""
        page = PAGE.format(title=html.escape(title), css=CSS,
                           nav=build_nav(fn), toc_box=toc_box, body=body)
        (OUT / (slug(fn) + ".html")).write_text(page, encoding="utf-8")
    # landing = the decisions doc
    shutil.copyfile(OUT / "decisions-for-the-team.html", OUT / "index.html")
    print(f"built {len(present)} pages -> {OUT}")


if __name__ == "__main__":
    main()
