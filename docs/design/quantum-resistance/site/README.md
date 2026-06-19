# Conceal post-quantum docs — interactive site

Generated from the markdown in `docs/design/quantum-resistance/` by `../build-site.py`
(requires `pandoc`). Self-contained HTML (no external dependencies).

Rebuild + serve:

    cd docs/design/quantum-resistance
    python3 build-site.py
    python3 -m http.server 8745 --bind 127.0.0.1 --directory site
    # open http://127.0.0.1:8745/

Landing page = the team decision dashboard (`decisions-for-the-team`).
