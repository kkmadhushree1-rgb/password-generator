# Secure Password Generator

- `web/` – browser app (open `web/index.html`). Files: index.html, style.css, script.js.
  Uses `crypto.getRandomValues`. Options: length, character types, custom symbols,
  excluded characters, keyword, start with a letter, no repeats.
- `python/password_generator.py` – module + CLI using the `secrets` module.
  Example: `python python/password_generator.py -l 24 -n 5`

Nothing is sent over the network or stored.
