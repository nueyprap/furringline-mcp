# Night Shift

This folder belongs to Night Shift, the nightly autonomous coding routine. Its rules and gate
live in `nueyprap/nuey-skills` under `scripts/night-shift/` and `.agents/skills/night-shift/`.

- `config.toml`: what Night Shift may change here and how the gate checks it.
- `gate.py`, `merge.py`: the trusted gate and merge step. GitHub runs them from the default branch.
- Pause Night Shift in this repository: add an empty file `.night-shift/PAUSED` on the default branch.

Do not edit these files by hand here: change them in nuey-skills and re-run the installer.
