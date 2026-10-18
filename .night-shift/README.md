# Nightly Repo Improvements

This folder belongs to Nightly Repo Improvements (once called Night Shift), the nightly routine
that improves this repository. Its rules and gate live in `nueyprap/nuey-skills` under `scripts/night-shift/` and `.agents/skills/nightly-repo-improvements/`.

- `config.toml`: what the nightly routine may change here and how the gate checks it.
- `gate.py`, `merge.py`: the trusted gate and merge step. GitHub runs them from the default branch.
- Pause it in this repository: add an empty file `.night-shift/PAUSED` on the default branch.

Do not edit these files by hand here: change them in nuey-skills and re-run the installer.
