# FURRINGLINE catalog

Use the `furringline` tools to find FURRINGLINE building materials (gypsum board, ceiling and wall framing, T-bar ceilings, insulation, fixings) and to calculate materials for a job.

- Product names are in Thai; Thai keywords work best (ยิปซัม, โครงฝ้า, ทีบาร์, ฉนวน, สกรู). Brands: ตราช้าง (Elephant), Knauf, SCG, USG, Armstrong.
- For quantities, call `list_calculators`, then `calculate_materials` with the area in square metres. If the result is not complete, ask the user for the missing choice (for example the board type) and call again with `choices`.
- Prices are THB before 7% VAT and indicative. Always tell the user that only a formal FURRINGLINE quotation is binding.
