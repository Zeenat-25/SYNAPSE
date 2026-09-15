# README asset guide

Copy `README.md` to `SYNAPSE/README.md` and the entire `assets/readme/` folder to `SYNAPSE/assets/readme/`. Keep the paths and filename capitalization intact. The ZIP contains a top-level SYNAPSE folder; copy its contents into your existing repository.

## Included assets and exact placement

```text
SYNAPSE/assets/readme/
├── ASSETS.md
├── hero.gif                    # Eight-second looping evidence-flow animation
├── hero.svg                    # Static accessible hero fallback; complete SVG source
├── dashboard-placeholder.svg   # Clearly labeled fictional dashboard mockup
├── blindspot-demo.svg          # Evidence overload diagram
├── synapse-flow.svg            # Conceptual blind spot heuristic
├── coverage-demo.svg           # Fictional risk/coverage interface
├── evidence-graph.svg          # Deterministic relationship illustration
├── audit-chain.svg             # Conceptual hash chain
├── analyst-demo.svg            # Scripted AI conversation illustration
├── report-placeholder.svg      # Clearly labeled report layout placeholder
└── footer.svg                  # Brand footer
```

All SVG files contain editable source, embedded titles/descriptions, and local geometry. No JavaScript, remote fonts, external images, CSS animation or foreignObject is required. Typography uses system font fallbacks. The README includes two Mermaid diagrams, a compact technology matrix and three linked Shields.io button images. Shields images require that third-party service; their target links are the project URLs supplied by the author.

## Replace placeholders with actual screenshots

1. Capture a redacted dashboard using only synthetic evidence. Remove personal information, real case identifiers, credentials, local paths and sensitive indicators. Export to `SYNAPSE/assets/readme/dashboard-preview.webp`, ideally at least 1600 pixels wide.
2. Change `assets/readme/dashboard-placeholder.svg` in README.md to `assets/readme/dashboard-preview.webp`. Update the alt text to describe the actual screen and remove the illustration caption only after a real screenshot is present.
3. Export a redacted first page from a genuine SYNAPSE PDF report to `SYNAPSE/assets/readme/report-preview.png`, ideally at least 1400 pixels wide. Change the report image path and alt text accordingly; remove the placeholder caption only after replacement.

These optional replacement files are deliberately not referenced as images until supplied, so the delivered README has no missing local assets.

## Motion and static fallback

The hero uses a slow GIF signal to communicate movement through the evidence pipeline. GIF is used because SVG animation can vary by renderer. The static equivalent is linked immediately below the hero. To make the README entirely static, change the first image source from `assets/readme/hero.gif` to `assets/readme/hero.svg`. No animated SVG is required. Other panels stay still for readability.

## Verification scope

Content and setup instructions are based on the supplied project brief. The live source and deployments could not be independently retrieved during preparation. External service availability, installed feature behavior, model metrics, environment configuration and local startup have therefore not been independently verified. All referenced local assets were checked for existence and all SVGs for well-formed XML. Demo values and report/dashboard placeholders are explicitly labeled. No real screenshots or actual report exports were supplied.
