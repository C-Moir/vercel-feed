# Contributing

## Adding AI tool signatures

Edit `fingerprints.js`, add to `AI_TOOLS`:

    { name: 'YourTool', pattern: /<!--[\s\S]*?Built with YourTool/i }

Rules:
- HTML comment patterns only (CSS/JS patterns produce false positives)
- Test against real HTML from the tool before submitting
- One signature per PR

## Adding framework signatures

Edit `fingerprints.js`, add to `FRAMEWORKS`:

    { name: 'YourFramework', htmlPattern: /window\.__yourSignal/i }

Header detection preferred over HTML pattern where possible.
