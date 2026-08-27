# AIPAM Static Demo (Standalone)

This frontend supports a static demo mode that runs without backend services.

## What demo mode does

- Uses precomputed fictional data (Emotet + Cobalt Strike narrative).
- Disables real upload/download side effects.
- Enables a 16-step guided walkthrough across upgraded AIPAM screens.
- Keeps routes and UI behavior aligned with the real app structure.

## Run locally

```bash
npm run dev:demo
```

## Build for GitHub Pages

Choose the script that matches your repository name (the Pages URL path):

```bash
npm run build:demo:pages
```

For `https://nhanbc.github.io/AIPAM_DEMO/`:

```bash
npm run build:demo:pages:nhan
```

The script uses base path `/AIPAMDEMO2/`, suitable for repository pages at:

`https://<your-user>.github.io/AIPAMDEMO2/`

## Publish quick steps

1. Build demo artifacts with SPA fallback (`dist/404.html`) for deep links:

```bash
npm run build:demo:pages
```

2. Push `dist/` contents to the `AIPAMDEMO2` repository branch you publish from (commonly `gh-pages` or `main` depending on your Pages settings).

3. Verify the walkthrough opens and steps 1–16 navigate correctly.
