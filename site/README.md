# Showcase page

A single static page: `index.html` plus `data.js`. No build step, no dependencies, no server code.

## Updating the numbers

Every figure on the page is read from `evals/results/`. After new results are added:

```bash
python3 site/build.py
```

That rewrites `data.js`. Do not edit `data.js` or type numbers into `index.html`.

## Preview locally

```bash
python3 -m http.server 8000 --directory site
```

Then open http://127.0.0.1:8000/.

## Hosting

The page is hosted on Vercel at https://mcp-guard-nine.vercel.app. The Vercel project is connected to this
repository with its root directory set to `site`, so every push to `main` redeploys it and every pull request
gets a preview. There is no build step.

After adding results, run `python3 site/build.py` and commit the regenerated `data.js`; the deploy follows the
merge.
