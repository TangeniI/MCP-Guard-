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

## Hosting (both free)

**Vercel.** Import the GitHub repository, set **Root Directory** to `site`, leave the framework as "Other"
and the build command empty. Vercel can deploy from a private repository.

**GitHub Pages.** In the repository's settings, under Pages, choose "Deploy from a branch" and serve the
`site` folder, or copy the two files to a `docs`-style Pages folder. On a free GitHub account, Pages needs the
repository to be public.

The page links to the GitHub repository and to three documents in it. Those links only work for visitors
once the repository is public.
