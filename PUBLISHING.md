# Publishing inpguard to PyPI

Status: package metadata and workflow are prepared; **nothing has been uploaded**.

The first release is `0.1.0`. Publishing uses PyPI Trusted Publishing through
GitHub Actions, so no API token or password is stored in the repository.

## One-time setup (only you can do this)

1. Create a PyPI account at <https://pypi.org/account/register/> and enable 2FA.
2. Add a **pending trusted publisher**:
   - PyPI → **Your account** → **Publishing** → **Add a new pending publisher**
   - PyPI project name: `inpguard`
   - Owner: `onurcetinkaya-ce`
   - Repository name: `inpguard`
   - Workflow name: `publish.yml`
   - Environment name: `pypi`
3. In GitHub, open **Settings → Environments** and create an environment named
   `pypi`. No secrets are needed.

The pending publisher is what lets the workflow publish the first release
without a token.

## Release

1. Confirm the version in `pyproject.toml` is the one you intend to publish.
2. Commit and push the packaging changes.
3. GitHub → **Releases** → **Draft a new release**.
4. Tag: `v0.1.0`; target: `main`; publish the release.
5. The **Publish** workflow builds the sdist and wheel, runs `twine check`, and
   uploads to PyPI. Watch the Actions tab.
6. Verify:

```bash
python -m pip install inpguard==0.1.0
inpguard --version
python -c "import inpguard; print(inpguard.__version__)"
```

## Local pre-flight (already run before handoff)

```bash
python3 -m venv /tmp/inpguard-build
/tmp/inpguard-build/bin/pip install build twine
/tmp/inpguard-build/bin/python -m build
/tmp/inpguard-build/bin/twine check dist/*
```

Then install the built wheel into a clean venv and run the CLI.

## What this does and does not change

Publishing makes the package installable and creates a real registry entry.
It does **not** create adoption by itself. The portal's evidence options count
dependent repositories, monthly registry downloads, distro inclusion, or an
ecosyste.ms critical flag. A new package starts near zero downloads. Do not
apply to the Cyber Verification Program again until at least one of those
metrics is real and verifiable; the support reply of 2026-11-08 confirmed there
is no pre-adoption path.
