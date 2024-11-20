# Publishing entropy-chaos to PyPI

## Prerequisites

```bash
pip install build twine
```

---

## First time: Create the PyPI project

1. Register at https://pypi.org/account/register/
2. Create the project page at https://pypi.org/manage/projects/ (it auto-creates on first upload)

---

## Option A — Trusted Publishing (recommended, no API key needed)

This uses GitHub's OIDC to authenticate with PyPI without storing any secrets.

### 1. Configure Trusted Publisher on PyPI

Go to: https://pypi.org/manage/project/entropy-chaos/settings/publishing/

Add a **new pending publisher** with:
```
PyPI Project Name : entropy-chaos
Owner             : <your-github-username>
Repository        : entropy-chaos
Workflow name     : ci.yml
Environment name  : pypi
```

### 2. Push a release tag

```bash
git tag v0.3.0
git push origin v0.3.0
```

The GitHub Actions CI pipeline will automatically:
1. Run all 128 tests across Python 3.10/3.11/3.12
2. Build the wheel + sdist
3. Publish to PyPI via OIDC (no secrets needed)
4. Create a GitHub Release with CHANGELOG notes

---

## Option B — API token (manual upload)

### 1. Build locally

```bash
python -m build
twine check dist/*
```

### 2. Upload to PyPI

```bash
# First upload (creates the project)
twine upload dist/*
# Username: __token__
# Password: pypi-AgENdGVzdC5weXBpLm9yZ...  (your API token)
```

### 3. Using `.pypirc` (avoids typing credentials)

Create `~/.pypirc`:
```ini
[distutils]
index-servers = pypi

[pypi]
repository = https://upload.pypi.org/legacy/
username = __token__
password = pypi-AgEN...your-token-here
```

Then just:
```bash
twine upload dist/*
```

---

## Versioning workflow

1. Update `entropy/__init__.py`: `__version__ = "0.3.1"`
2. Update `pyproject.toml`: `version = "0.3.1"`
3. Add entry to `CHANGELOG.md`
4. Commit: `git commit -am "chore: bump to v0.3.1"`
5. Tag: `git tag v0.3.1 && git push origin v0.3.1`

---

## Test PyPI (optional dry run)

```bash
twine upload --repository testpypi dist/*
pip install --index-url https://test.pypi.org/simple/ entropy-chaos==0.3.0
entropy --version
```

---

## Post-publish checklist

- [ ] `pip install entropy-chaos==0.3.0` works
- [ ] `entropy --version` returns `entropy 0.3.0`
- [ ] PyPI page shows correct description (from README.md)
- [ ] GitHub Release created with CHANGELOG notes
- [ ] SARIF uploaded to GitHub Code Scanning
