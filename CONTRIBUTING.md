# Contributing to TaintWatch

Thank you for your interest in contributing to **TaintWatch**!
We welcome contributions from developers, security researchers, and AI engineers worldwide.

Whether you're fixing a typo, adding an integration, improving documentation, or optimizing performance, your help is appreciated.

---

## Code of Conduct

We are committed to providing a welcoming, inclusive, and harassment-free environment.
Please review our [Code of Conduct](CODE_OF_CONDUCT.md) before participating.

---

## Getting Started

### 1. Prerequisites
- **Python 3.11+**
- **Node.js 20+** and `npm` (for the web UI)
- `git`

### 2. Fork and Clone
```bash
git clone https://github.com/eyadstein/taintwatch.git
cd taintwatch
```

### 3. Python Environment Setup
```bash
python -m venv .venv
# On Linux/macOS:
source .venv/bin/activate
# On Windows:
.venv\Scripts\activate

pip install -e ".[dev,server,notebooks]"
```

### 4. Web UI Setup
```bash
cd web
npm install
cd ..
```

---

## Development Workflow

Before submitting a Pull Request, please ensure all quality checks pass:

```bash
# 1. Lint checks
ruff check src tests

# 2. Strict type checking
mypy src tests

# 3. Test suite
pytest

# 4. Web type checking and tests
cd web
npm run typecheck
npm test -- --run
npm run build
cd ..
```

---

## Finding Tasks to Work On

Check out our [Catalog of 30+ Contributor Tasks](docs/CONTRIBUTING_TASKS_30.md) for well-scoped, beginner-to-intermediate tasks marked `good first issue` and `help wanted` across:
- Model & Framework Integrations (LlamaIndex, AutoGen, Semantic Kernel, Haystack)
- Web UI & Interactive Visualizations
- Benchmarking & Scenario Additions
- Policy DSL Enhancements
- Performance Optimizations & Documentation

---

## Submitting a Pull Request (PR)

1. Create a feature branch from `main`:
   ```bash
   git checkout -b feature/my-cool-feature
   ```
2. Commit with descriptive commit messages.
3. Push to your fork and open a Pull Request against `eyadstein/taintwatch:main`.
4. Ensure CI checks pass.
