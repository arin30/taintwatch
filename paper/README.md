# Paper

`main.tex` is an IEEEtran conference draft. Tables and number macros in `generated/` are written
by code, so they always match the results:

    python -m taintwatch.paper

Rerun the evaluations first if you change the code:

    python -m taintwatch.evaluation
    python -m taintwatch.evaluation.outside
    python -m taintwatch.adversary

Build: upload this folder to Overleaf, or run `pdflatex main.tex` twice with a TeX distribution
(for example MiKTeX). A test fails if `generated/` differs from what the results produce.

Before submitting: fill in the TODOs (introduction, related work, authors), verify every
citation yourself, run a real-LLM evaluation, and remove any claim the data does not support.
