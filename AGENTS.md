# Agent instructions

- Write all project documentation in English, including this file, README files, and any new documentation.
- Verify every new feature or change with appropriate tests and commit successfully tested changes before handing off the work.
- Review pre-existing changes before including them in a commit; preserve local data and confidential email samples.
- Before committing, run `venv/bin/python -m unittest discover -s tests -v`, compile modified Python modules, and run `git diff --check`.
- Add regression tests for functional bug fixes. Automated tests must work without network access.
- Do not commit virtual environments, caches, bytecode, or real emails. Use synthetic test fixtures.
- Keep commits focused and descriptive. Pushing to a remote requires an explicit request.
