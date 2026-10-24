# Unreleased

- Fix syntax validation failure for empty or comment-only YAML files
- Discover schema and rules packaged with an installed Terraform module (`nac/schema.yaml`, `nac/rules/`, located via `terraform init`'s `modules.json`) and with a bundle dropped into the project (any `.zip`, `.tar.gz` or `.tgz` file in `.nac/`, or an extracted `.nac/bundle/`); local `-s`/`-r` and `.schema.yaml`/`.rules/` take priority over the bundle, which takes priority over the module (archives are extracted once into a git-ignored `.nac/cache/`)
- Add `--bundle` (repeatable) and `--module-dir` CLI options (env `NAC_VALIDATE_BUNDLE`, `NAC_VALIDATE_MODULE_DIR`). Several bundles are peers of one priority tier and may split rules and the schema between them; a rule ID or schema provided by two bundles is an error, as are two bundles with the same manifest `name` (e.g. an old and a new version left in `.nac/`). Bundles in `.nac/` that provide nothing for nac-validate (e.g. only test templates) are skipped
- Add `--list-artifacts` CLI option showing the effective schema, artifact layers and rules with their origin; `--list-rules` remains as an undocumented alias
- Add `overrides.yaml` to disable rules of lower layers by rule ID (`disable: {rules: [...]}`): `.nac/overrides.yaml` in the project disables rules of a bundle and the module, a bundle's `overrides.yaml` disables rules of the module. Local rules are never affected. Entries are declarative: one that matches nothing is not an error, and `--list-artifacts` shows disabled rules and entries that matched no rule
- Add `Validator.from_project()` to build a validator from all artifact layers and overrides, as the CLI does; `Validator.from_paths()` keeps loading the given local paths only
- Fix duplicate rule IDs across multiple `-r` directories going undetected; they now raise an error instead of the later directory silently replacing the earlier rule

# 2.0.0

- Add `RuleBase` base class for semantic validation rules
- Overhaul CLI output: validation results now show structured errors with file paths, line context, and rule identifiers, followed by a checklist-style summary per rule
- Add `--json` CLI option for machine-readable JSON validation output
- Add `--list-rules` CLI option to display available validation rules
- Add `--no-color` CLI option to disable colored terminal output
- Add `--compact` CLI option to reduce output verbosity
- BREAKING CHANGE (via `nac-yaml`): Rework list merge logic — within-file duplicates are now preserved; if any file contains duplicate dict items in a list, merging is disabled for that entire list and items are concatenated instead
- BREAKING CHANGE (via `nac-yaml`): Two dict items in a list now merge when all shared primitive fields match, even if both sides have additional unique primitive fields

# 1.2.0

- Add `jmespath` as a direct dependency
- Enhance displayed paths in error messages by showing keys instead of indexes for list items

# 1.1.0

- Enhance error handling and logging
- Migrate to `uv` package manager
- Update license references

# 1.0.0

- BREAKING CHANGE: Rename tool from `iac-validate` to `nac-validate`
- Modernize CLI interface using [typer](https://github.com/fastapi/typer)
- BREAKING CHANGE: Do not deduplicate items in a list of primitive values, for example a list of strings
- BREAKING CHANGE: Deduplicate items in a list of dictionaries consistently, regardless of whether they are in the same file or not
- Add option to get access to schema from semantic validation rules

# 0.2.7

- Suppress Yamale syntax warnings when running Python 3.12+

# 0.2.6

- Fix issue with directly nested lists in YAML files

# 0.2.5

- Check non-default schema and rules paths for existence

# 0.2.4

- Dependency updates

# 0.2.3

- Handle file errors gracefully
- Allow empty YAML files

# 0.2.2

- Add `--non-strict` CLI argument to accept unexpected elements in YAML files

# 0.2.1

- Do not merge YAML dictionary list items, where each list item has unique attributes with primitive values

# 0.2.0

- Preserve YAML quotes in output
- Add `!env` tag to read values from environment variables

# 0.1.8

- Use `ruamel.yaml` package consistently

# 0.1.7

- Add `output` CLI argument

# 0.1.6

- Add YAML syntax validation

# 0.1.5

- Add pre-commit config

# 0.1.4

- Add support for logging multiple error messsages

# 0.1.3

- Add support for Ansible Vault encrypted values

# 0.1.2

- Allow multiple paths as argument

# 0.1.1

- No changes

# 0.1.0

- Initial release
