[![Tests](https://github.com/netascode/nac-validate/actions/workflows/test.yml/badge.svg)](https://github.com/netascode/nac-validate/actions/workflows/test.yml)
![Python Support](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13%20%7C%203.14-informational "Python Support: 3.10, 3.11, 3.12, 3.13, 3.14")

# nac-validate

A CLI tool to perform syntactic and semantic validation of YAML files.

```
$ nac-validate --help

Usage: nac-validate [OPTIONS] [PATHS]...

A CLI tool to perform syntactic and semantic validation of YAML files.

Arguments:
  [PATHS]...            List of paths pointing to YAML files or directories

Options:
  -v, --verbosity [DEBUG|INFO|WARNING|ERROR|CRITICAL]
                        Verbosity level [env: NAC_VALIDATE_VERBOSITY] [default: WARNING]
  -s, --schema FILE     Path to schema file [env: NAC_VALIDATE_SCHEMA] [default: .schema.yaml]
  -r, --rules DIRECTORY Path(s) to directories with semantic validation rules (repeatable)
                        [env: NAC_VALIDATE_RULES]
  -o, --output FILE     Write merged content from YAML files to a new YAML file
                        [env: NAC_VALIDATE_OUTPUT]
  --non-strict          Accept unexpected elements in YAML files
                        [env: NAC_VALIDATE_NON_STRICT]
  -f, --format [text|json]
                        Output format for validation results
                        [env: NAC_VALIDATE_FORMAT] [default: text]
  --no-color            Disable colored output [env: NO_COLOR]
  --compact             Use compact output format without rule context details
                        [env: NAC_VALIDATE_COMPACT]
  --version             Display version number
  --list-rules          List all available validation rules and exit
  --help                Show this message and exit
```

## Exit Codes

The CLI uses specific exit codes to help automation distinguish between error types:

| Exit Code | Meaning |
|-----------|---------|
| 0 | Validation passed |
| 1 | Semantic validation failed (business rule violations) |
| 2 | Syntax validation failed (YAML syntax or schema errors) |
| 3 | Configuration error (missing schema, invalid rules, etc.) |

## How It Works

Syntactic validation is done by basic YAML syntax validation (e.g., indentation) and by providing a [Yamale](https://github.com/23andMe/Yamale) schema and validating all YAML files against that schema. Semantic validation is done by providing a set of rules (implemented in Python) which are then validated against the YAML data. Every rule is implemented as a Python class and should be placed in a `.py` file located in the `--rules` path.

## Writing Validation Rules

Each `.py` file must have a single class named `Rule` that subclasses `RuleBase`. This class must set `id` and `description` as class attributes. It must implement a `classmethod()` named `match` that has a single function argument `data` which is the data read from all YAML files. It can optionally also have a second argument `schema` which would then provide the `Yamale` schema.

### Simple Rules (String List)

For simple validations, rules can return a list of strings describing each violation:

```python
from nac_validate import RuleBase


class Rule(RuleBase):
    id = "101"
    description = "Verify child naming restrictions"
    severity = "HIGH"

    @classmethod
    def match(cls, data):
        results = []
        try:
            for child in data["root"]["children"]:
                if child["name"] == "FORBIDDEN":
                    results.append("root.children.name" + " - " + str(child["name"]))
        except KeyError:
            pass
        return results
```

### Structured Rules (Recommended)

For richer output with context, explanations, and recommendations, subclass `RuleBase` and set the rich context attributes as class-level fields:

```python
from nac_validate import RuleBase, Violation


class Rule(RuleBase):
    id = "301"
    description = "Verify Infra VLAN Is Defined When Referenced by AAEPs"
    severity = "HIGH"

    # Rich context displayed in terminal output
    title = "INFRA VLAN CONFIGURATION WARNING"
    affected_items_label = "Affected AAEPs"
    explanation = """\
The Infrastructure VLAN (Infra VLAN) is critical for APIC-to-leaf
communication. When infra_vlan is enabled on an AAEP, the global
infra_vlan value must be explicitly defined."""
    recommendation = """\
Define the Infra VLAN in your access_policies configuration:

  apic:
    access_policies:
      infra_vlan: 3967
      aaeps:
        - name: INFRA-AAEP
          infra_vlan: true"""
    references = [
        "https://www.cisco.com/c/en/us/td/docs/dcn/aci/apic/all/apic-fabric-access-policies.html"
    ]

    @classmethod
    def match(cls, inventory):
        violations = []

        aaeps = inventory.get("apic", {}).get("access_policies", {}).get("aaeps", [])
        if aaeps is None:
            aaeps = []

        # Find AAEPs with infra_vlan enabled
        affected_aaeps = [
            aaep.get("name", "unnamed")
            for aaep in aaeps
            if aaep.get("infra_vlan", False)
        ]

        if affected_aaeps:
            infra_vlan = (
                inventory.get("apic", {})
                .get("access_policies", {})
                .get("infra_vlan", 0)
            )
            if infra_vlan == 0:
                for aaep_name in affected_aaeps:
                    violations.append(
                        Violation(
                            message=f"AAEP '{aaep_name}' has infra_vlan enabled but global infra_vlan is not defined",
                            path=f"apic.access_policies.aaeps[name={aaep_name}].infra_vlan",
                            details={
                                "aaep_name": aaep_name,
                                "infra_vlan_enabled": True,
                                "global_infra_vlan_defined": False,
                            },
                        )
                    )

        return violations
```

### RuleBase Attributes

All rules must subclass `RuleBase` and set at minimum `id` and `description`. The following class attributes are available:

| Attribute | Required | Default | Description |
|-----------|----------|---------|-------------|
| `id` | Yes | — | Unique rule identifier |
| `description` | Yes | — | Short description of the rule |
| `severity` | No | `"HIGH"` | Severity level (`HIGH`, `MEDIUM`, `LOW`) |
| `title` | No | `""` | Header displayed in violation output |
| `explanation` | No | `""` | Detailed explanation of why this matters |
| `recommendation` | No | `""` | How to fix the issue, with examples |
| `affected_items_label` | No | `"Affected Items"` | Label for the violations list |
| `references` | No | `[]` | Links to documentation |

Rich terminal output sections (title header, explanation, recommendation, references) are rendered individually for whichever attributes are set. Setting any of `title`, `explanation`, or `recommendation` enables enhanced output; only populated sections are shown.

**`Violation`** - Represents a single validation failure:

- `message` (str): Human-readable description of the issue
- `path` (str): Location in the YAML structure (e.g., `apic.tenants[name=PROD].vrfs[0]`)
- `details` (dict, optional): Machine-readable metadata for automation

## JSON Output

Use `--format json` for machine-readable output suitable for CI/CD pipelines:

```bash
nac-validate data/ -s schema.yaml -r rules/ --format json
```

Output structure:

```json
{
  "syntax_errors": [],
  "semantic_errors": [
    {
      "rule_id": "301",
      "description": "Verify Infra VLAN Is Defined When Referenced by AAEPs",
      "errors": [
        "apic.access_policies.aaeps[name=INFRA-AAEP].infra_vlan - AAEP 'INFRA-AAEP' has infra_vlan enabled but global infra_vlan is not defined"
      ]
    }
  ]
}
```

## Installation

Python 3.10+ is required to install `nac-validate`. Don't have Python 3.10 or later? See [Python 3 Installation & Setup Guide](https://realpython.com/installing-python/).

`nac-validate` can be installed in a virtual environment using `uv` or `pip`:

```bash
# Using uv (recommended)
uv tools install nac-validate

# Using pip
pip install nac-validate
```

## Pre-Commit Hook

The tool can be integrated via a [pre-commit](https://pre-commit.com/) hook with the following config (`.pre-commit-config.yaml`), assuming the default values (`.schema.yaml`, `.rules/`) are appropriate:

```yaml
repos:
  - repo: https://github.com/netascode/nac-validate
    rev: v1.0.0
    hooks:
      - id: nac-validate
```

In case the schema or validation rules are located somewhere else the required CLI arguments can be added like this:

```yaml
repos:
  - repo: https://github.com/netascode/nac-validate
    rev: v1.0.0
    hooks:
      - id: nac-validate
        args:
          - '-s'
          - 'my_schema.yaml'
          - '-r'
          - 'rules/'
```

## Ansible Vault Support

Values can be encrypted using [Ansible Vault](https://docs.ansible.com/ansible/latest/user_guide/vault.html). This requires Ansible (`ansible-vault` command) to be installed and the following two environment variables to be defined:

```
export ANSIBLE_VAULT_ID=dev
export ANSIBLE_VAULT_PASSWORD=Password123
```

`ANSIBLE_VAULT_ID` is optional, and if not defined will be omitted.

## Additional Tags

### Reading Environment Variables

The `!env` YAML tag can be used to read values from environment variables.

```yaml
root:
  name: !env VAR_NAME
```
