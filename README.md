[![Tests](https://github.com/netascode/nac-validate/actions/workflows/test.yml/badge.svg)](https://github.com/netascode/nac-validate/actions/workflows/test.yml)
![Python Support](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13%20%7C%203.14-informational "Python Support: 3.11, 3.12, 3.13, 3.14")

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
  --fail-on [HIGH|MEDIUM|LOW]
                        Lowest rule severity that fails validation. Violations of less
                        severe rules are still reported, but do not affect the exit code
                        [env: NAC_VALIDATE_FAIL_ON] [default: LOW]
  --version             Display version number
  --list-artifacts      List the effective schema, artifact layers and validation rules and exit
  --artifacts / --no-artifacts
                        Experimental: also load schema and rules from bundles in nac/bundles/
                        and the installed Terraform module, applying nac/overrides.yaml.
                        Off by default (implied by --bundle and --module-dir); will become
                        the default in a future version [env: NAC_VALIDATE_ARTIFACTS]
  --bundle PATH         Experimental: path to an artifact bundle (zip, tar.gz or directory),
                        repeatable; implies --artifacts. Defaults to every .zip, .tar.gz or
                        .tgz file and directory in nac/bundles/ [env: NAC_VALIDATE_BUNDLE]
  --module-dir DIRECTORY
                        Experimental: path to a module directory containing nac/ artifacts;
                        implies --artifacts. Defaults to the module discovered via
                        terraform init [env: NAC_VALIDATE_MODULE_DIR]
  --help                Show this message and exit
```

## Exit Codes

The CLI uses specific exit codes to help automation distinguish between error types:

| Exit Code | Meaning |
|-----------|---------|
| 0 | Validation passed |
| 1 | Semantic validation failed (violations of rules at or above the `--fail-on` severity) |
| 2 | Syntax validation failed (YAML syntax or schema errors) |
| 3 | Configuration error (missing schema, invalid rules, etc.) |

## Failure Threshold

Every rule has a severity (`HIGH`, `MEDIUM` or `LOW`). By default a violation of any rule fails validation. `--fail-on` (or `NAC_VALIDATE_FAIL_ON`) sets the lowest severity that fails it, so rules can give advice without blocking a pipeline:

```text
$ nac-validate data/ -s schema.yaml -r rules/ --fail-on HIGH
...
  ✓ Semantic validation: PASSED (1 violation below failure threshold)

    • 1 MEDIUM severity violation (rules: 205) (below failure threshold)
$ echo $?
0
```

Violations below the threshold are still printed and included in the JSON output, marked `"blocking": false`.

The severity of a rule packaged in a bundle or module can be changed in `nac/overrides.yaml` (see [Packaged Schema and Rules](#packaged-schema-and-rules-experimental)).

## Ignore Comments

A comment in a data file exempts an object from rules:

```yaml
iosxe:
  devices:
    - name: edge-1  # nac-validate: ignore[505, 506] legacy peer, CHG-1234
      configuration:
        # nac-validate: ignore[205] mixed modes during migration
        interfaces:
          ...
# nac-validate: ignore-file[413]
```

- A comment after content applies to that entry and everything below it, a comment on its own line to the next entry, and `ignore-file` to every object in the file.
- Rule IDs are required. Text after them is the reason.
- Only violations with a `path` can be suppressed. List items are matched by the selectors in the path (`devices[name=edge-1]`), so comments keep working when files are merged.

Suppressed violations don't fail validation but are counted in the summary and listed in the JSON output. Comments that suppressed nothing are reported as a warning.

## How It Works

Syntactic validation is done by basic YAML syntax validation (e.g., indentation) and by providing a [Yamale](https://github.com/23andMe/Yamale) schema and validating all YAML files against that schema. Semantic validation is done by providing a set of rules (implemented in Python) which are then validated against the YAML data. Every rule is implemented as a Python class and should be placed in a `.py` file located in the `--rules` path.

## Schema Extensions

nac-validate extends Yamale with additional keyword arguments on the standard validators. Vanilla Yamale accepts and ignores them, so a schema using them still works with plain Yamale, which then just does not enforce them.

Extensions are checked once the data passed the Yamale validation. An extension keyword on a validator that does not support it, or with an invalid value, fails loading the schema (exit code 3). A keyword known neither to Yamale nor to nac-validate, like a misspelled one, is logged as a warning and ignored.

### Primary Keys

`primary_key` on a `list()` of maps names a field that every item must set to a single value (not a map or list), unique within the list:

```yaml
tenants: list(include('tenant'), primary_key='name')
---
tenant:
  name: str()
  vrfs: list(include('vrf'), primary_key='name', required=False)
vrf:
  name: str()
```

A composite key names several comma-separated fields, whose combination must be unique, so the same interface name can be used on different nodes:

```yaml
interfaces: list(include('interface'), primary_key='node_id,name')
```

Values of different types are distinct (`1` and `"1"` do not collide). Primary keys are checked in every file and, once every file passed, on the data merged from all files: items with the same key are only merged when all their shared fields match, so the same key used with conflicting values in two files remains a duplicate.

### Unique Values

`unique` on a `list()` requires values to be unique within the list without making them the key of an item. `unique=True` applies to a list of single values (items that are maps or lists are not compared):

```yaml
features: list(str(), unique=True)
```

On a list of maps, `unique` names comma-separated fields whose combination must be unique. Unlike with `primary_key`, the fields may be optional: a field that is not set is a value of its own, so a route without a `vrf` does not collide with the same prefix in a VRF, and items setting none of the fields are not compared:

```yaml
routes: list(include('route'), unique='prefix,vrf')
```

It can be combined with a `primary_key`, but must not name the same fields:

```yaml
zone_pairs: list(include('zone_pair'), primary_key='name', unique='source,destination')
```

As with primary keys, values of different types are distinct, and `unique` is checked in every file and, once every file passed, on the data merged from all files, where items from different files that don't merge still collide.

### References

A list declares what its items can be referenced as with `ref_name`, a field what it refers to with `ref`. The value of the field must then be the key of an item of such a list:

```yaml
device:
  vrfs: list(include('vrf'), primary_key='name', ref_name='vrf', ref_implicit='default,management')
interface:
  vrf: str(ref='vrf', required=False)
  vrfs: list(str(ref='vrf'), required=False)
```

- `ref_name` requires a single-field `primary_key`. Several lists may share a name, so a reference can name an item of any of them (e.g. hosts, networks and ranges as `network_object`)
- `ref_implicit` lists comma-separated values that exist without being defined in the data, such as default objects of the platform; `*` and `?` are globs (`system-*`)
- `ref` works on any validator of a single value, including the item validator of a list and `any()`. Values are compared as text, so an integer key matches its string form

Targets are looked up following the nesting of the data: for every list enclosing both the reference and a list of targets, both must be in the same item of it. A VRF defined in one device is not visible from another device, while a reference outside the `devices` list sees the VRFs of all devices.

`ref_in` names fields of the referencing item whose values select the items the target is in, the last one the innermost list's item. Paths are dotted and read from the nearest list item enclosing the reference. A selector that is not set falls back to nesting, and a selector naming an unknown item is only reported by its own `ref`:

```yaml
leak_destination:
  tenant: str(ref='tenant')
  vrf: str(ref='tenant_vrf', ref_in='tenant')
contract_master:
  application_profile: str(ref='application_profile', required=False)
  endpoint_group: str(ref='endpoint_group', ref_in='application_profile')
```

`ref_scope='any'` on a list with a single-field `primary_key` lifts the isolation of its items: a reference inside one tenant sees targets in all tenants.

### IP Forms

`type` on an `ip()` restricts the value to one or several comma-separated forms:

| Type | Accepted | Rejected |
|---|---|---|
| `address` | `10.0.0.1` | any prefix length |
| `interface` | `10.0.0.1/24` | no prefix length, network or broadcast address (`10.0.0.0/24`, `10.0.0.255/24`) |
| `network` | `10.0.0.0/24` | no prefix length, host bits set (`10.0.0.1/24`) |

```yaml
a: ip(version=4, type='address')
b: ip(type='interface')
c: ip(type='network')
d: ip(type='interface,network')
```

`interface` rejects the network address of the subnet, the IPv4 broadcast address and the IPv6 subnet-router anycast address (`2001:db8::/64`), except on IPv4 /31 and /32 and IPv6 /127 and /128 subnets. Prefix lengths must be numbers, netmasks like `10.0.0.1/255.255.255.0` are rejected.

### Ordered Lists

`ordered=True` on a `list()` marks the order of its items as significant. A list without it, or with `ordered=False`, has no significant order. It is not checked against the data:

```yaml
a: list(str(), ordered=True)
```

### Descriptions

`description` documents a schema element. It is supported on every validator and not checked against the data:

```yaml
tenants: list(include('tenant'), primary_key='name', description='Tenants of the fabric')
---
tenant:
  name: str(description='Name of the tenant')
```

## Packaged Schema and Rules (Experimental)

> **Note:** This feature is experimental and may change in future versions. It is not subject to semantic versioning guarantees.

Besides the local `--schema` and `--rules` paths, schema and rules can come from two more places. Loading them is currently opt-in: enable it with `--artifacts` or `NAC_VALIDATE_ARTIFACTS=true` (passing `--bundle` or `--module-dir` enables it as well). It will become the default in a future version, after which `--no-artifacts` turns it off.

```shell
nac-validate --artifacts data/
```

The layers are, highest priority first:

1. **Local**: `--schema`/`--rules`, or the `.schema.yaml` and `.rules/` defaults
2. **Bundle**: every `.zip`, `.tar.gz` or `.tgz` archive and every directory in the project's `nac/bundles/` (or the paths given with `--bundle`), holding `manifest.yaml`, `schema.yaml` and `rules/` at its root
3. **Module**: the `nac/` directory (`nac/schema.yaml`, `nac/rules/`) of the Terraform module installed by `terraform init` (or the one given with `--module-dir`)

A higher layer replaces the schema of a lower one and rules with the same ID. Rules of lower layers can be disabled, or given another severity, by ID in `nac/overrides.yaml`:

```yaml
disable:
  rules:
    - "101"
severity:
  rules:
    "205": LOW      # HIGH, MEDIUM or LOW
```

The severity replaces the one the rule declares, everywhere: in the output, the summary, the JSON output and the `--fail-on` check. Like disable entries, a bundle's `overrides.yaml` can set severities of module rules, and local rules are never affected (edit them instead). `--list-artifacts` shows each changed severity, who set it and what the rule declares, entries that match no rule, and entries without effect because a higher layer's rule shadows the rule they apply to.

Run `nac-validate --list-artifacts` to see the effective schema, the layers in use and where each rule comes from. It reads rules without running them: the `id`, `description` and `severity` of each rule are taken from the string or number literals in its `Rule` class, and a rule whose ID is not such a literal (computed or inherited) is listed as having an unknown ID. With `--artifacts` it still extracts bundle archives into `nac/bundles/.cache/`.

The project directory is the **current working directory**, not the location of the data, `--schema` or `--rules`: `nac/bundles/`, `nac/overrides.yaml` and the `.terraform/` directory (or `TF_DATA_DIR`) written by `terraform init` are looked up there. Run nac-validate from your root module directory, or point to the artifacts with `--module-dir` and `--bundle`.

### Trust

Rules are Python code that nac-validate executes, so bundles and modules need the same trust as code in your own repository. Review them with `--list-artifacts` (bundle archives are shown with a SHA-256 prefix) before enabling `--artifacts`. Note that a module update (`terraform init -upgrade`) or a new file in `nac/bundles/` changes which code runs, and `.terraform/` is usually not part of your reviewed changes.

Discovery is implemented in [nac-artifacts](https://github.com/netascode/nac-artifacts), which documents the bundle format in detail.

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
| `id` | Yes | — | Unique rule identifier, a number such as `"101"` or `101` (other IDs log a warning) |
| `description` | Yes | — | Short description of the rule |
| `severity` | No | `"HIGH"` | Severity level (`HIGH`, `MEDIUM`, `LOW`), compared against `--fail-on`. Any other value logs a warning and is treated as `HIGH`. Projects can change it for packaged rules in `nac/overrides.yaml` |
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
      "severity": "HIGH",
      "errors": [
        "apic.access_policies.aaeps[name=INFRA-AAEP].infra_vlan - AAEP 'INFRA-AAEP' has infra_vlan enabled but global infra_vlan is not defined"
      ],
      "blocking": true
    }
  ]
}
```

`semantic_errors` lists every violated rule, including those below the `--fail-on` threshold; `blocking` tells whether the rule's violations fail validation.

With [ignore comments](#ignore-comments), `suppressed` lists the suppressed violations (with the comment's file, line and reason) and `unused_ignores` the comments that suppressed nothing.

## Installation

Python 3.11+ is required to install `nac-validate`. Don't have Python 3.11 or later? See [Python 3 Installation & Setup Guide](https://realpython.com/installing-python/).

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
