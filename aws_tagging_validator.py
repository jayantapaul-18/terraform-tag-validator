# tf_plan_tag_analyze.py
import os
import sys
import json
import pprint as pp
import argparse
from collections import defaultdict
from typing import Dict, List, Tuple, Any, Optional
from dataclasses import dataclass
import yaml

COLORS = {
    "RED": "\033[91m",
    "GREEN": "\033[92m",
    "YELLOW": "\033[93m",
    "BLUE": "\033[94m",
    "MAGENTA": "\033[95m",
    "CYAN": "\033[96m",
    "WHITE": "\033[97m",
    "RESET": "\033[0m",
    "ORANGE": "\033[38;5;208m", # Added Orange for Warnings
}

@dataclass
class TagRule:
    key: str
    allowed_values: List[str] = None
    case_insensitive: bool = False
    suggestion: str = ""

    def __post_init__(self):
        if self.allowed_values is None:
            self.allowed_values = []

    def as_dict(self) -> Dict[str, Any]:
        return {
            "key": self.key,
            "allowed_values": self.allowed_values,
            "case_insensitive": self.case_insensitive,
            "suggestion": self.suggestion
        }

@dataclass
class EnvironmentConfig:
    env_name: str
    environment_tag: TagRule
    default: bool = False

    def as_dict(self) -> Dict[str, Any]:
        return {
            "env_name": self.env_name,
            "environment_tag": self.environment_tag.as_dict(),
            "default": self.default
        }

@dataclass
class ResourceViolations:
    missing_mandatory: List[TagRule]
    invalid_mandatory: List[Tuple[TagRule, str]] # Store rule and the invalid value found
    missing_optional: List[TagRule]

    def as_dict(self) -> Dict[str, List[Any]]:
         return {
             "missing_mandatory": [rule.as_dict() for rule in self.missing_mandatory],
             # Store rule and value found for invalid mandatory tags
             "invalid_mandatory": [{"rule": rule.as_dict(), "found_value": value} for rule, value in self.invalid_mandatory],
             "missing_optional": [rule.as_dict() for rule in self.missing_optional],
         }

    def has_errors(self) -> bool:
        """Checks if there are any mandatory violations (errors)."""
        return bool(self.missing_mandatory or self.invalid_mandatory)

    def has_warnings(self) -> bool:
        """Checks if there are any optional tag warnings."""
        return bool(self.missing_optional)

    def has_issues(self) -> bool:
        """Checks if there are any errors or warnings."""
        return self.has_errors() or self.has_warnings()

class TagValidatorConfig:
    def __init__(self, config_path: str, debug: bool = False):
        self.mandatory_rules: Dict[str, List[TagRule]] = defaultdict(list)
        self.optional_tags: List[TagRule] = []
        self.excluded_resources: List[str] = []
        self.environment_configs: List[EnvironmentConfig] = []
        self.default_environment: str = "LOWER"
        self.debug = debug
        self._load_configs(config_path)
        self._validate_configs()
        if self.debug:
            print("--- TagValidatorConfig Initialized ---", file=sys.stderr)
            # Add pprint or detailed logging here if needed when debug is true

    def _load_configs(self, config_path: str):
        try:
            env_config_file = os.path.join(config_path, "env_config.yaml")
            tag_rules_file = os.path.join(config_path, "tag_rules.yaml")

            if not os.path.exists(env_config_file):
                raise FileNotFoundError(f"Environment config file not found: {env_config_file}")
            if not os.path.exists(tag_rules_file):
                raise FileNotFoundError(f"Tag rules file not found: {tag_rules_file}")

            # Load environment config
            with open(env_config_file) as f:
                env_config = yaml.safe_load(f) or {}

            self.default_environment = env_config.get("default_environment", "LOWER").upper()
            self.environment_configs = []

            for env_name, rules in env_config.get("environments", {}).items():
                env_name = env_name.upper()
                env_tag_config = rules.get("Environment", {})
                self.environment_configs.append(
                    EnvironmentConfig(
                        env_name=env_name,
                        environment_tag=TagRule(
                            key="Environment",
                            allowed_values=env_tag_config.get("allowed_values", []),
                            suggestion=env_tag_config.get("suggestion", "")
                        ),
                        default=(env_name == self.default_environment)
                    )
                )

            # Load tag rules
            with open(tag_rules_file) as f:
                tag_rules = yaml.safe_load(f) or {}

            # Process mandatory rules
            self.mandatory_rules = defaultdict(list)
            for resource_type, rules in tag_rules.get("mandatory_rules", {}).items():
                 if rules: # Ensure rules is not None
                    for rule_data in rules:
                         if rule_data and 'key' in rule_data: # Ensure rule_data is a dict and has a key
                            self.mandatory_rules[resource_type].append(
                                TagRule(
                                    key=rule_data.get("key"),
                                    allowed_values=rule_data.get("allowed_values"), # None becomes [] in __post_init__
                                    case_insensitive=rule_data.get("case_insensitive", False),
                                    suggestion=rule_data.get("suggestion", "")
                                )
                            )

            # Process optional tags
            self.optional_tags = []
            for rule_data in tag_rules.get("optional_tags", []):
                if rule_data and 'key' in rule_data: # Ensure rule_data is a dict and has a key
                    self.optional_tags.append(
                        TagRule(
                            key=rule_data.get("key"),
                            allowed_values=rule_data.get("allowed_values"), # None becomes [] in __post_init__
                            case_insensitive=rule_data.get("case_insensitive", False),
                            suggestion=rule_data.get("suggestion", "")
                        )
                    )

            self.excluded_resources = tag_rules.get("excluded_resources", [])

        except FileNotFoundError as e:
             raise e # Re-raise file not found errors directly
        except Exception as e:
            raise RuntimeError(f"Config loading failed from '{config_path}': {str(e)}") from e

    def _validate_configs(self):
        if not self.mandatory_rules.get("global"):
            raise ValueError("Missing or empty 'global' mandatory rules in tag_rules.yaml")
        if not any(cfg.default for cfg in self.environment_configs):
            # Attempt to find the default environment name if not explicitly marked
            default_env_exists = any(cfg.env_name == self.default_environment for cfg in self.environment_configs)
            if not default_env_exists:
                raise ValueError(f"The configured default environment ('{self.default_environment}') was not found in env_config.yaml")
            else:
                 # If the default exists but isn't marked, mark it now (optional, good practice)
                 for cfg in self.environment_configs:
                     if cfg.env_name == self.default_environment:
                         cfg.default = True
                         break


class TerraformTagValidator:
    def __init__(self, config: TagValidatorConfig, debug: bool = False, color: bool = False):
        self.config = config
        self.debug_enabled = debug
        self.color_enabled = color
        self.current_env = os.getenv("DEPLOYMENT_ENV", config.default_environment).upper()
        self.env_config = self._get_environment_config()

    def _debug_log(self, message: str):
        """Conditional debug logging with color"""
        if self.debug_enabled:
            colored_msg = self._colorize(f"[DEBUG] {message}", "CYAN")
            print(colored_msg, file=sys.stderr)

    def _colorize(self, text: str, color: str) -> str:
        """Apply color if enabled and TTY detected"""
        # Check both stdout and stderr - log messages might go to stderr
        if self.color_enabled and (sys.stdout.isatty() or sys.stderr.isatty()):
            color_code = COLORS.get(color.upper(), COLORS["RESET"])
            return f"{color_code}{text}{COLORS['RESET']}"
        return text

    def _get_environment_config(self) -> EnvironmentConfig:
        """Gets the config for the current or default environment."""
        for cfg in self.config.environment_configs:
            if cfg.env_name == self.current_env:
                self._debug_log(f"Using environment config for: {self.current_env}")
                return cfg
        # Fallback to default if current_env config not found
        default_cfg = next((cfg for cfg in self.config.environment_configs if cfg.default), None)
        if default_cfg:
            self._debug_log(f"Using default environment config: {default_cfg.env_name}")
            return default_cfg
        # This should not happen if _validate_configs passed, but as a safeguard:
        raise RuntimeError("Could not determine environment configuration.")


    def _get_mandatory_rules(self, resource_type: str) -> List[TagRule]:
        """Merges global and resource-specific mandatory rules, ensuring uniqueness."""
        global_rules = self.config.mandatory_rules.get("global", [])
        resource_rules = self.config.mandatory_rules.get(resource_type, [])

        seen_keys = set()
        merged_rules = []

        # Add environment rule first (always mandatory)
        env_rule = self.env_config.environment_tag
        merged_rules.append(env_rule)
        seen_keys.add(env_rule.key)

        # Add other global and resource-specific rules
        for rule in global_rules + resource_rules:
             # Check rule validity before processing
            if rule and rule.key and rule.key not in seen_keys:
                merged_rules.append(rule)
                seen_keys.add(rule.key)

        return merged_rules

    def validate_plan(self, plan_path: str) -> Dict[str, ResourceViolations]:
        """Validates the Terraform plan file against configured rules."""
        try:
            with open(plan_path) as f:
                plan_data = json.load(f)

            violations: Dict[str, ResourceViolations] = {}
            total_resources = 0
            analyzed_resources = 0

            for resource in plan_data.get("resource_changes", []):
                total_resources += 1
                address = resource.get("address", "unknown")
                resource_type = resource.get("type", "")

                if self._should_skip_resource(resource):
                    self._debug_log(f"Skipping resource: {address} (Type: {resource_type}, Actions: {resource.get('actions', [])})")
                    continue

                analyzed_resources += 1
                self._debug_log(f"Analyzing resource: {address} (Type: {resource_type})")

                tags = self._extract_tags(resource)
                self._debug_log(f"Extracted tags for {address}: {tags}")

                resource_violations = self._validate_resource_tags(resource_type, tags)

                if resource_violations.has_issues():
                     violations[address] = resource_violations


            self._debug_log(f"Analyzed {analyzed_resources}/{total_resources} resources")
            return violations

        except FileNotFoundError:
             raise RuntimeError(f"Validation failed: Plan file not found at '{plan_path}'")
        except json.JSONDecodeError:
            raise RuntimeError(f"Validation failed: Could not parse JSON from plan file '{plan_path}'")
        except Exception as e:
            raise RuntimeError(f"Validation failed during plan processing: {str(e)}") from e

    def _should_skip_resource(self, resource: Dict) -> bool:
        """Determines if a resource should be skipped based on actions or type."""
        actions = resource.get("actions", [])
        # Skip if the only action is "no-op" or if "delete" is present (unless "create" is also present - create_before_destroy)
        if actions == ["no-op"]:
            return True
        if "delete" in actions and "create" not in actions and "update" not in actions:
             return True
        # Skip if resource type is excluded
        return resource.get("type", "") in self.config.excluded_resources

    def _extract_tags(self, resource: Dict) -> Dict[str, str]:
        """Extracts tags from various common Terraform structures within a resource change."""
        tags = {}
        # 'after_unknown' might contain planned tags not yet known. Prioritize 'after'.
        config = resource.get("change", {}).get("after", {})
        if not isinstance(config, dict): # Handle cases where 'after' might be null or not a dict
            config = {}

        # Handle standard 'tags' map
        if isinstance(config.get("tags"), dict):
            tags.update({k: str(v) for k, v in config["tags"].items() if v is not None}) # Ensure values are strings

        # Handle 'tags_all' map (often includes default tags, overrides 'tags')
        if isinstance(config.get("tags_all"), dict):
            tags.update({k: str(v) for k, v in config["tags_all"].items() if v is not None}) # Ensure values are strings

        # Handle list-formatted tags (e.g., aws_autoscaling_group 'tag' block)
        if isinstance(config.get("tag"), list):
            for tag_spec in config["tag"]:
                if isinstance(tag_spec, dict):
                    key = tag_spec.get("key")
                    # Value might be boolean, number, etc. Convert to string.
                    value = tag_spec.get("value")
                    if key is not None and value is not None: # Check key and value are not None
                        tags[key] = str(value)

        return tags

    def _validate_resource_tags(self, resource_type: str, tags: Dict[str, str]) -> ResourceViolations:
        """Validates mandatory and optional tags for a single resource."""
        mandatory_rules = self._get_mandatory_rules(resource_type)
        optional_rules = self.config.optional_tags

        missing_mandatory: List[TagRule] = []
        invalid_mandatory: List[Tuple[TagRule, str]] = []
        missing_optional: List[TagRule] = []

        # 1. Validate Mandatory Tags
        for rule in mandatory_rules:
            tag_value = tags.get(rule.key) # Use .get() for safer access

            if tag_value is None: # Check if tag exists
                missing_mandatory.append(rule)
                self._debug_log(f"MISSING Mandatory Tag: '{rule.key}' for resource type '{resource_type}'")
                continue # Skip value validation if missing

            # Check value validity if allowed_values are specified
            if rule.allowed_values:
                 valid, _ = self._validate_value(tag_value, rule)
                 if not valid:
                     invalid_mandatory.append((rule, tag_value))
                     self._debug_log(f"INVALID Mandatory Tag Value: '{rule.key}' = '{tag_value}' for resource type '{resource_type}'. Allowed: {rule.allowed_values} (Case Insensitive: {rule.case_insensitive})")


        # 2. Check for Missing Optional Tags
        for rule in optional_rules:
             if rule.key not in tags:
                 missing_optional.append(rule)
                 self._debug_log(f"MISSING Optional Tag (Warning): '{rule.key}' for resource type '{resource_type}'")


        return ResourceViolations(
             missing_mandatory=missing_mandatory,
             invalid_mandatory=invalid_mandatory,
             missing_optional=missing_optional
        )

    def _validate_value(self, value: str, rule: TagRule) -> Tuple[bool, str]:
        """Validates a single tag value against a rule. Returns (isValid, reason)"""
        if not rule.allowed_values:
            return True, "No specific values required." # Any value is OK if list is empty

        value_to_check = str(value) # Ensure we're comparing strings
        allowed_values_to_check = [str(v) for v in rule.allowed_values]

        if rule.case_insensitive:
            value_lower = value_to_check.lower()
            is_valid = any(v.lower() == value_lower for v in allowed_values_to_check)
            reason = f"Value '{value}' is not in allowed list (case-insensitive): {rule.allowed_values}"
        else:
            is_valid = value_to_check in allowed_values_to_check
            reason = f"Value '{value}' is not in allowed list (case-sensitive): {rule.allowed_values}"

        return is_valid, "" if is_valid else reason


    ## --- Report Generation ---

    def generate_console_report(self, violations: Dict[str, ResourceViolations]) -> str:
        """Generates a color-coded console report."""
        if not violations:
            return self._colorize("✅ All analyzed resources comply with tagging requirements.", "GREEN")

        report = []
        report.append(self._colorize("\n🚫 Tag Compliance Issues Detected", "RED"))
        report.append(self._colorize("=====================================", "RED"))

        total_missing_mand = 0
        total_invalid_mand = 0
        total_missing_opt = 0
        resources_with_errors = 0
        resources_with_warnings = 0

        # Sort resources by address for consistent output
        sorted_addresses = sorted(violations.keys())

        for address in sorted_addresses:
            details = violations[address]
            has_error = details.has_errors()
            has_warning = details.has_warnings()

            if has_error: resources_with_errors += 1
            if has_warning: resources_with_warnings += 1

            report.append(f"\n{self._colorize('Resource:', 'CYAN')} {address}")

            # Mandatory Missing (Error)
            if details.missing_mandatory:
                report.append(self._colorize("  ❌ Missing mandatory tags:", "RED"))
                for rule in details.missing_mandatory:
                    suggestion = f" (Suggestion: {rule.suggestion})" if rule.suggestion else ""
                    report.append(f"    - {rule.key}{suggestion}")
                    total_missing_mand += 1

            # Mandatory Invalid (Error)
            if details.invalid_mandatory:
                report.append(self._colorize("  ❌ Invalid mandatory tag values:", "RED"))
                for rule, found_value in details.invalid_mandatory:
                    allowed = ", ".join(map(str, rule.allowed_values))
                    case_note = "(case-insensitive)" if rule.case_insensitive else "(case-sensitive)"
                    msg = (f"    - {rule.key}: Found value '{found_value}' is not allowed. "
                           f"Expected {case_note}: [{allowed}]")
                    report.append(msg)
                    total_invalid_mand += 1

            # Optional Missing (Warning)
            if details.missing_optional:
                report.append(self._colorize("  ⚠️ Missing suggested tags (Warning):", "ORANGE"))
                for rule in details.missing_optional:
                    suggestion = f" (Suggestion: {rule.suggestion})" if rule.suggestion else ""
                    # Provide example format for adding the tag
                    example = f"Example: Add ` {rule.key} = \"some_value\" ` to your resource tags."
                    report.append(f"    - {rule.key}{suggestion}")
                    report.append(f"      {self._colorize(example, 'YELLOW')}")
                    total_missing_opt += 1


        # --- Summary ---
        summary = [
            self._colorize("\n📊 REPORT SUMMARY:", "MAGENTA"),
            f"Total resources analyzed: {len(violations)} found with issues", # Corrected wording
            # f"Total resources analyzed: {analyzed_resources}" # Need to pass this value if required
        ]
        status_color = "RED" if resources_with_errors > 0 else ("ORANGE" if resources_with_warnings > 0 else "GREEN")
        status_text = "FAIL (Mandatory Errors)" if resources_with_errors > 0 else ("WARN (Suggested Missing)" if resources_with_warnings > 0 else "PASS")

        summary.append(f"Overall Status: {self._colorize(status_text, status_color)}")

        if resources_with_errors > 0:
             summary.append(self._colorize(f"Resources with ERRORS: {resources_with_errors}", "RED"))
             summary.append(f"  - Total Missing Mandatory Tags: {total_missing_mand}")
             summary.append(f"  - Total Invalid Mandatory Tags: {total_invalid_mand}")
        if resources_with_warnings > 0:
             summary.append(self._colorize(f"Resources with WARNINGS: {resources_with_warnings}", "ORANGE"))
             summary.append(f"  - Total Missing Suggested Tags: {total_missing_opt}")

        summary.append(self._colorize("=====================================", "RED" if resources_with_errors else "ORANGE"))

        report.extend(summary)

        return "\n".join(report)

    def generate_json_report(self, violations: Dict[str, ResourceViolations]) -> str:
         """Generates a JSON report."""
         output_violations = {addr: v.as_dict() for addr, v in violations.items()}

         has_errors = any(v.has_errors() for v in violations.values())
         # has_warnings = any(v.has_warnings() for v in violations.values()) # Optional: include warning status

         status = "FAIL" if has_errors else "PASS" # Simplified status based on errors only for exit code logic

         summary = {
             "total_resources_with_issues": len(violations),
             "total_mandatory_errors": sum(len(v.missing_mandatory) + len(v.invalid_mandatory) for v in violations.values()),
             "total_suggested_warnings": sum(len(v.missing_optional) for v in violations.values()),
             "status": status
         }

         report_data = {
            "violations": output_violations,
            "summary": summary
         }
         return json.dumps(report_data, indent=2)


def log_audit_info(color_enabled: bool):
    """Logs GitLab CI environment information if available."""
    ci_vars = {
        "Project Path": os.getenv("CI_PROJECT_PATH"),
        "Branch/Tag": os.getenv("CI_COMMIT_REF_NAME"), # More general than CI_COMMIT_BRANCH
        "Pipeline ID": os.getenv("CI_PIPELINE_ID"),
        "Job ID": os.getenv("CI_JOB_ID"),
        "User": os.getenv("GITLAB_USER_LOGIN") or os.getenv("GITLAB_USER_EMAIL"), # Try login first
    }
    # Filter out None values
    available_vars = {k: v for k, v in ci_vars.items() if v}

    if not available_vars:
        print("[AUDIT] No GitLab CI environment variables detected.", file=sys.stderr)
        return

    # Use _colorize directly if needed, adapting its logic slightly
    def _audit_colorize(text: str, color: str) -> str:
        if color_enabled and sys.stderr.isatty():
             color_code = COLORS.get(color.upper(), COLORS["RESET"])
             return f"{color_code}{text}{COLORS['RESET']}"
        return text

    print(_audit_colorize("--- 🔍 AUDIT LOG INFO ---", "BLUE"), file=sys.stderr)
    for key, value in available_vars.items():
        print(f"  {key}: {value}", file=sys.stderr)
    print(_audit_colorize("------------------------", "BLUE"), file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(
        description="Validates tags in a Terraform plan JSON file against configured rules.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Environment Variables:
  DEPLOYMENT_ENV:     Overrides the current environment context (e.g., PROD, LOWER).
                      Defaults to 'default_environment' in env_config.yaml.
  TAG_DEBUG_LOG=1:    Enable debug logging (equivalent to --debug).
  TAG_COLOR_LOGS=1:   Enable colored output (equivalent to --color).
  SKIP_TAG_VALIDATION=1: Skip all tag validation (equivalent to --skip-validation).
"""
    )
    parser.add_argument("plan_file", help="Path to Terraform plan JSON file.")
    parser.add_argument("--config", default="config", help="Config directory path (default: ./config).")
    parser.add_argument("--json", action="store_true", help="Output report in JSON format.")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging.")
    parser.add_argument("--color", action="store_true", help="Enable colored output.")
    parser.add_argument("--skip-validation", action="store_true", help="Skip tag validation entirely.")

    args = parser.parse_args()

    # Resolve flags from env or args
    debug_enabled = args.debug or os.getenv("TAG_DEBUG_LOG") == "1"
    color_enabled = args.color or os.getenv("TAG_COLOR_LOGS") == "1"
    skip_validation = args.skip_validation or os.getenv("SKIP_TAG_VALIDATION") == "1"

    # --- Audit Logging ---
    # Log audit info early, before potential errors during config load
    log_audit_info(color_enabled)

    # --- Skip Validation Check ---
    if skip_validation:
         msg = "[INFO] Skipping tag validation as requested by flag or environment variable."
         if color_enabled: msg = f"{COLORS['YELLOW']}{msg}{COLORS['RESET']}"
         print(msg, file=sys.stderr)
         sys.exit(0) # Exit successfully if skipping

    # --- Main Validation Logic ---
    exit_code = 0
    try:
        if debug_enabled: print("[DEBUG] Debug logging enabled.", file=sys.stderr)
        if color_enabled: print("[DEBUG] Color output enabled.", file=sys.stderr) # Use debug for this meta-info

        config = TagValidatorConfig(args.config, debug=debug_enabled)
        validator = TerraformTagValidator(config, debug=debug_enabled, color=color_enabled)
        violations = validator.validate_plan(args.plan_file)

        has_errors = any(v.has_errors() for v in violations.values())

        if args.json:
            print(validator.generate_json_report(violations))
        else:
            report = validator.generate_console_report(violations)
            print(report)

        # Exit code 1 if there are mandatory errors, 0 otherwise (warnings don't cause failure)
        if has_errors:
            exit_code = 1

    except Exception as e:
        error_msg = f"❌ Error: {str(e)}"
        if color_enabled and (sys.stdout.isatty() or sys.stderr.isatty()):
            error_msg = f"{COLORS['RED']}{error_msg}{COLORS['RESET']}"
        print(error_msg, file=sys.stderr)
        exit_code = 2 # Use exit code 2 for script/config errors

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
