import os
import sys
import json
import pprint as pp
import argparse
from collections import defaultdict
from typing import Dict, List, Tuple, Any
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

    def as_dict(self):
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

    def as_dict(self):
        return {
            "env_name": self.env_name,
            "environment_tag": self.environment_tag.as_dict(),
            "default": self.default
        }

class TagValidatorConfig:
    def __init__(self, config_path: str):
        self.mandatory_rules = defaultdict(list)
        self.optional_tags = []
        self.excluded_resources = []
        self.environment_configs = []
        self.default_environment = "LOWER"
        self._load_configs(config_path)
        self._validate_configs()
        print("TagValidatorConfig initialized with the following settings:")
        # print(f"===================mandatory_rules===========================")
        # pp.pprint(self.mandatory_rules)
        # print(f"===================optional_tags==========================")
        # pp.pprint(self.optional_tags)
        # print(f"===================excluded_resources===========================")
        # pp.pprint(self.excluded_resources)
        # print(f"===========================================================")
        # pp.pprint(self.environment_configs)
        # print(f"===================environment_configs======================")
        
    def _load_configs(self, config_path: str):
        try:
            # Load environment config
            with open(f"{config_path}/env_config.yaml") as f:
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
            with open(f"{config_path}/tag_rules.yaml") as f:
                tag_rules = yaml.safe_load(f) or {}

            # Process mandatory rules
            self.mandatory_rules = defaultdict(list)
            for resource_type, rules in tag_rules.get("mandatory_rules", {}).items():
                for rule in rules:
                    self.mandatory_rules[resource_type].append(
                        TagRule(
                            key=rule.get("key"),
                            allowed_values=rule.get("allowed_values", []),
                            case_insensitive=rule.get("case_insensitive", False),
                            suggestion=rule.get("suggestion", "")
                        )
                    )

            # Process optional tags
            self.optional_tags = [
                TagRule(
                    key=rule.get("key"),
                    allowed_values=rule.get("allowed_values", []),
                    case_insensitive=rule.get("case_insensitive", False),
                    suggestion=rule.get("suggestion", "")
                ) for rule in tag_rules.get("optional_tags", [])
            ]

            self.excluded_resources = tag_rules.get("excluded_resources", [])

        except Exception as e:
            raise RuntimeError(f"Config loading failed: {str(e)}")

    def _validate_configs(self):
        if not self.mandatory_rules.get("global"):
            raise ValueError("Missing global mandatory rules in config")
        if not any(cfg.default for cfg in self.environment_configs):
            raise ValueError("No default environment configured")

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
        """Apply color if enabled"""
        if self.color_enabled and sys.stdout.isatty():
            return f"{COLORS[color]}{text}{COLORS['RESET']}"
        return text
           
    def _get_environment_config(self) -> EnvironmentConfig:
        for cfg in self.config.environment_configs:
            if cfg.env_name == self.current_env:
                return cfg
        return next(cfg for cfg in self.config.environment_configs if cfg.default)

    def _get_mandatory_rules(self, resource_type: str) -> List[TagRule]:
        global_rules = self.config.mandatory_rules.get("global", [])
        resource_rules = self.config.mandatory_rules.get(resource_type, [])
        
        seen_keys = set()
        merged_rules = []

        # Add environment rule first
        env_rule = self.env_config.environment_tag
        merged_rules.append(env_rule)
        seen_keys.add(env_rule.key)

        # Add other rules
        for rule in global_rules + resource_rules:
            if rule.key not in seen_keys:
                merged_rules.append(rule)
                seen_keys.add(rule.key)

        return merged_rules

    def validate_plan(self, plan_path: str) -> Dict:
        try:
            with open(plan_path) as f:
                plan_data = json.load(f)
                
            violations = {}
            total_resources = 0
            analyzed_resources = 0

            for resource in plan_data.get("resource_changes", []):
                total_resources += 1
                if self._should_skip_resource(resource):
                    self._debug_log(f"Skipping resource: {resource.get('address')}")
                    continue
                
                analyzed_resources += 1
                resource_type = resource.get("type", "")
                address = resource.get("address", "unknown")
                
                self._debug_log(f"Analyzing resource: {address}")
                tags = self._extract_tags(resource)
                missing, invalid = self._validate_tags(resource_type, tags)
                
                if missing or invalid:
                    violations[address] = {
                        "missing": [rule.as_dict() for rule in missing],
                        "invalid": [rule.as_dict() for rule in invalid]
                    }

            self._debug_log(f"Analyzed {analyzed_resources}/{total_resources} resources")
            return violations
            
        except Exception as e:
            raise RuntimeError(f"Validation failed: {str(e)}")
    
    def _should_skip_resource(self, resource: Dict) -> bool:
        return (
            "delete" in resource.get("actions", []) or
            resource.get("type", "") in self.config.excluded_resources
        )

    def _extract_tags(self, resource: Dict) -> Dict[str, str]:
        tags = {}
        config = resource.get("change", {}).get("after", {})
        print("\n[DEBUG] Raw resource config:", json.dumps(config, indent=2))  # Debug
        # Handle standard tags
        if isinstance(config.get("tags"), dict):
            tags.update(config["tags"])
        
        # Handle tags_all
        if isinstance(config.get("tags_all"), dict):
            tags.update(config["tags_all"])
        
        # Handle list-formatted tags (AWS ASG style)
        if isinstance(config.get("tag"), list):
            for tag_spec in config["tag"]:
                if isinstance(tag_spec, dict):
                    key = tag_spec.get("key")
                    value = tag_spec.get("value")
                    if key and value is not None:
                        tags[key] = value
        print("[DEBUG] Extracted tags:", tags)  # Debug
        return tags

    def _validate_tags(self, resource_type: str, tags: Dict) -> Tuple[List, List]:
        rules = self._get_mandatory_rules(resource_type)
        print(f"\n[DEBUG] Validating {resource_type} with rules:")  # Debug
        missing = []
        invalid = []
        
        for rule in rules:
            print(f"  - {rule.key}: {rule.allowed_values} (case_insensitive={rule.case_insensitive})")
            if rule.key not in tags:
                missing.append(rule)
                continue
                
            if not self._validate_value(tags[rule.key], rule):
                invalid.append(rule)
                
        return missing, invalid

    def _validate_value(self, value: str, rule: TagRule) -> bool:
        if not rule.allowed_values:
            return True
            
        if rule.case_insensitive:
            return value.lower() in [v.lower() for v in rule.allowed_values]
        return value in rule.allowed_values

    ## Console Report Generation
    def generate_console_report(self, violations: dict) -> str:
            """Generate color-coded console report"""
            if not violations:
                return self._colorize("✅ All resources comply with tagging requirements", "GREEN")
            
            report = []
            report.append(self._colorize("\n🚫 Tag Compliance Violations Detected", "RED"))
            report.append(self._colorize("=====================================", "RED"))
            
            for resource, details in violations.items():
                report.append(f"\n{self._colorize('Resource:', 'CYAN')} {resource}")
                
                if details["missing"]:
                    report.append(self._colorize("  Missing mandatory tags:", "YELLOW"))
                    for rule in details["missing"]:
                        suggestion = f" ({rule['suggestion']})" if rule['suggestion'] else ""
                        report.append(f"    - {rule['key']}{suggestion}")
                        
                if details["invalid"]:
                    report.append(self._colorize("  Invalid tag values:", "YELLOW"))
                    for rule in details["invalid"]:
                        allowed = ", ".join(rule['allowed_values'])
                        case_note = "(case-insensitive)" if rule['case_insensitive'] else ""
                        msg = (f"    - {rule['key']}: "
                            f"Allowed values {case_note}: [{allowed}]")
                        report.append(msg)
            
            summary = [
                self._colorize("\nREPORT: Violation Summary:", "MAGENTA"),
                f"Total resources with issues: {len(violations)}",
                f"Missing tags count: {sum(len(v['missing']) for v in violations.values())}",
                f"Invalid values count: {sum(len(v['invalid']) for v in violations.values())}",
                self._colorize("=====================================", "RED")
            ]
            report.extend(summary)
            
            return "\n".join(report)

def main():
    parser = argparse.ArgumentParser(description="Terraform Tag Validator")
    parser.add_argument("plan_file", help="Path to Terraform plan JSON")
    parser.add_argument("--config", default="config", help="Config directory path")
    parser.add_argument("--json", action="store_true", help="Output report in JSON format")
    parser.add_argument("--debug", action="store_true", 
                       help="Enable debug logging (or set TAG_DEBUG_LOG=1)")
    parser.add_argument("--color", action="store_true", 
                       help="Enable colored output (or set TAG_COLOR_LOGS=1)")

    args = parser.parse_args()

    try:
        # Resolve debug and color flags from env or args
        debug_enabled = args.debug or os.getenv("TAG_DEBUG_LOG") == "1"
        color_enabled = args.color or os.getenv("TAG_COLOR_LOGS") == "1"

        config = TagValidatorConfig(args.config)
        validator = TerraformTagValidator(config, debug=debug_enabled, color=color_enabled)
        violations = validator.validate_plan(args.plan_file)

        if args.json:
            print(json.dumps({
                "violations": violations,
                "summary": {
                    "total_violations": len(violations),
                    "status": "FAIL" if violations else "PASS"
                }
            }, indent=2))
        else:
            report = validator.generate_console_report(violations)
            print(report)

        sys.exit(1 if violations else 0)
        
    except Exception as e:
        error_msg = f"❌ Error: {str(e)}"
        if color_enabled:
            error_msg = f"{COLORS['RED']}{error_msg}{COLORS['RESET']}"
        print(error_msg, file=sys.stderr)
        sys.exit(2)

if __name__ == "__main__":
    main()