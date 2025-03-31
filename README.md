## Terraform AWS Tag Validator

This implementation provides a maintainable, enterprise-ready solution for Terraform tag validation that can evolve with changing requirements.

## Code Structure

terraform-tag-validator/
├── config/
│ ├── tag_rules.yaml # Tag validation rules
│ └── env_config.yaml # Environment-specific settings
└── terraform_tag_validator.py # Main validation script

## Usage / Test Command:

```bash
pip install pyyaml
yamllint config/env_config.yaml
cat config/tag_rules.yaml | grep -A3 "mandatory_rules:"
# Generate a test plan with obvious violations
terraform plan -out=tfplan && terraform show -json tfplan > bad_plan.json
python3 terraform_tag_validator.py bad_plan.json --debug --color
# Generate a test plan with no violations
terraform plan -out=tfplan && terraform show -json tfplan > plan.json
python3 terraform_tag_validator.py plan.json --debug --color

# With custom config path
python3 terraform_tag_validator.py ./plan.json --config ./config --json
python3 terraform_tag_validator.py plan.json --config ./custom_config

# JSON output
python3 terraform_tag_validator.py plan.json --json
```

## Terraform Plan Summarizer

```bash
python3 tf_plan_summarizer.py
```

- `Terraform Plan Summary Report`
- Plan File: /terraform/terraform-tag-validator/plan.json
- Terraform Version: 1.6.6
- Plan Format Ver: 1.2
- ============================================================
- Resource Changes Summary: 4 to create.

---

- Create (4):

- aws_s3_bucket.ai_lab_bucket
- aws_s3_bucket_acl.ai_lab_bucket
- aws_s3_bucket_ownership_controls.ai_lab_bucket
- aws_s3_bucket_versioning.versioning

## Debug Logging Control

```bash
# Enable Debug logging via command line
python3 terraform_tag_validator.py plan.json --debug

# Or via environment variable
export TAG_DEBUG_LOG=1
python3 terraform_tag_validator.py plan.json
```

## Color Control

```bash
# Enable colors
python3 terraform_tag_validator.py plan.json --color

# Disable colors explicitly
python3 terraform_tag_validator.py plan.json --no-color

# Environment variable control
export TAG_COLOR_LOGS=0
python3 terraform_tag_validator.py plan.json
```

## Output Formats:

- Console Output:
- `Success Case`:

- ✅ All resources comply with tagging requirements

- `Failure Case`:

# 🚫 Tag Compliance Violations Detected

Resource: aws_s3_bucket.ai_lab_bucket
Missing mandatory tags: - DataRetention (Data retention policy) - Sensitivity (Data sensitivity level)

REPORT: Violation Summary:
Total resources with issues: 1
Missing tags count: 2
Invalid values count: 0
=====================================

## Configuration Validation

- Ensure mandatory rules have non-empty allowed_values

- Added example values in YAML config

- Ensure Environment and Application tags are required globally

## Key Feature:

## Reporting

\*Color-coded output

Detailed violation summary

Resource-specific breakdown

Clear success/failure indicators

Counts of different violation types\*

- `JSON Output`:

```json
{
  "violations": {
    "aws_s3_bucket.ai_lab_bucket": {
      "missing": [
        {
          "key": "DataRetention",
          "allowed_values": ["30d", "1y", "5y"],
          "case_insensitive": false,
          "suggestion": "Data retention policy"
        },
        {
          "key": "Sensitivity",
          "allowed_values": ["public", "confidential", "restricted"],
          "case_insensitive": true,
          "suggestion": "Data sensitivity level"
        }
      ],
      "invalid": []
    }
  },
  "summary": {
    "total_violations": 1,
    "status": "FAIL"
  }
}
```

\*\*Separated Configuration:

- Tag rules in `tag_rules.yaml`

- Environment config in `env_config.yaml`

- Easy to modify without code changes\*\*

# Strong Typing:

- Uses Python dataclasses for type-safe configuration

- TagRule and EnvironmentConfig classes

# Robust Validation:

- Config validation during loading

- Clear error messages for misconfigurations

- Fallback to default environment

# Modular Architecture:

- Separate classes for configuration and validation

- Clear separation of concerns

- Easier to extend with new features

# Improved Environment Handling:

- Environment-specific tag rules

- Automatic fallback to default environment

- Clear configuration structure

## Verify Tag Rules Configuration Files

- File: `config/tag_rules.yaml`

```yaml
# Base tagging rules
# Example tag_rules.yaml
mandatory_rules:
  global:
    - key: Environment
      allowed_values:
        [
          "Production::PROD",
          "Non-production::DEV",
          "Non-production::PLAB",
          "Non-production::QAT",
          "Non-production::UAT",
          "Non-production::TEST",
        ]
      suggestion: "Environment classification"

    - key: Application
      allowed_values: ["JP", "AI"]
      case_insensitive: true
      suggestion: "Main application name"

    - key: Owner
      allowed_values: ["jayantapaul.jp18@gmail.com"]
      suggestion: "Team responsible for the resource"

  aws_s3_bucket:
    - key: DataRetention
      allowed_values: ["30d", "1y", "5y"]
      suggestion: "Data retention policy"

    - key: Sensitivity
      allowed_values: ["public", "confidential", "restricted"]
      case_insensitive: true
      suggestion: "Data sensitivity level"

    # - key: DataRetention
    #   allowed_values:  # Explicit list
    #     - "30 Days"
    #     - "1 Year"
    #     - "5 Years"
    #   suggestion: "Data retention policy"

optional_tags:
  - key: CostCenter
    suggestion: "Financial tracking code"

  - key: Terraform
    allowed_values: ["true", "false"]
    case_insensitive: true
    suggestion: "Mark Terraform-managed resources"

excluded_resources:
  - aws_iam_role
  - aws_iam_policy
  - aws_s3_bucket_versioning
  - aws_s3_bucket_ownership_controls
  - aws_s3_bucket_acl
```

## Verify Environment Configuration Files

- File: `config/env_config.yaml`

```yaml
environments:
  PROD:
    Environment:
      allowed_values: ["Production::PROD"]
      suggestion: "Production environment"

  LOWER:
    Environment:
      allowed_values:
        [
          "Non-production::DEV",
          "Non-production::PLAB",
          "Non-production::QAT",
          "Non-production::UAT",
          "Non-production::TEST",
        ]
      suggestion: "Non-production environment"

# Explicit default declaration
default_environment: LOWER
```
