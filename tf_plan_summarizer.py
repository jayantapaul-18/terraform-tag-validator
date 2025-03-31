#!/usr/bin/env python33

import json
import argparse
import sys
import os
from collections import defaultdict
import platform

# --- ANSI Color Codes ---
# Check if we're in a supportive terminal environment
def is_color_supported():
    """Check if the terminal likely supports ANSI colors."""
    if platform.system() == 'Windows':
        # Basic check for modern Windows terminals or environments like Git Bash
        return 'ANSICON' in os.environ or 'WT_SESSION' in os.environ or os.environ.get('TERM')
    # Check if TERM indicates color support and stdout is a TTY
    return hasattr(sys.stdout, 'isatty') and sys.stdout.isatty() and os.environ.get('TERM') not in ['dumb', '']


# Define colors - empty strings if not supported or --no-color is used
class Colors:
    RED = ""
    GREEN = ""
    YELLOW = ""
    CYAN = ""
    DIM = ""
    BOLD = ""
    RESET = ""

    @classmethod
    def enable(cls):
        cls.RED = "\033[91m"
        cls.GREEN = "\033[92m"
        cls.YELLOW = "\033[93m"
        cls.CYAN = "\033[96m"
        cls.DIM = "\033[2m"
        cls.BOLD = "\033[1m"
        cls.RESET = "\033[0m"

    @classmethod
    def disable(cls):
        for attr in dir(cls):
             if not callable(getattr(cls, attr)) and not attr.startswith("__"):
                  setattr(cls, attr, "")

# Helper function for colorizing text
def colorize(text, color_code):
    return f"{color_code}{text}{Colors.RESET}"

# --- Helper Function to Detect Changes ---
def get_changed_attributes(change_detail):
    """
    Identifies top-level attributes that are changing or unknown.

    Args:
        change_detail (dict): The 'change' object for a resource from the plan JSON.

    Returns:
        list: A list of strings describing changed/unknown attributes.
    """
    changed_keys = set()
    before = change_detail.get("before") or {}
    after = change_detail.get("after") or {}
    after_unknown = change_detail.get("after_unknown") or {}
    actions = change_detail.get("actions", [])

    # Attributes that will have values computed during apply
    for key in after_unknown:
        if after_unknown[key]: # Check if the value is true/non-null
            changed_keys.add(f"{key} (known after apply)")

    # Attributes being added or modified
    for key, after_value in after.items():
        if key not in before:
            if key not in after_unknown or not after_unknown.get(key): # Avoid duplicating unknowns
                 changed_keys.add(f"{key} (added)")
        elif key not in after_unknown or not after_unknown.get(key): # Only compare if not already marked unknown
            before_value = before.get(key)
            # Simple comparison, might not catch all nuances of complex types
            if before_value != after_value:
                 changed_keys.add(key)

    # Attributes being removed (only relevant for 'update', not 'replace')
    if actions == ["update"]:
        for key in before:
            if key not in after:
                changed_keys.add(f"{key} (removed)")

    return sorted(list(changed_keys))


# --- Main Summarizing Function ---
def summarize_tf_plan(plan_json_path, include_no_op=False, no_color=False):
    """
    Reads a Terraform JSON plan file and generates a colorized summary report
    with change details.

    Args:
        plan_json_path (str): Path to the Terraform plan JSON file.
        include_no_op (bool): If True, include 'no-op'/'read' details.
        no_color (bool): If True, disable ANSI color output.

    Returns:
        str: A formatted summary report string, or None on critical error.
    """
    # Enable/Disable Colors
    if not no_color and is_color_supported():
        Colors.enable()
    else:
        Colors.disable() # Ensure colors are empty strings

    try:
        # File validation and reading (same as before)
        if not os.path.exists(plan_json_path):
            raise FileNotFoundError(f"{Colors.RED}Error:{Colors.RESET} Plan JSON file not found at '{plan_json_path}'")
        if not os.path.isfile(plan_json_path):
             raise IsADirectoryError(f"{Colors.RED}Error:{Colors.RESET} '{plan_json_path}' is a directory, not a file.")

        with open(plan_json_path, 'r', encoding='utf-8') as f:
            try:
                plan_data = json.load(f)
            except json.JSONDecodeError as e:
                print(f"{Colors.RED}Error:{Colors.RESET} Failed to parse JSON in '{plan_json_path}'. Invalid syntax.", file=sys.stderr)
                print(f"Details: {e}", file=sys.stderr)
                return None

    except (FileNotFoundError, IsADirectoryError) as e:
        print(e, file=sys.stderr) # Error message already includes color attempt
        return None
    except IOError as e:
        print(f"{Colors.RED}Error:{Colors.RESET} reading file '{plan_json_path}': {e}", file=sys.stderr)
        return None
    except Exception as e:
         print(f"{Colors.RED}An unexpected error occurred during file handling:{Colors.RESET} {e}", file=sys.stderr)
         return None

    tf_version = plan_data.get('terraform_version', 'N/A')
    format_version = plan_data.get('format_version', 'N/A')
    resource_changes = plan_data.get('resource_changes', [])

    changes_by_action = defaultdict(list) # Stores tuples: (address, changed_attributes_list)
    action_counts = defaultdict(int)

    if not resource_changes and 'resource_changes' in plan_data:
        pass # No changes
    elif 'resource_changes' not in plan_data:
        print(f"{Colors.YELLOW}Warning:{Colors.RESET} 'resource_changes' key not found in the JSON plan. Unable to analyze resources.", file=sys.stderr)
    else:
        for change in resource_changes:
            actions = change.get('change', {}).get('actions', ['unknown'])
            address = change.get('address', 'unknown_resource')
            change_detail = change.get('change', {})
            changed_attributes = []

            # Determine action category
            action_category = "unknown"
            if actions == ["no-op"]: action_category = "no-op"
            elif actions == ["read"]: action_category = "read"
            elif actions == ["create"]: action_category = "create"
            elif actions == ["update"]:
                action_category = "update"
                changed_attributes = get_changed_attributes(change_detail)
            elif actions == ["delete"]: action_category = "delete"
            elif "create" in actions and "delete" in actions:
                action_category = "replace"
                changed_attributes = get_changed_attributes(change_detail)
            # Fallbacks
            elif "create" in actions: action_category = "create"
            elif "delete" in actions: action_category = "delete"

            action_counts[action_category] += 1
            changes_by_action[action_category].append((address, changed_attributes))

    # --- Build the Report ---
    report_lines = []
    report_lines.append(colorize("Terraform Plan Summary Report", Colors.BOLD))
    report_lines.append(f"Plan File:         {os.path.abspath(plan_json_path)}")
    report_lines.append(f"Terraform Version: {tf_version}")
    report_lines.append(f"Plan Format Ver:   {format_version}")
    report_lines.append(colorize("=" * 60, Colors.DIM))

    # Overall summary
    summary_parts = []
    if action_counts['create']:  summary_parts.append(colorize(f"{action_counts['create']} to create", Colors.GREEN))
    if action_counts['update']:  summary_parts.append(colorize(f"{action_counts['update']} to update", Colors.YELLOW))
    if action_counts['replace']: summary_parts.append(colorize(f"{action_counts['replace']} to replace", Colors.CYAN))
    if action_counts['delete']:  summary_parts.append(colorize(f"{action_counts['delete']} to destroy", Colors.RED + Colors.BOLD)) # Highlight destroy

    no_op_read_count = action_counts['no-op'] + action_counts['read']
    if no_op_read_count > 0 and include_no_op:
         summary_parts.append(colorize(f"{no_op_read_count} unchanged/read", Colors.DIM))

    if summary_parts:
         report_lines.append(f"Resource Changes Summary: {', '.join(summary_parts)}.")
    elif 'resource_changes' in plan_data:
         report_lines.append(colorize("Resource Changes Summary: No resource changes detected.", Colors.DIM))
    else:
         report_lines.append(colorize("Resource Changes Summary: Could not determine resource changes (check warnings).", Colors.YELLOW))

    # Detailed sections
    action_order = ["create", "update", "replace", "delete"]
    if include_no_op:
         action_order.extend(["read", "no-op"])

    has_detailed_changes = False
    for action in action_order:
        if changes_by_action[action]:
            has_detailed_changes = True
            report_lines.append(colorize("-" * 60, Colors.DIM))

            # Get color and title
            color = Colors.RESET
            title = action.capitalize()
            prefix = ""
            if action == 'create': color = Colors.GREEN
            elif action == 'update': color = Colors.YELLOW; title = "Update"
            elif action == 'replace': color = Colors.CYAN; title = "Replace"
            elif action == 'delete':
                color = Colors.RED + Colors.BOLD
                title = "DESTROY" # Uppercase for emphasis
                prefix = colorize("[DELETION!] ", Colors.RED + Colors.BOLD)
            elif action == 'read': color = Colors.DIM; title = "Read (Data Sources)"
            elif action == 'no-op': color = Colors.DIM; title = "Unchanged"

            report_lines.append(colorize(f"{prefix}{title} ({action_counts[action]}):", color))

            # Sort resources by address
            sorted_resources = sorted(changes_by_action[action], key=lambda x: x[0])

            for address, changed_attrs in sorted_resources:
                report_lines.append(f"  - {colorize(address, color)}")
                # Show changed attributes for update/replace
                if (action == 'update' or action == 'replace') and changed_attrs:
                    for attr in changed_attrs:
                        # Indent attribute changes further
                        report_lines.append(f"      {colorize('~', Colors.DIM)} {colorize(attr, Colors.DIM)}")

    # Handle case where only no-op/read changes exist but --include-no-op wasn't used
    if not has_detailed_changes and 'resource_changes' in plan_data and len(resource_changes) > 0 and not include_no_op:
        if no_op_read_count > 0:
             report_lines.append(colorize("-" * 60, Colors.DIM))
             report_lines.append(colorize(f"Note: {no_op_read_count} resource(s) are unchanged or will be read.", Colors.DIM))
             report_lines.append(colorize("      (Use --include-no-op flag to list them)", Colors.DIM))

    # Output Changes Note
    output_changes = plan_data.get('output_changes', {})
    if output_changes:
         report_lines.append(colorize("-" * 60, Colors.DIM))
         report_lines.append(f"Output Changes: {len(output_changes)} output(s) will also be created, updated, or destroyed.")

    report_lines.append(colorize("=" * 60, Colors.DIM))
    return "\n".join(report_lines)


def main():
    """Parses command-line arguments and runs the summarizer."""
    parser = argparse.ArgumentParser(
        description=f"{colorize('Summarize a Terraform plan from its JSON output with color highlighting.', Colors.BOLD if is_color_supported() else '')}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""{colorize('How to Generate the Required JSON Input File:', Colors.BOLD if is_color_supported() else '')}
  1. terraform plan -out=tfplan.binary   # Create binary plan
  2. terraform show -json tfplan.binary > plan.json  # Convert to JSON

{colorize('Example Usage:', Colors.BOLD if is_color_supported() else '')}
  # Summarize plan.json with colors
  python3 tf_plan_summarizer.py plan.json

  # Summarize and save to report.txt (colors disabled in file)
  python3 tf_plan_summarizer.py plan.json -o report.txt

  # Summarize without colors in the terminal
  python3 tf_plan_summarizer.py plan.json --no-color

  # Include unchanged/read resources in the details
  python3 tf_plan_summarizer.py plan.json --include-no-op
"""
    )
    parser.add_argument(
        "plan_json_file",
        help="Path to the Terraform plan JSON file.",
    )
    parser.add_argument(
        "-o", "--output",
        metavar="OUTPUT_FILE",
        help="Optional path to write the summary report file (colors will be disabled)."
    )
    parser.add_argument(
        "--include-no-op",
        action="store_true",
        help="Include details of resources with 'no-op' or 'read' actions."
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colorized output, even if the terminal supports it."
    )

    args = parser.parse_args()

    # Disable color if outputting to a file
    force_no_color = args.no_color or (args.output is not None)

    # --- Run Summarizer ---
    summary_report = summarize_tf_plan(args.plan_json_file, args.include_no_op, force_no_color)

    # --- Output Report ---
    if summary_report is None:
         sys.exit(1)

    if args.output:
        try:
            # Always write without color codes to file
            with open(args.output, 'w', encoding='utf-8') as f:
                # Need to run summary again *if* colors were initially enabled for console
                # but are disabled for file. If they were already disabled, reuse report.
                if not force_no_color and is_color_supported(): # Colors were on, disable for file
                     file_report = summarize_tf_plan(args.plan_json_file, args.include_no_op, no_color=True)
                     if file_report: f.write(file_report)
                else: # Colors were already off, just write the report we have
                    f.write(summary_report)

            print(f"Summary report successfully written to '{os.path.abspath(args.output)}'")
        except IOError as e:
            print(f"{Colors.RED}Error:{Colors.RESET} Could not write report to file '{args.output}': {e}", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"{Colors.RED}An unexpected error occurred while writing the file:{Colors.RESET} {e}", file=sys.stderr)
            sys.exit(1)
    else:
        # Print colorized (or plain) report to standard output
        print(summary_report)

if __name__ == "__main__":
    main()