import json
import logging
import re
from pathlib import Path
from mdutils import MdUtils
from prettytable import PrettyTable

from socketsecurity.core.classes import Diff, Issue, Purl

log = logging.getLogger("socketcli")

class Messages:

    @staticmethod
    def map_severity_to_sarif(severity: str) -> str:
        """
        Map Socket severity levels to SARIF levels (GitHub code scanning).

        'low' -> 'note'
        'medium' or 'middle' -> 'warning'
        'high' or 'critical' -> 'error'
        """
        severity_mapping = {
            "low": "note",
            "medium": "warning",
            "middle": "warning",  # older data might say "middle"
            "high": "error",
            "critical": "error",
        }
        return severity_mapping.get(severity.lower(), "note")

    @staticmethod
    def find_line_in_file(packagename: str, packageversion: str, manifest_file: str) -> tuple:
        """
        Finds the line number and snippet of code for the given package/version in a manifest file.
        Returns a 2-tuple: (line_number, snippet_or_message).

        Supports:
          1) JSON-based manifest files (package-lock.json, Pipfile.lock, composer.lock)
             - Locates a dictionary entry with the matching package & version
             - Searches the raw text for the key
          2) Text-based (requirements.txt, package.json, yarn.lock, pnpm-lock.yaml, etc.)
             - Uses regex patterns to detect a match line by line
        """
        file_type = Path(manifest_file).name
        log.debug("Processing file for line lookup: %s", manifest_file)

        if file_type in ["package-lock.json", "Pipfile.lock", "composer.lock"]:
            try:
                with open(manifest_file, "r", encoding="utf-8") as f:
                    raw_text = f.read()
                log.debug("Read %d characters from %s", len(raw_text), manifest_file)
                data = json.loads(raw_text)
                packages_dict = (
                    data.get("packages")
                    or data.get("default")
                    or data.get("dependencies")
                    or {}
                )
                log.debug("Found package keys in %s: %s", manifest_file, list(packages_dict.keys()))
                found_key = None
                found_info = None
                for key, value in packages_dict.items():
                    if key.endswith(packagename) and "version" in value:
                        if value["version"] == packageversion:
                            found_key = key
                            found_info = value
                            break
                if found_key and found_info:
                    needle_key = f'"{found_key}":'
                    lines = raw_text.splitlines()
                    log.debug("Total lines in %s: %d", manifest_file, len(lines))
                    for i, line in enumerate(lines, start=1):
                        if needle_key in line:
                            log.debug("Found match at line %d in %s: %s", i, manifest_file, line.strip())
                            return i, line.strip()
                    return 1, f'"{found_key}": {found_info}'
                else:
                    return 1, f"{packagename} {packageversion} (not found in {manifest_file})"
            except (FileNotFoundError, json.JSONDecodeError) as e:
                log.error("Error reading %s: %s", manifest_file, e)
                return 1, f"Error reading {manifest_file}"

        # For pnpm-lock.yaml, use a special regex pattern.
        if file_type.lower() == "pnpm-lock.yaml":
            searchstring = rf'^\s*/{re.escape(packagename)}/{re.escape(packageversion)}:'
        else:
            search_patterns = {
                "package.json":         rf'"{packagename}":\s*"[\^~]?{re.escape(packageversion)}"',
                "yarn.lock":            rf'{packagename}@{packageversion}',
                "requirements.txt":     rf'^{re.escape(packagename)}\s*(?:==|===|!=|>=|<=|~=|\s+)?\s*{re.escape(packageversion)}(?:\s*;.*)?$',
                "pyproject.toml":       rf'{packagename}\s*=\s*"{re.escape(packageversion)}"',
                "Pipfile":              rf'"{packagename}"\s*=\s*"{re.escape(packageversion)}"',
                "go.mod":               rf'require\s+{re.escape(packagename)}\s+{re.escape(packageversion)}',
                "go.sum":               rf'{re.escape(packagename)}\s+{re.escape(packageversion)}',
                "pom.xml":              rf'<artifactId>{re.escape(packagename)}</artifactId>\s*<version>{re.escape(packageversion)}</version>',
                "build.gradle":         rf'implementation\s+"{re.escape(packagename)}:{re.escape(packageversion)}"',
                "Gemfile":              rf'gem\s+"{re.escape(packagename)}",\s*"{re.escape(packageversion)}"',
                "Gemfile.lock":         rf'\s+{re.escape(packagename)}\s+\({re.escape(packageversion)}\)',
                ".csproj":              rf'<PackageReference\s+Include="{re.escape(packagename)}"\s+Version="{re.escape(packageversion)}"\s*/>',
                ".fsproj":              rf'<PackageReference\s+Include="{re.escape(packagename)}"\s+Version="{re.escape(packageversion)}"\s*/>',
                "paket.dependencies":   rf'nuget\s+{re.escape(packagename)}\s+{re.escape(packageversion)}',
                "Cargo.toml":           rf'{re.escape(packagename)}\s*=\s*"{re.escape(packageversion)}"',
                "build.sbt":            rf'"{re.escape(packagename)}"\s*%\s*"{re.escape(packageversion)}"',
                "Podfile":              rf'pod\s+"{re.escape(packagename)}",\s*"{re.escape(packageversion)}"',
                "Package.swift":        rf'\.package\(name:\s*"{re.escape(packagename)}",\s*url:\s*".*?",\s*version:\s*"{re.escape(packageversion)}"\)',
                "mix.exs":              rf'\{{:{re.escape(packagename)},\s*"{re.escape(packageversion)}"\}}',
                "composer.json":        rf'"{re.escape(packagename)}":\s*"{re.escape(packageversion)}"',
                "conanfile.txt":        rf'{re.escape(packagename)}/{re.escape(packageversion)}',
                "vcpkg.json":           rf'"{re.escape(packagename)}":\s*"{re.escape(packageversion)}"',
            }
            searchstring = search_patterns.get(file_type, rf'{re.escape(packagename)}.*{re.escape(packageversion)}')

        log.debug("Using search pattern for %s: %s", file_type, searchstring)
        try:
            with open(manifest_file, 'r', encoding="utf-8") as file:
                lines = [line.rstrip("\n") for line in file]
                log.debug("Total lines in %s: %d", manifest_file, len(lines))
                for line_number, line_content in enumerate(lines, start=1):
                    line_main = line_content.split(";", 1)[0].strip()
                    if re.search(searchstring, line_main, re.IGNORECASE):
                        log.debug("Match found at line %d in %s: %s", line_number, manifest_file, line_content.strip())
                        return line_number, line_content.strip()
        except FileNotFoundError:
            return 1, f"{manifest_file} not found"
        except Exception as e:
            return 1, f"Error reading {manifest_file}: {e}"

        return 1, f"{packagename} {packageversion} (not found)"

    @staticmethod
    def get_manifest_type_url(manifest_file: str, pkg_name: str, pkg_version: str) -> str:
        """
        Determine the correct URL path based on the manifest file type.
        """
        manifest_to_url_prefix = {
            "package.json": "npm",
            "package-lock.json": "npm",
            "yarn.lock": "npm",
            "pnpm-lock.yaml": "npm",
            "requirements.txt": "pypi",
            "pyproject.toml": "pypi",
            "Pipfile": "pypi",
            "go.mod": "go",
            "go.sum": "go",
            "pom.xml": "maven",
            "build.gradle": "maven",
            ".csproj": "nuget",
            ".fsproj": "nuget",
            "paket.dependencies": "nuget",
            "Cargo.toml": "cargo",
            "Gemfile": "rubygems",
            "Gemfile.lock": "rubygems",
            "composer.json": "composer",
            "vcpkg.json": "vcpkg",
        }
        file_type = Path(manifest_file).name
        url_prefix = manifest_to_url_prefix.get(file_type, "unknown")
        return f"https://socket.dev/{url_prefix}/package/{pkg_name}/alerts/{pkg_version}"

    @staticmethod
    def create_security_comment_sarif(diff) -> dict:
        """
        Create SARIF-compliant output from the diff report, including dynamic URL generation
        based on manifest type and improved <br/> formatting for GitHub SARIF display.

        This function now:
        - Processes every alert in diff.new_alerts.
        - For alerts with multiple manifest files, generates an individual SARIF result for each file.
        - Appends the manifest file name to the rule ID and name to make each result unique.
        - Does NOT fall back to 'requirements.txt' if no manifest file is provided.
        - Adds detailed log to validate our assumptions.

        """
        if len(diff.new_alerts) == 0:
            for alert in diff.new_alerts:
                if alert.error:
                    break

        sarif_data = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "Socket Security",
                        "informationUri": "https://socket.dev",
                        "rules": []
                    }
                },
                "results": []
            }]
        }

        rules_map = {}
        results_list = []

        for alert in diff.new_alerts:
            pkg_name = alert.pkg_name
            pkg_version = alert.pkg_version
            base_rule_id = f"{pkg_name}=={pkg_version}"
            severity = alert.severity

            log.debug("Alert %s - introduced_by: %s, manifests: %s", base_rule_id, alert.introduced_by, getattr(alert, 'manifests', None))
            manifest_files = []
            if alert.introduced_by and isinstance(alert.introduced_by, list):
                for entry in alert.introduced_by:
                    if isinstance(entry, (list, tuple)) and len(entry) >= 2:
                        files = [f.strip() for f in entry[1].split(";") if f.strip()]
                        manifest_files.extend(files)
                    elif isinstance(entry, str):
                        manifest_files.extend([m.strip() for m in entry.split(";") if m.strip()])
            elif hasattr(alert, 'manifests') and alert.manifests:
                manifest_files = [mf.strip() for mf in alert.manifests.split(";") if mf.strip()]

            log.debug("Alert %s - extracted manifest_files: %s", base_rule_id, manifest_files)
            if not manifest_files:
                log.error("Alert %s: No manifest file found; cannot determine file location.", base_rule_id)
                continue

            log.debug("Alert %s - using manifest_files for processing: %s", base_rule_id, manifest_files)

            # Create an individual SARIF result for each manifest file.
            for mf in manifest_files:
                log.debug("Alert %s - Processing manifest file: %s", base_rule_id, mf)
                socket_url = Messages.get_manifest_type_url(mf, pkg_name, pkg_version)
                line_number, line_content = Messages.find_line_in_file(pkg_name, pkg_version, mf)
                if line_number < 1:
                    line_number = 1
                log.debug("Alert %s: Manifest %s, line %d: %s", base_rule_id, mf, line_number, line_content)

                # Create a unique rule id and name by appending the manifest file.
                unique_rule_id = f"{base_rule_id} ({mf})"
                rule_name = f"Alert {base_rule_id} ({mf})"
                props = {}
                if hasattr(alert, 'props') and alert.props:
                    props = alert.props
                suggestion = ''
                if hasattr(alert, 'suggestion'):
                    suggestion = alert.suggestion
                alert_title = ''
                if hasattr(alert, 'title'):
                    alert_title = alert.title
                description = ''
                if hasattr(alert, 'description'):
                    description = alert.description
                short_desc = (f"{props.get('note', '')}<br/><br/>Suggested Action:<br/>{suggestion}"
                              f"<br/><a href=\"{socket_url}\">{socket_url}</a>")
                full_desc = "{} - {}".format(alert_title, description.replace('\r\n', '<br/>'))

                if unique_rule_id not in rules_map:
                    rules_map[unique_rule_id] = {
                        "id": unique_rule_id,
                        "name": rule_name,
                        "shortDescription": {"text": rule_name},
                        "fullDescription": {"text": full_desc},
                        "helpUri": socket_url,
                        "defaultConfiguration": {
                            "level": Messages.map_severity_to_sarif(severity)
                        },
                    }

                result_obj = {
                    "ruleId": unique_rule_id,
                    "message": {"text": short_desc},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": mf},
                            "region": {
                                "startLine": line_number,
                                "snippet": {"text": line_content},
                            },
                        }
                    }]
                }
                results_list.append(result_obj)

        sarif_data["runs"][0]["tool"]["driver"]["rules"] = list(rules_map.values())
        sarif_data["runs"][0]["results"] = results_list

        return sarif_data

    @staticmethod
    def create_security_comment_json(diff: Diff) -> dict:
        scan_failed = False
        if len(diff.new_alerts) == 0:
            for alert in diff.new_alerts:
                alert: Issue
                if alert.error:
                    scan_failed = True
                    break
        output = {
            "scan_failed": scan_failed,
            "new_alerts": [],
            "full_scan_id": diff.id,
            "diff_url": diff.diff_url
        }
        for alert in diff.new_alerts:
            alert: Issue
            output["new_alerts"].append(json.loads(str(alert)))
        return output

    @staticmethod
    def security_comment_template(diff: Diff) -> str:
        """
        Generates the security comment template in the new required format.
        Dynamically determines placement of the alerts table if markers like `<!-- start-socket-alerts-table -->` are used.

        :param diff: Diff - Contains the detected vulnerabilities and warnings.
        :return: str - The formatted Markdown/HTML string.
        """
        # Group license policy violations by PURL (ecosystem/package@version)
        license_groups = {}
        security_alerts = []
        
        for alert in diff.new_alerts:
            if alert.type == "licenseSpdxDisj":
                purl_key = f"{alert.pkg_type}/{alert.pkg_name}@{alert.pkg_version}"
                if purl_key not in license_groups:
                    license_groups[purl_key] = []
                license_groups[purl_key].append(alert)
            else:
                security_alerts.append(alert)

        # Start of the comment
        comment = """<!-- socket-security-comment-actions -->

> **❗️ Caution**  
> **Review the following alerts detected in dependencies.**  
>  
> According to your organization's Security Policy, you **must** resolve all **"Block"** alerts before proceeding. It's recommended to resolve **"Warn"** alerts too.  
> Learn more about [Socket for GitHub](https://socket.dev?utm_medium=gh).

<!-- start-socket-updated-alerts-table -->
<table>
  <thead>
    <tr>
      <th>Action</th>
      <th>Severity</th>
      <th align="left">Alert (click for details)</th>
    </tr>
  </thead>
  <tbody>
    """

        # Loop through security alerts (non-license), dynamically generating rows
        for alert in security_alerts:
            severity_icon = Messages.get_severity_icon(alert.severity)
            action = "Block" if alert.error else "Warn"
            details_open = ""
            # Generate a table row for each alert
            comment += f"""
<!-- start-socket-alert-{alert.pkg_name}@{alert.pkg_version} -->
<tr>
  <td><strong>{action}</strong></td>
  <td align="center">
      <img src="{severity_icon}" alt="{alert.severity}" width="20" height="20">
  </td>
  <td>
    <details {details_open}>
      <summary>{alert.pkg_name}@{alert.pkg_version} - {alert.title}</summary>
      <p><strong>Note:</strong> {alert.description}</p>
      <p><strong>Source:</strong> <a href="{alert.manifests}">Manifest File</a></p>
      <p>ℹ️ Read more on:  
      <a href="{alert.purl}">This package</a> |  
      <a href="{alert.url}">This alert</a> |  
      <a href="https://socket.dev/alerts/malware">What is known malware?</a></p>
      <blockquote>
        <p><em>Suggestion:</em> {alert.suggestion}</p>
        <p><em>Mark as acceptable risk:</em> To ignore this alert only in this pull request, reply with:<br/>
        <code>@SocketSecurity ignore {alert.pkg_name}@{alert.pkg_version}</code><br/>
        Or ignore all future alerts with:<br/>
        <code>@SocketSecurity ignore-all</code></p>
      </blockquote>
    </details>
  </td>
</tr>
<!-- end-socket-alert-{alert.pkg_name}@{alert.pkg_version} -->
    """

        # Add license policy violation entries grouped by PURL
        for purl_key, alerts in license_groups.items():
            action = "Block" if any(alert.error for alert in alerts) else "Warn"
            first_alert = alerts[0]
            
            # Use orange diamond for license policy violations
            license_icon = "🔶"
            
            # Build license findings list
            license_findings = []
            for alert in alerts:
                license_findings.append(alert.title)
            
            comment += f"""
<!-- start-socket-alert-{first_alert.pkg_name}@{first_alert.pkg_version} -->
<tr>
  <td><strong>{action}</strong></td>
  <td align="center">{license_icon}</td>
  <td>
    <details>
      <summary>{first_alert.pkg_name}@{first_alert.pkg_version} has a License Policy Violation.</summary>
      <p><strong>License findings:</strong></p>
      <ul>
"""
            for finding in license_findings:
                comment += f"        <li>{finding}</li>\n"
            
            comment += f"""      </ul>
      <p><strong>From:</strong> {first_alert.manifests}</p>
      <p>ℹ️ Read more on: <a href="{first_alert.purl}">This package</a> | <a href="https://socket.dev/alerts/license">What is a license policy violation?</a></p>
      <blockquote>
        <p><em>Next steps:</em> Take a moment to review the security alert above. Review the linked package source code to understand the potential risk. Ensure the package is not malicious before proceeding. If you're unsure how to proceed, reach out to your security team or ask the Socket team for help at <strong>support@socket.dev</strong>.</p>
        <p><em>Suggestion:</em> Find a package that does not violate your license policy or adjust your policy to allow this package's license.</p>
        <p><em>Mark the package as acceptable risk:</em> To ignore this alert only in this pull request, reply with the comment <code>@SocketSecurity ignore {first_alert.pkg_name}@{first_alert.pkg_version}</code>. You can also ignore all packages with <code>@SocketSecurity ignore-all</code>. To ignore an alert for all future pull requests, use Socket's Dashboard to change the triage state of this alert.</p>
      </blockquote>
    </details>
  </td>
</tr>
<!-- end-socket-alert-{first_alert.pkg_name}@{first_alert.pkg_version} -->
    """

        # Close table
        comment += """
  </tbody>
</table>
<!-- end-socket-alerts-table -->

[View full report](https://socket.dev/...&action=error%2Cwarn)
    """

        return comment

    @staticmethod
    def get_severity_icon(severity: str) -> str:
        """
        Maps severity levels to their corresponding badge/icon URLs.

        :param severity: str - Severity level (e.g., "Critical", "High").
        :return: str - Badge/icon URL.
        """
        severity_map = {
            "critical": "https://github-app-statics.socket.dev/severity-3.svg",
            "high": "https://github-app-statics.socket.dev/severity-2.svg",
            "medium": "https://github-app-statics.socket.dev/severity-1.svg",
            "low": "https://github-app-statics.socket.dev/severity-0.svg",
        }
        return severity_map.get(severity.lower(), "https://github-app-statics.socket.dev/severity-0.svg")


    @staticmethod
    def create_next_steps(md: MdUtils, next_steps: dict):
        """
        Creates the next steps section of the security comment template
        :param md: MdUtils - Main markdown variable
        :param next_steps: Dict - Contains the detected next steps to include
        :return:
        """
        for step in next_steps:
            detail = next_steps[step]
            md.new_line("<details>")
            md.new_line(f"<summary>{step}</summary>")
            for line in detail:
                md.new_paragraph(line)
            md.new_line("</details>")
        return md

    @staticmethod
    def create_deeper_look(md: MdUtils) -> MdUtils:
        """
        Creates the deeper look section for the Security Comment Template
        :param md: MdUtils - Main markdown variable
        :return:
        """
        md.new_line("<details>")
        md.new_line("<summary>Take a deeper look at the dependency</summary>")
        md.new_paragraph(
            "Take a moment to review the security alert above. Review the linked package source code to understand the "
            "potential risk. Ensure the package is not malicious before proceeding. If you're unsure how to proceed, "
            "reach out to your security team or ask the Socket team for help at support [AT] socket [DOT] dev."
        )
        md.new_line("</details>")
        return md

    @staticmethod
    def create_remove_package(md: MdUtils) -> MdUtils:
        """
        Creates the remove packages suggestion section for the Security Comment Template
        :param md:
        :return:
        """
        md.new_line("<details>")
        md.new_line("<summary>Remove the package</summary>")
        md.new_paragraph(
            "If you happen to install a dependency that Socket reports as "
            "[https://socket.dev/npm/issue/malware](Known Malware) you should immediately remove it and select a "
            "different dependency. For other alert types, you may may wish to investigate alternative packages or "
            "consider if there are other ways to mitigate the specific risk posed by the dependency."
        )
        md.new_line("</details>")
        return md

    @staticmethod
    def create_acceptable_risk(md: MdUtils, ignore_commands: list) -> MdUtils:
        """
        Creates the comment on how to accept risk for the Security Comment Template
        :param md: MdUtils - Main markdown variable
        :param ignore_commands: List of detected ignore commands based on the alerts associated purls
        :return:
        """
        md.new_line("<details>")
        md.new_line("<summary>Mark a package as acceptable risk</summary>")
        md.new_paragraph(
            "To ignore an alert, reply with a comment starting with `SocketSecurity ignore` followed by a space "
            "separated list of `ecosystem/package-name@version` specifiers. e.g. `SocketSecurity ignore npm/foo@1.0.0`"
            " or ignore all packages with `SocketSecurity ignore-all`"
        )
        md.new_list(ignore_commands)
        md.new_line("</details>")
        return md

    @staticmethod
    def create_security_alert_table(diff: Diff, md: MdUtils) -> (MdUtils, list, dict):
        """
        Creates the detected issues table based on the Security Policy
        :param diff: Diff - Diff report with the detected issues
        :param md: MdUtils - Main markdown variable
        :return:
        """
        alert_table = [
            "Alert",
            "Package",
            "Introduced by",
            "Manifest File",
            "CI"
        ]
        num_of_alert_columns = len(alert_table)
        next_steps = {}
        ignore_commands = []
        for alert in diff.new_alerts:
            alert: Issue
            if alert.next_step_title not in next_steps:
                next_steps[alert.next_step_title] = [
                    alert.description,
                    alert.suggestion
                ]
            ignore = f"`SocketSecurity ignore {alert.purl}`"
            if ignore not in ignore_commands:
                ignore_commands.append(ignore)
            manifest_str, source_str = Messages.create_sources(alert)
            purl_url = f"[{alert.purl}]({alert.url})"
            if alert.error:
                emoji = ':no_entry_sign:'
            else:
                emoji = ':warning:'
            row = [
                alert.title,
                purl_url,
                source_str,
                manifest_str,
                emoji
            ]
            if row not in alert_table:
                alert_table.extend(row)
        num_of_alert_rows = len(diff.new_alerts) + 1
        md.new_table(
            columns=num_of_alert_columns,
            rows=num_of_alert_rows,
            text=alert_table,
            text_align="left"
        )
        return md, ignore_commands, next_steps

    @staticmethod
    def dependency_overview_template(diff: Diff) -> str:
        """
        Creates the dependency Overview comment and returns a dict of the results
        :param diff: Diff - Diff report with the added & removed packages
        :return:
        """
        md = MdUtils(file_name="markdown_overview_temp.md")
        md.new_line("<!-- socket-overview-comment-actions -->")
        md.new_header(level=1, title="Socket Security: Dependency Overview")
        md.new_line("Review the following changes in direct dependencies. Learn more about [socket.dev](https://socket.dev)")
        md.new_line()
        md = Messages.create_added_table(diff, md)
        md.create_md_file()
        if len(md.file_data_text.lstrip()) >= 65500:
            md = Messages.short_dependency_overview_comment(diff)
        return md.file_data_text.lstrip()

    @staticmethod
    def short_dependency_overview_comment(diff: Diff) -> MdUtils:
        md = MdUtils(file_name="markdown_overview_temp.md")
        md.new_line("<!-- socket-overview-comment-actions -->")
        md.new_header(level=1, title="Socket Security: Dependency Overview")
        md.new_line("Review the following changes in direct dependencies. Learn more about [socket.dev](https://socket.dev)")
        md.new_line()
        md.new_line("The amount of dependency changes were to long for this comment. Please check out the full report")
        md.new_line(f"To view more information about this report checkout the [Full Report]({diff.diff_url})")
        return md

    @staticmethod
    def create_remove_line(diff: Diff, md: MdUtils) -> MdUtils:
        """
        Creates the removed packages line for the Dependency Overview template
        :param diff: Diff - Diff report with the removed packages
        :param md: MdUtils - Main markdown variable
        :return:
        """
        removed_line = "Removed packages:"
        for removed in diff.removed_packages:
            removed: Purl
            package_url = Messages.create_purl_link(removed)
            removed_line += f" {package_url},"
        removed_line = removed_line.rstrip(",")
        md.new_line(removed_line)
        return md

    @staticmethod
    def create_added_table(diff: Diff, md: MdUtils) -> MdUtils:
        """
        Create the Added packages table for the Dependency Overview template
        :param diff: Diff - Diff report with the Added package information
        :param md: MdUtils - Main markdown variable
        :return:
        """
        # Table column headers
        overview_table = [
            "Diff",
            "Package",
            "Supply Chain<br/>Security",
            "Vulnerability",
            "Quality",
            "Maintenance",
            "License"
        ]
        num_of_overview_columns = len(overview_table)

        count = 0
        for added in diff.new_packages:
            added: Purl  # Ensure `added` has scores and relevant attributes.

            package_url = f"[{added.purl}]({added.url})"
            diff_badge = f"[![+](https://github-app-statics.socket.dev/diff-added.svg)]({added.url})"

            # Scores dynamically converted to badge URLs and linked
            def score_to_badge(score):
                score_percent = int(score * 100)  # Convert to integer percentage
                return f"[![{score_percent}](https://github-app-statics.socket.dev/score-{score_percent}.svg)]({added.url})"

            # Generate badges for each score type
            supply_chain_risk_badge = score_to_badge(added.scores.get("supplyChain", 100))
            vulnerability_badge = score_to_badge(added.scores.get("vulnerability", 100))
            quality_badge = score_to_badge(added.scores.get("quality", 100))
            maintenance_badge = score_to_badge(added.scores.get("maintenance", 100))
            license_badge = score_to_badge(added.scores.get("license", 100))

            # Add the row for this package
            row = [
                diff_badge,
                package_url,
                supply_chain_risk_badge,
                vulnerability_badge,
                quality_badge,
                maintenance_badge,
                license_badge
            ]
            overview_table.extend(row)
            count += 1  # Count total packages

        # Calculate total rows for table
        num_of_overview_rows = count + 1  # Include header row

        # Generate Markdown table
        md.new_table(
            columns=num_of_overview_columns,
            rows=num_of_overview_rows,
            text=overview_table,
            text_align="center"
        )
        return md

    @staticmethod
    def create_purl_link(details: Purl) -> str:
        """
        Creates the Purl link for the Dependency Overview Comment for the added packages
        :param details: Purl - Details about the package needed to create the URLs
        :return:
        """
        package_url = f"[{details.purl}]({details.url})"
        return package_url

    @staticmethod
    def create_console_security_alert_table(diff: Diff) -> PrettyTable:
        """
        Creates the detected issues table based on the Security Policy
        :param diff: Diff - Diff report with the detected issues
        :return:
        """
        alert_table = PrettyTable(
            [
                "Alert",
                "Package",
                "url",
                "Introduced by",
                "Manifest File",
                "CI Status"
            ]
        )
        for alert in diff.new_alerts:
            alert: Issue
            manifest_str, source_str = Messages.create_sources(alert, "console")
            if alert.error:
                state = "block"
            elif alert.warn:
                state = "warn"
            elif alert.monitor:
                state = "monitor"
            else:
                state = "ignore"
            row = [
                alert.title,
                alert.purl,
                alert.url,
                source_str,
                manifest_str,
                state
            ]
            alert_table.add_row(row)
        return alert_table

    @staticmethod
    def create_sources(alert: Issue, style="md") -> [str, str]:
        sources = []
        manifests = []

        for source, manifest in alert.introduced_by:
            if style == "md":
                add_str = f"<li>{manifest}</li>"
                source_str = f"<li>{source}</li>"
            elif style == "plain":
                add_str = f"• {manifest}"
                source_str = f"• {source}"
            else:  # raw
                add_str = f"{manifest};"
                source_str = f"{source};"

            if source_str not in sources:
                sources.append(source_str)
            if add_str not in manifests:
                manifests.append(add_str)

        if style == "md":
            manifest_str = f"<ul>{''.join(manifests)}</ul>"
            sources_str = f"<ul>{''.join(sources)}</ul>"
        elif style == "plain":
            manifest_str = "\n".join(manifests)
            sources_str = "\n".join(sources)
        else:
            manifest_str = "".join(manifests).rstrip(";")
            sources_str = "".join(sources).rstrip(";")

        return manifest_str, sources_str
