import json
import os
import re
import json

from pathlib import Path
from mdutils import MdUtils
from prettytable import PrettyTable

from socketsecurity.core.classes import Diff, Issue, Purl


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
             - Does a rough line-based search to find the actual line in the raw text
          2) Text-based (requirements.txt, package.json, yarn.lock, etc.)
             - Uses compiled regex patterns to detect a match line by line
        """
        # Extract just the file name to detect manifest type
        file_type = Path(manifest_file).name

        # ----------------------------------------------------
        # 1) JSON-based manifest files
        # ----------------------------------------------------
        if file_type in ["package-lock.json", "Pipfile.lock", "composer.lock"]:
            try:
                # Read entire file so we can parse JSON and also do raw line checks
                with open(manifest_file, "r", encoding="utf-8") as f:
                    raw_text = f.read()

                # Attempt JSON parse
                data = json.loads(raw_text)

                # In practice, you may need to check data["dependencies"], data["default"], etc.
                # This is an example approach.
                packages_dict = (
                    data.get("packages")
                    or data.get("default")
                    or data.get("dependencies")
                    or {}
                )

                found_key = None
                found_info = None
                # Locate a dictionary entry whose 'version' matches
                for key, value in packages_dict.items():
                    # For NPM package-lock, keys might look like "node_modules/axios"
                    if key.endswith(packagename) and "version" in value:
                        if value["version"] == packageversion:
                            found_key = key
                            found_info = value
                            break

                if found_key and found_info:
                    # Search lines to approximate the correct line number
                    needle_key = f'"{found_key}":'               # e.g. "node_modules/axios":
                    needle_version = f'"version": "{packageversion}"'
                    lines = raw_text.splitlines()
                    best_line = 1
                    snippet = None

                    for i, line in enumerate(lines, start=1):
                        if (needle_key in line) or (needle_version in line):
                            best_line = i
                            snippet = line.strip()
                            break  # On first match, stop

                    # If we found an approximate line, return it; else fallback to line 1
                    if best_line > 0 and snippet:
                        return best_line, snippet
                    else:
                        return 1, f'"{found_key}": {found_info}'
                else:
                    return 1, f"{packagename} {packageversion} (not found in {manifest_file})"

            except (FileNotFoundError, json.JSONDecodeError):
                return 1, f"Error reading {manifest_file}"

        # ----------------------------------------------------
        # 2) Text-based / line-based manifests
        # ----------------------------------------------------
        # Define a dictionary of patterns for common manifest types
        search_patterns = {
            "package.json":         rf'"{packagename}":\s*"{packageversion}"',
            "yarn.lock":            rf'{packagename}@{packageversion}',
            "pnpm-lock.yaml":       rf'"{re.escape(packagename)}"\s*:\s*\{{[^}}]*"version":\s*"{re.escape(packageversion)}"',
            "requirements.txt":     rf'^{re.escape(packagename)}\s*(?:==|===|!=|>=|<=|~=|\s+)?\s*{re.escape(packageversion)}(?:\s*;.*)?$',
            "pyproject.toml":       rf'{packagename}\s*=\s*"{packageversion}"',
            "Pipfile":              rf'"{packagename}"\s*=\s*"{packageversion}"',
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

        # If no specific pattern is found for this file name, fallback to a naive approach
        searchstring = search_patterns.get(file_type, rf'{re.escape(packagename)}.*{re.escape(packageversion)}')

        try:
            # Read file lines and search for a match
            with open(manifest_file, 'r', encoding="utf-8") as file:
                lines = [line.rstrip("\n") for line in file]
                for line_number, line_content in enumerate(lines, start=1):
                    # For Python conditional dependencies, ignore everything after first ';'
                    line_main = line_content.split(";", 1)[0].strip()

                    # Use a case-insensitive regex search
                    if re.search(searchstring, line_main, re.IGNORECASE):
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
        """
        scan_failed = False
        if len(diff.new_alerts) == 0:
            for alert in diff.new_alerts:
                alert: Issue
                if alert.error:
                    scan_failed = True
                    break
        sarif_data = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Socket Security",
                            "informationUri": "https://socket.dev",
                            "rules": []
                        }
                    },
                    "results": []
                }
            ]
        }

        rules_map = {}
        results_list = []

        for alert in diff.new_alerts:
            pkg_name = alert.pkg_name
            pkg_version = alert.pkg_version
            rule_id = f"{pkg_name}=={pkg_version}"
            severity = alert.severity

            # Generate the correct URL for the alert based on manifest type
            introduced_list = alert.introduced_by
            manifest_file = introduced_list[0][1] if introduced_list and isinstance(introduced_list[0], list) else alert.manifests or "requirements.txt"
            socket_url = Messages.get_manifest_type_url(manifest_file, pkg_name, pkg_version)

            # Prepare descriptions with <br/> replacements
            short_desc = f"{alert.props.get('note', '')}<br/><br/>Suggested Action:<br/>{alert.suggestion}<br/><a href=\"{socket_url}\">{socket_url}</a>"
            full_desc = "{} - {}".format(alert.title, alert.description.replace('\r\n', '<br/>'))

            # Identify the line and snippet in the manifest file
            line_number, line_content = Messages.find_line_in_file(pkg_name, pkg_version, manifest_file)
            if line_number < 1:
                line_number = 1  # Ensure SARIF compliance

            # Create the rule if not already defined
            if rule_id not in rules_map:
                rules_map[rule_id] = {
                    "id": rule_id,
                    "name": f"{pkg_name}=={pkg_version}",
                    "shortDescription": {"text": f"Alert generated for {rule_id} by Socket Security"},
                    "fullDescription": {"text": full_desc},
                    "helpUri": socket_url,
                    "defaultConfiguration": {
                        "level": Messages.map_severity_to_sarif(severity)
                    },
                }

            # Add the SARIF result
            result_obj = {
                "ruleId": rule_id,
                "message": {"text": short_desc},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": manifest_file},
                            "region": {
                                "startLine": line_number,
                                "snippet": {"text": line_content},
                            },
                        }
                    }
                ],
            }
            results_list.append(result_obj)

        # Attach rules and results
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
            "full_scan_id": diff.id
        }
        for alert in diff.new_alerts:
            alert: Issue
            output["new_alerts"].append(json.loads(str(alert)))
        return output

    @staticmethod
    def security_comment_template(diff: Diff) -> str:
        """
        Creates the security comment template
        :param diff: Diff - Diff report with the data needed for the template
        :return:
        """
        md = MdUtils(file_name="markdown_security_temp.md")
        md.new_line("<!-- socket-security-comment-actions -->")
        md.new_header(level=1, title="Socket Security: Issues Report")
        md.new_line("Potential security issues detected. Learn more about [socket.dev](https://socket.dev)")
        md.new_line("To accept the risk, merge this PR and you will not be notified again.")
        md.new_line()
        md.new_line("<!-- start-socket-alerts-table -->")
        md, ignore_commands, next_steps = Messages.create_security_alert_table(diff, md)
        md.new_line("<!-- end-socket-alerts-table -->")
        md.new_line()
        md = Messages.create_next_steps(md, next_steps)
        md = Messages.create_deeper_look(md)
        md = Messages.create_remove_package(md)
        md = Messages.create_acceptable_risk(md, ignore_commands)
        md.create_md_file()
        return md.file_data_text.lstrip()

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
        md.new_line("New and removed dependencies detected. Learn more about [socket.dev](https://socket.dev)")
        md.new_line()
        md = Messages.create_added_table(diff, md)
        if len(diff.removed_packages) > 0:
            md = Messages.create_remove_line(diff, md)
        md.create_md_file()
        if len(md.file_data_text.lstrip()) >= 65500:
            md = Messages.short_dependency_overview_comment(diff)
        return md.file_data_text.lstrip()

    @staticmethod
    def short_dependency_overview_comment(diff: Diff) -> MdUtils:
        md = MdUtils(file_name="markdown_overview_temp.md")
        md.new_line("<!-- socket-overview-comment-actions -->")
        md.new_header(level=1, title="Socket Security: Dependency Overview")
        md.new_line("New and removed dependencies detected. Learn more about [socket.dev](https://socket.dev)")
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
        :param diff: Diff - Diff report with the Added packages information
        :param md: MdUtils - Main markdown variable
        :return:
        """
        overview_table = [
            "Package",
            "Direct",
            "Capabilities",
            "Transitives",
            "Size",
            "Author"
        ]
        num_of_overview_columns = len(overview_table)
        count = 0
        for added in diff.new_packages:
            added: Purl
            package_url = Messages.create_purl_link(added)
            capabilities = ", ".join(added.capabilities)
            row = [
                package_url,
                added.direct,
                capabilities,
                added.transitives,
                f"{added.size} KB",
                added.author_url
            ]
            overview_table.extend(row)
            count += 1
        num_of_overview_rows = count + 1
        md.new_table(
            columns=num_of_overview_columns,
            rows=num_of_overview_rows,
            text=overview_table,
            text_align="left"
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
            else:
                add_str = f"{manifest};"
                source_str = f"{source};"
            if source_str not in sources:
                sources.append(source_str)
            if add_str not in manifests:
                manifests.append(add_str)
        manifest_list = "".join(manifests)
        source_list = "".join(sources)
        source_list = source_list.rstrip(";")
        manifest_list = manifest_list.rstrip(";")
        if style == "md":
            manifest_str = f"<ul>{manifest_list}</ul>"
            sources_str = f"<ul>{source_list}</ul>"
        else:
            manifest_str = manifest_list
            sources_str = source_list
        return manifest_str, sources_str
