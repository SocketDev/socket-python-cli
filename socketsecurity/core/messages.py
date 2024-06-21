import json

from mdutils import MdUtils
from socketsecurity.core.classes import Diff, Purl, Issue
from prettytable import PrettyTable


class Messages:

    @staticmethod
    def create_security_comment_json(diff: Diff) -> dict:
        if len(diff.new_alerts) == 0:
            scan_failed = False
        else:
            scan_failed = True
        output = {
            "scan_failed": scan_failed,
            "new_alerts": []
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
            "Manifest File"
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
            manifest_str, sources = Messages.create_sources(alert, "console")
            purl_url = f"[{alert.purl}]({alert.url})"
            row = [
                alert.title,
                purl_url,
                ", ".join(sources),
                manifest_str
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
        return md.file_data_text.lstrip()

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
                "Introduced by",
                "Manifest File"
            ]
        )
        for alert in diff.new_alerts:
            alert: Issue
            manifest_str, sources = Messages.create_sources(alert, "console")
            row = [
                alert.title,
                alert.url,
                ", ".join(sources),
                manifest_str
            ]
            alert_table.add_row(row)
        return alert_table

    @staticmethod
    def create_sources(alert: Issue, style="md") -> [str, list]:
        sources = []
        manifests = []
        for source, manifest in alert.introduced_by:
            sources.append(source)
            if style == "md":
                manifests.append(f"<li>{manifest}</li>")
            else:
                manifests.append(manifest)
        manifest_list = "".join(manifests)
        if style == "md":
            manifest_str = f"<ul>{manifest_list}</ul>"
        else:
            manifest_str = manifest_list
        return manifest_str, sources
