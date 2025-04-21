import json

from requests import Response

from socketsecurity.core import log
from socketsecurity.core.classes import Comment, Issue


class Comments:
    @staticmethod
    def process_response(response: Response) -> dict:
        output = {}
        try:
            output = response.json()
        except Exception as error:
            log.debug("Unable to parse comment response json, trying as text")
            log.debug(error)
            try:
                output = json.loads(response.text)
            except Exception as error:
                log.error("Unable to process comment data, unable to get previous comment data")
                log.error(error)
        return output

    @staticmethod
    def remove_alerts(comments: dict, new_alerts: list) -> list:
        alerts = []
        if "ignore" not in comments:
            return new_alerts
        ignore_all, ignore_commands = Comments.get_ignore_options(comments)
        for alert in new_alerts:
            alert: Issue
            if ignore_all:
                break
            else:
                full_name = f"{alert.pkg_type}/{alert.pkg_name}"
                purl = (full_name, alert.pkg_version)
                purl_star = (full_name, "*")
                if purl in ignore_commands or purl_star in ignore_commands:
                    log.info(f"Alerts for {alert.pkg_name}@{alert.pkg_version} ignored")
                else:
                    log.info(f"Adding alert {alert.type} for {alert.pkg_name}@{alert.pkg_version}")
                    alerts.append(alert)
        return alerts

    @staticmethod
    def get_ignore_options(comments: dict) -> [bool, list]:
        ignore_commands = []
        ignore_all = False

        for comment in comments["ignore"]:
            comment: Comment
            first_line = comment.body_list[0]
            if not ignore_all and "SocketSecurity ignore" in first_line:
                try:
                    first_line = first_line.lstrip("@")
                    _, command = first_line.split("SocketSecurity ")
                    command = command.strip()
                    if command == "ignore-all":
                        ignore_all = True
                    else:
                        command = command.lstrip("ignore").strip()
                        name, version = command.split("@")
                        data = (name, version)
                        ignore_commands.append(data)
                except Exception as error:
                    log.error(f"Unable to process ignore command for {comment}")
                    log.error(error)
        return ignore_all, ignore_commands

    @staticmethod
    def is_ignore(pkg_name: str, pkg_version: str, name: str, version: str) -> bool:
        result = False
        if pkg_name == name and (pkg_version == version or version == "*"):
            result = True
        return result

    @staticmethod
    def is_heading_line(line) -> bool:
        is_heading_line = True
        if line != "|Alert|Package|Introduced by|Manifest File|CI|" and ":---" not in line:
            is_heading_line = False
        return is_heading_line

    @staticmethod
    def process_security_comment(comment: Comment, comments) -> str:
        ignore_all, ignore_commands = Comments.get_ignore_options(comments)
        if "start-socket-alerts-table" in "".join(comment.body_list):
            new_body = Comments.process_original_security_comment(comment, ignore_all, ignore_commands)
        else:
            new_body = Comments.process_updated_security_comment(comment, ignore_all, ignore_commands)

        return new_body

    @staticmethod
    def process_original_security_comment(
            comment: Comment,
            ignore_all: bool,
            ignore_commands: list[tuple[str, str]]
    ) -> str:
        start = False
        lines = []
        for line in comment.body_list:
            line = line.strip()
            if "start-socket-alerts-table" in line:
                start = True
                lines.append(line)
            elif start and "end-socket-alerts-table" not in line and not Comments.is_heading_line(line) and line != '':
                title, package, introduced_by, manifest, ci = line.lstrip("|").rstrip("|").split("|")
                details, _ = package.split("](")
                ecosystem, details = details.split("/", 1)
                ecosystem = ecosystem.lstrip("[")
                pkg_name, pkg_version = details.split("@")
                pkg_name = f"{ecosystem}/{pkg_name}"
                ignore = False
                for name, version in ignore_commands:
                    if ignore_all or Comments.is_ignore(pkg_name, pkg_version, name, version):
                        ignore = True
                if not ignore:
                    lines.append(line)
            elif "end-socket-alerts-table" in line:
                start = False
                lines.append(line)
            else:
                lines.append(line)
        return "\n".join(lines)

    @staticmethod
    def process_updated_security_comment(
            comment: Comment,
            ignore_all: bool,
            ignore_commands: list[tuple[str, str]]
    ) -> str:
        """
        Processes an updated security comment containing an HTML table with alert sections.
        Removes entire sections marked by start and end hidden comments if the alert matches
        ignore conditions.

        :param comment: Comment - The raw comment object containing the existing information.
        :param ignore_all: bool - Flag to ignore all alerts.
        :param ignore_commands: list of tuples - Specific ignore commands representing (pkg_name, pkg_version).
        :return: str - The updated comment as a single string.
        """
        lines = []
        ignore_section = False
        pkg_name = pkg_version = ""  # Track current package and version

        # Loop through the comment lines
        for line in comment.body_list:
            line = line.strip()

            # Detect the start of an alert section
            if line.startswith("<!-- start-socket-alert-"):
                # Extract package name and version from the comment
                try:
                    start_marker = line[len("<!-- start-socket-alert-"):-4]  # Strip the comment markers
                    pkg_name, pkg_version = start_marker.split("@")  # Extract pkg_name and pkg_version
                except ValueError:
                    pkg_name, pkg_version = "", ""

                # Determine if we should ignore this alert
                ignore_section = ignore_all or any(
                    Comments.is_ignore(pkg_name, pkg_version, name, version)
                    for name, version in ignore_commands
                )

                # If not ignored, include this start marker
                if not ignore_section:
                    lines.append(line)

            # Detect the end of an alert section
            elif line.startswith("<!-- end-socket-alert-"):
                # Only include if we are not ignoring this section
                if not ignore_section:
                    lines.append(line)
                ignore_section = False  # Reset ignore flag

            # Include lines inside an alert section only if not ignored
            elif not ignore_section:
                lines.append(line)

        return "\n".join(lines)

    @staticmethod
    def extract_alert_details_from_row(row: str, ignore_all: bool, ignore_commands: list[tuple[str, str]]) -> tuple:
        """
        Parses an HTML table row (<tr>) to extract alert details and determine if it should be ignored.

        :param row: str - The HTML table row as a string.
        :param ignore_all: bool - Flag to ignore all alerts.
        :param ignore_commands: list of tuples - List of (pkg_name, pkg_version) to ignore.
        :return: tuple - (pkg_name, pkg_version, ignore)
        """
        # Extract package details (pkg_name and pkg_version) from the HTML table row
        try:
            # Find the relevant <summary> element to extract package information
            start_index = row.index("<summary>")
            end_index = row.index("</summary>")
            summary_content = row[start_index + 9:end_index]  # Extract content between <summary> tags

            # Example: "npm/malicious-package@1.0.0 - Known Malware Alert"
            pkg_info, _ = summary_content.split(" - ", 1)
            pkg_name, pkg_version = pkg_info.split("@")
        except ValueError:
            # If parsing fails, skip this row
            return "", "", False

        # Check ignore logic
        ignore = False
        for name, version in ignore_commands:
            if ignore_all or Comments.is_ignore(pkg_name, pkg_version, name, version):
                ignore = True
                break

        return pkg_name, pkg_version, ignore


    @staticmethod
    def check_for_socket_comments(comments: dict):
        socket_comments = {}
        for comment_id in comments:
            comment = comments[comment_id]
            comment: Comment
            if "socket-security-comment-actions" in comment.body:
                socket_comments["security"] = comment
            elif "socket-overview-comment-actions" in comment.body:
                socket_comments["overview"] = comment
            elif "SocketSecurity ignore".lower() in comment.body_list[0].lower():
                if "ignore" not in socket_comments:
                    socket_comments["ignore"] = []
                socket_comments["ignore"].append(comment)
        return socket_comments
