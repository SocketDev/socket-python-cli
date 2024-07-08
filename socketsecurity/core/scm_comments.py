from socketsecurity.core.classes import Comment, Issue
from socketsecurity.core import log
from requests import Response
import json


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
                purl = f"{alert.pkg_name}, {alert.pkg_version}"
                purl_star = f"{alert.pkg_name}, *"
                if purl in ignore_commands or purl_star in ignore_commands:
                    print(f"Alerts for {alert.pkg_name}@{alert.pkg_version} ignored")
                else:
                    print(f"Adding alert {alert.type} for {alert.pkg_name}@{alert.pkg_version}")
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
                first_line = first_line.lstrip("@")
                _, command = first_line.split("SocketSecurity ")
                command = command.strip()
                if command == "ignore-all":
                    ignore_all = True
                else:
                    command = command.lstrip("ignore").strip()
                    name, version = command.split("@")
                    data = f"{name}, {version}"
                    ignore_commands.append(data)
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
        if line != "|Alert|Package|Introduced by|Manifest File|" and ":---" not in line:
            is_heading_line = False
        return is_heading_line

    @staticmethod
    def process_security_comment(comment: Comment, comments) -> str:
        lines = []
        start = False
        ignore_all, ignore_commands = Comments.get_ignore_options(comments)
        for line in comment.body_list:
            line = line.strip()
            if "start-socket-alerts-table" in line:
                start = True
                lines.append(line)
            elif start and "end-socket-alerts-table" not in line and not Comments.is_heading_line(line) and line != '':
                title, package, introduced_by, manifest = line.lstrip("|").rstrip("|").split("|")
                details, _ = package.split("](")
                ecosystem, details = details.split("/", 1)
                pkg_name, pkg_version = details.split("@")
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
        new_body = "\n".join(lines)
        return new_body

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
            elif "SocketSecurity ignore" in comment.body:
                if "ignore" not in socket_comments:
                    socket_comments["ignore"] = []
                socket_comments["ignore"].append(comment)
        return socket_comments
