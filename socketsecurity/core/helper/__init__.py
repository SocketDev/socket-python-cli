import markdown
from bs4 import BeautifulSoup, NavigableString, Tag
import string


class Helper:
    @staticmethod
    def parse_gfm_section(html_content):
        """
        Parse a GitHub-Flavored Markdown section containing a table and surrounding content.
        Returns a dict with "before_html", "columns", "rows_html", and "after_html".
        """
        html = markdown.markdown(html_content, extensions=['extra'])
        soup = BeautifulSoup(html, "html.parser")

        table = soup.find('table')
        if not table:
            # If no table, treat entire content as before_html
            return {"before_html": html, "columns": [], "rows_html": [], "after_html": ''}

        # Collect HTML before the table
        before_parts = [str(elem) for elem in table.find_previous_siblings()]
        before_html = ''.join(reversed(before_parts))

        # Collect HTML after the table
        after_parts = [str(elem) for elem in table.find_next_siblings()]
        after_html = ''.join(after_parts)

        # Extract table headers
        headers = [th.get_text(strip=True) for th in table.find_all('th')]

        # Extract table rows (skip header)
        rows_html = []
        for tr in table.find_all('tr')[1:]:
            cells = [str(td) for td in tr.find_all('td')]
            rows_html.append(cells)

        return {
            "before_html": before_html,
            "columns": headers,
            "rows_html": rows_html,
            "after_html": after_html
        }

    @staticmethod
    def parse_cell(html_td):
        """Convert a table cell HTML into plain text or a dict for links/images."""
        soup = BeautifulSoup(html_td, "html.parser")
        a = soup.find('a')
        if a:
            cell = {"url": a.get('href', '')}
            img = a.find('img')
            if img:
                cell.update({
                    "img_src": img.get('src', ''),
                    "title": img.get('title', ''),
                    "link_text": a.get_text(strip=True)
                })
            else:
                cell["link_text"] = a.get_text(strip=True)
            return cell
        return soup.get_text(strip=True)

    @staticmethod
    def parse_html_parts(html_fragment):
        """
        Convert an HTML fragment into a list of parts.
        Each part is either:
          - {"text": "..."}
          - {"link": "url", "text": "..."}
          - {"img_src": "url", "alt": "...", "title": "..."}
        """
        soup = BeautifulSoup(html_fragment, 'html.parser')
        parts = []

        def handle_element(elem):
            if isinstance(elem, NavigableString):
                text = str(elem).strip()
                if text and not all(ch in string.punctuation for ch in text):
                    parts.append({"text": text})
            elif isinstance(elem, Tag):
                if elem.name == 'a':
                    href = elem.get('href', '')
                    txt = elem.get_text(strip=True)
                    parts.append({"link": href, "text": txt})
                elif elem.name == 'img':
                    parts.append({
                        "img_src": elem.get('src', ''),
                        "alt": elem.get('alt', ''),
                        "title": elem.get('title', '')
                    })
                else:
                    # Recurse into children for nested tags
                    for child in elem.children:
                        handle_element(child)

        for element in soup.contents:
            handle_element(element)

        return parts

    @staticmethod
    def section_to_json(section_result):
        """
        Convert a parsed section into structured JSON.
        Returns {"before": [...], "table": [...], "after": [...]}.
        """
        # Build JSON rows for the table
        table_rows = []
        cols = section_result.get('columns', [])
        for row_html in section_result.get('rows_html', []):
            cells = [Helper.parse_cell(cell_html) for cell_html in row_html]
            table_rows.append(dict(zip(cols, cells)))

        return {
            "before": Helper.parse_html_parts(section_result.get('before_html', '')),
            "table": table_rows,
            "after": Helper.parse_html_parts(section_result.get('after_html', ''))
        }