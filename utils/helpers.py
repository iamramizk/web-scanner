import re
from urllib.parse import urlparse


class Helpers:
    @staticmethod
    def is_valid_url(url: str) -> bool:
        """Checks if a string is a valid URL"""

        # Regular expression for validating a URL
        regex = re.compile(
            r"^(?:http|ftp)s?://"  # http:// or https://
            r"|^"  # or start of string for URLs without a scheme
            r"(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+"  # domain
            r"(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|"  # domain extension
            r"localhost|"  # localhost
            r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|"  # ipv4
            r"\[?[A-F0-9]*:[A-F0-9:]+\]?)"  # ipv6
            r"(?::\d+)?"  # optional port
            r"(?:/?|[/?]\S+)?$",  # optional path
            re.IGNORECASE,
        )

        return re.match(regex, url) is not None

    @staticmethod
    def get_short_url(url: str) -> str | None:
        """Gets the short url without full path or schema"""
        # Add scheme if missing
        if not urlparse(url).scheme:
            url = "https://" + url

        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        if domain.startswith("www."):
            domain = domain[4:]
        return domain
