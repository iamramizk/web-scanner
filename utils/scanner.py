import requests
from urllib.parse import urlparse
import pydig
from bs4 import BeautifulSoup
from Wappalyzer import Wappalyzer, WebPage
import warnings
import json
from datetime import datetime
import os
import re
from collections import defaultdict
from rich.style import Style
from rich.progress import (
    Progress,
    TextColumn,
    BarColumn,
    SpinnerColumn,
)
from .nameserver import NsLookup
from .helpers import Helper


warnings.filterwarnings("ignore", category=UserWarning)


class Scanner:
    def __init__(self, url) -> None:
        self.output_dir: str = "data"
        self.runtime: str = ""
        self.url: str = url
        self.full_url: str = ""
        self.dns: dict = dict()
        self.whois: dict = dict()
        self.host: dict = dict()
        self.html: str = ""
        self.tech: dict = dict()
        self.headers: dict = dict()
        self.scripts: list = list()
        self.meta: dict = dict()
        self.socials: list = list()
        self.all: dict = dict()

        self.run()

    def run(self) -> None:
        now = datetime.now()
        self.runtime = now.strftime("%Y-%m-%d %H:%M:%S")

        self.clean_url()
        funcs = {
            self.get_dns: "Scanning DNS",
            self.get_whois: "Scanning WHOIS",
            self.get_host: "Scanning HOST",
            self.get_tech: "Scanning TECH",
            self.get_meta: "Scanning META",
            self.get_socials: "Scanning SOCIALS",
        }
        max_func_name_len = max(len(desc) for desc in funcs.values()) + 2

        with Progress(
            SpinnerColumn(style=Style(color="white")),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(
                style=Style(color="white"),
                complete_style=Style(color="cyan"),
            ),
            transient=True,
        ) as progress:
            task = progress.add_task("", total=len(funcs))
            for func, name in funcs.items():
                progress.update(
                    task, description=f"[cyan]{name.ljust(max_func_name_len)}"
                )
                try:
                    func()
                except Exception as e:
                    pass
                finally:
                    progress.advance(task)

        # save save all data
        self.all = {
            "runtime": self.runtime,
            "url": self.full_url,
            "dns": self.dns,
            "whois": self.whois,
            "host": self.host,
            "tech": self.tech,
            "headers": self.headers,
            "scripts": self.scripts,
            "meta": self.meta,
            "socials": self.socials,
        }
        with open(
            f"{self.output_dir}/{self.url}.json", "w", encoding="utf-8"
        ) as json_file:
            json.dump(self.all, json_file, indent=4)

    def clean_url(self) -> None:
        """Cleans the URL to the basic form"""
        if "//" in self.url:
            self.url = self.url.split("//")[1]

    def get_dns(self) -> None:
        results_dict = {
            "A": "",
            "NS": "",
            "CNAME": "",
            "SOA": "",
            "PTR": "",
            "MX": "",
            "TXT": "",
            "AAAA": "",
            "DS": "",
            "DNSKEY": "",
            "CDS": "",
            "CDNSKEY": "",
            "CAA": "",
        }
        for type, _ in results_dict.items():
            results_dict[type] = pydig.query(self.url, type)

        results_dict["TARGET"] = self.url

        results_dict = {k: v for k, v in results_dict.items() if v}
        self.dns = results_dict

    def get_whois(self) -> None:
        file_path = f"data/.whois-{self.url}.txt"
        os.system(f"whois {self.url} > {file_path}")
        result = defaultdict(list)
        # Regex for values start with a letter or digit after the space
        pattern = re.compile(
            r"^([A-Za-z ]+):\s([A-Za-z0-9].*)$",
            re.IGNORECASE,
        )

        with open(file_path, "r") as file:
            for line in file:
                match = pattern.match(line)
                if match:
                    key, value = match.groups()
                    result[key.strip()].append(value.strip())

        # Process the results to handle duplicates
        processed_result = {}
        for key, values in result.items():
            # Normalize values to lowercase for case insensitive comparison
            normalized_values = [v.lower() for v in values]
            unique_values = list(dict.fromkeys(normalized_values))

            # Convert lists with a single unique element to just the element
            if len(unique_values) == 1:
                # Find first original val that match normalized unique value
                original_value = next(
                    v for v in values if v.lower() == unique_values[0]
                )
                processed_result[key] = original_value
            else:
                # Retain the original values but remove duplicates
                seen = set()
                unique_case_values = []
                for v in values:
                    if v.lower() not in seen:
                        unique_case_values.append(v)
                        seen.add(v.lower())
                processed_result[key] = unique_case_values

        self.whois = processed_result
        os.system(f"rm {file_path}")

    def get_host(self) -> None:
        results = requests.get(f"http://ip-api.com/json/{self.url}").json()
        # Append nameserver to host dict
        if results["as"]:
            ns = NsLookup.get_name_by_as_string(results["as"])
            if ns:
                results["ns"] = ns
        self.host = results

    def get_tech(self) -> None:
        wappalyzer = Wappalyzer.latest()
        webpage = WebPage.new_from_url(f"https://{self.url}")
        technologies = wappalyzer.analyze_with_versions_and_categories(webpage)

        self.tech = technologies
        self.headers = dict(webpage.headers)
        self.scripts = webpage.scripts
        self.html = webpage.html
        self.full_url = webpage.url

    def get_meta(self) -> None:
        soup = BeautifulSoup(self.html, "html.parser")
        meta_title = soup.find("title").get_text() if soup.find("title") else None
        meta_description = (
            soup.find("meta", attrs={"name": "description"}).get("content")
            if soup.find("meta", attrs={"name": "description"})
            else None
        )

        # Store the results in a dictionary
        result = {
            "meta_title": meta_title,
            "meta_description": meta_description,
        }

        # Get all headers (h1-h6)
        for header_level in range(1, 7):
            result[f"h{header_level}"] = [
                header.get_text() for header in soup.find_all(f"h{header_level}")
            ]
        self.meta = result

    def get_socials(self) -> None:
        soup = BeautifulSoup(self.html, "html.parser")
        # Find all anchor tags
        anchor_tags = soup.find_all("a", href=True)

        social_media_domains = [
            "facebook.com",
            "fb.com",
            "twitter.com",
            "t.co",
            "x.com",
            "instagram.com",
            "instagr.am",
            "linkedin.com",
            "lnkd.in",
            "youtube.com",
            "youtu.be",
            "pinterest.com",
            "pin.it",
            "tiktok.com",
            "tiktokv.com",
            "snapchat.com",
            "sc.com",
            "reddit.com",
            "redd.it",
            "tumblr.com",
            "tmblr.co",
            "whatsapp.com",
            "wa.me",
            "telegram.org",
            "t.me",
            "wechat.com",
            "wechatapp.com",
            "vimeo.com",
            "flickr.com",
            "flic.kr",
            "medium.com",
            "discord.com",
            "discord.gg",
            "quora.com",
            "viber.com",
            "skype.com",
            "periscope.tv",
            "joinclubhouse.com",
            "twitch.tv",
            "kakaocorp.com",
            "kakao.com",
            "line.me",
            "linecorp.com",
        ]

        # Extract social media links
        social_media_links = []
        for tag in anchor_tags:
            href = tag["href"]
            parsed_url = urlparse(href)
            domain = parsed_url.netloc.lower()
            if any(
                domain.endswith(social_domain) for social_domain in social_media_domains
            ):
                # if any(domain in href for domain in social_media_domains):
                # remove / as some will show duplicates with or without
                if href.endswith("/"):
                    href = href[:-1]
                social_media_links.append(href)

        # remove duplicates
        social_media_links = list(set(social_media_links))
        self.socials = social_media_links
