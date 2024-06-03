import os
import sys
import json
from datetime import datetime
from textual.app import App, ComposeResult
from textual.screen import Screen
from textual.widgets import Footer, Header, Static
from textual.containers import ScrollableContainer
from rich.table import Table
from rich import box
from rich.prompt import Confirm
from rich.panel import Panel
from rich.console import Console
from utils.scanner import Scanner

console = Console()


def get_header_panel(text: str):
    return Panel(
        str(text),
        style="bold",
        border_style="cyan",
    )


def get_table(data, width=22, three_col=False) -> Table:
    table = Table(show_header=False, box=box.SIMPLE, show_lines=True)

    # tech stack data has 3 cols
    if three_col:
        table.add_column("Category", style="bold cyan", width=width)
        table.add_column("Item")
        table.add_column("Version", style="dim")
        for k, v in data.items():
            table.add_row(
                str(data[k]["categories"][0]).upper(),
                str(k),
                "\n".join(data[k]["versions"]),
            )
        return table

    # all other data has 2 col
    else:
        table.add_column(
            "Key",
            style="bold cyan",
            width=width,
            no_wrap=False,
            overflow="fold",
        )
        table.add_column("Value", no_wrap=False, overflow="fold")
        if isinstance(data, dict):
            for k, v in data.items():
                if isinstance(v, list):
                    v = "\n".join(v)
                table.add_row(
                    str(k).upper().replace("-", " ").replace("_", " "), str(v)
                )

        # scripts data is a list
        elif isinstance(data, list):
            for idx, row in enumerate(data):
                table.add_row(str(idx), str(row))

        return table


class DnsScreen(Screen):
    def compose(self) -> ComposeResult:
        yield Header()
        yield Static(get_header_panel("DNS"))
        yield ScrollableContainer(
            Static(get_table(data["dns"], 15)),
            classes="panel",
        )
        yield Footer()


class WhoisScreen(Screen):
    def compose(self) -> ComposeResult:
        yield Header()
        yield Static(get_header_panel("WHOIS"))
        yield ScrollableContainer(
            Static(get_table(data["whois"])),
            classes="panel",
        )
        yield Footer()


class HostScreen(Screen):
    def compose(self) -> ComposeResult:
        yield Header()
        yield Static(get_header_panel("HOST"))
        yield ScrollableContainer(
            Static(get_table(data["host"])),
            classes="panel",
        )
        yield Footer()


class TechScreen(Screen):
    def compose(self) -> ComposeResult:
        yield Header()
        yield Static(get_header_panel("TECH"))
        yield ScrollableContainer(
            Static(get_table(data["tech"], three_col=True)),
            classes="panel",
        )
        yield Footer()


class HeadersScreen(Screen):
    def compose(self) -> ComposeResult:
        yield Header()
        yield Static(get_header_panel("HEADERS"))
        yield ScrollableContainer(
            Static(get_table(data["headers"])),
            classes="panel",
        )
        yield Footer()


class ScriptsScreen(Screen):
    def compose(self) -> ComposeResult:
        yield Header()
        yield Static(get_header_panel("SCRIPTS"))
        yield ScrollableContainer(
            Static(get_table(data["scripts"], width=3)), classes="panel"
        )
        yield Footer()


class MetaScreen(Screen):
    def compose(self) -> ComposeResult:
        yield Header()
        yield Static(get_header_panel("META"))
        yield ScrollableContainer(
            Static(get_table(data["meta"])),
            classes="panel",
        )
        yield Footer()


class SocialsScreen(Screen):
    def compose(self) -> ComposeResult:
        yield Header()
        yield Static(get_header_panel("SOCIAL"))
        yield ScrollableContainer(
            Static(get_table(data["socials"], width=3)),
            classes="panel",
        )
        yield Footer()


class WebScanner(App):
    CSS_PATH = "utils/styles.tcss"

    BINDINGS = [
        ("q", "quit", "Quit"),
        ("d", "switch_mode('dns')", "DNS"),
        ("w", "switch_mode('whois')", "Whois"),
        ("h", "switch_mode('host')", "Host"),
        ("t", "switch_mode('tech')", "Tech"),
        ("e", "switch_mode('headers')", "Headers"),
        ("s", "switch_mode('scripts')", "Scripts"),
        ("m", "switch_mode('meta')", "Meta"),
        ("o", "switch_mode('socials')", "Socials"),
    ]
    MODES = {
        "dns": DnsScreen,
        "whois": WhoisScreen,
        "host": HostScreen,
        "tech": TechScreen,
        "headers": HeadersScreen,
        "scripts": ScriptsScreen,
        "meta": MetaScreen,
        "socials": SocialsScreen,
    }

    def on_mount(self) -> None:
        self.switch_mode("dns")


def get_modified_time(file_path: str) -> str:
    timestamp = os.path.getmtime(file_path)
    last_modified_date = datetime.fromtimestamp(timestamp)
    last_modified_str = last_modified_date.strftime("%Y-%m-%d %H:%M:%S")
    return last_modified_str


def clean_url(url: str) -> str:
    """Cleans the URL to the basic form"""
    if "//" in url:
        return url.split("//")[1].strip()
    return url.strip()


if __name__ == "__main__":
    args = sys.argv
    if not len(args) > 1:
        console.print(
            "\n[bold red][!][/bold red] Must provide target URL as argumet.",
        )
        exit()

    target = str(args[1])
    target = clean_url(target)

    # check if file exists
    if os.path.isfile(f"data/{target}.json"):
        console.print(
            f"\n[bold cyan][>][/bold cyan] File found from: [white]{get_modified_time(f'data/{target}.json')}[/white]"
        )
        open_from_cache = Confirm.ask(
            "[bold cyan][>][/bold cyan] Open from cache? [bold cyan](y/n)[/bold cyan]",
            show_choices=False,
        )
        print()
        if open_from_cache:
            with open(f"data/{target}.json", "r") as f:
                data = json.load(f)

        else:
            scanner = Scanner(target)
            data = scanner.all
    else:
        scanner = Scanner(target)
        data = scanner.all

    WebScanner().run()
