from rich.panel import Panel
from rich.console import Console
from rich import box

console = Console()

panel = Panel(
    "DNS",
    style="cyan on black",
    border_style="none",
    box=box.SIMPLE,
)

console.print(panel)
