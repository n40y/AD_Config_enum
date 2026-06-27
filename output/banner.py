from rich.console import Console
from rich.text import Text
from rich.panel import Panel

console = Console()

BANNER = r"""
    _   ____     _____ _   _ _   _ __  __
   / \ |  _ \   | ____| \ | | | | |  \/  |
  / _ \| | | |  |  _| |  \| | | | | |\/| |
 / ___ \ |_| |  | |___| |\  | |_| | |  | |
/_/   \_\____/  |_____|_| \_|\___/|_|  |_|
"""

SUBTITLE = "Active Directory Enumerator v1.0  —  by n40y"
TAGLINE   = "LDAP  |  NTLM  |  Pass-the-Hash  |  Null session  |  Rich output"


def print_banner():
    t = Text()
    t.append(BANNER, style="bold cyan")
    t.append(f"\n  {SUBTITLE}\n", style="dim white")
    t.append(f"  {TAGLINE}\n", style="dim cyan")
    console.print(t)


def print_connection_info(
    target: str,
    domain: str,
    user: str,
    is_pth: bool,
    auth_label: str = "Mot de passe",
):
    COLOR_MAP = {
        "Null session":  "yellow",
        "Pass-the-Hash": "yellow",
        "Mot de passe":  "green",
    }
    color = COLOR_MAP.get(auth_label, "green")

    console.print(
        Panel(
            f"[dim]Cible    :[/dim]  [bold]{target}[/bold]\n"
            f"[dim]Domaine  :[/dim]  [bold]{domain}[/bold]\n"
            f"[dim]Compte   :[/dim]  [bold]{user}[/bold]\n"
            f"[dim]Auth     :[/dim]  [{color}]{auth_label}[/{color}]",
            title="[bold green][ + ] Connexion réussie[/bold green]",
            border_style="green",
            expand=False,
        )
    )
    console.print()
