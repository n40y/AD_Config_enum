from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box

from core.scoring import compute_score, get_level

console = Console()

CHECKS_DISPLAY = [
    ("no_pwd_expiry",      "Mot de passe expire",   "JAMAIS",           "OK (rotation active)"),
    ("asrep_roastable",    "Pre-auth Kerberos",      "DÉSACTIVÉ",        "ACTIF"),
    ("unconstrained_deleg","Délégation Kerberos",    "NON CONTRAINTE",   "AUCUNE"),
    ("des_only",           "Chiffrement",            "DES uniquement",   "AES 256"),
    ("no_pwd_required",    "Mot de passe requis",    "NON",              "OUI"),
    ("kerberoastable",     "SPN / Kerberoastable",   "OUI",              "NON"),
    ("pwd_in_description", "Description sensible",   "TROUVÉE",          "AUCUNE"),
    ("shadow_credentials", "Shadow Credentials",     "PRÉSENTES",        "AUCUNE"),
    ("admin_count",        "adminCount",             "= 1",              "= 0"),
    ("account_disabled",   "Compte",                 "DÉSACTIVÉ",        "ACTIF"),
]

REMEDIATION = {
    "no_pwd_expiry":       "Activer l'expiration du mot de passe",
    "asrep_roastable":     "Activer la pré-authentification Kerberos",
    "unconstrained_deleg": "Passer en délégation contrainte ou RBCD",
    "des_only":            "Forcer AES 256 dans les propriétés du compte",
    "no_pwd_required":     "Exiger un mot de passe sur ce compte",
    "kerberoastable":      "Utiliser un mot de passe long (+25 chars) ou gMSA",
    "pwd_in_description":  "Supprimer le mot de passe de la description",
    "shadow_credentials":  "Auditer msDS-KeyCredentialLink (PyWhisker)",
    "admin_count":         "Vérifier l'appartenance aux groupes privilégiés",
}


def render_user_panel(entry, findings: list[str]):
    sam   = entry["user"] if isinstance(entry, dict) else str(entry.sAMAccountName)
    score = compute_score(findings)
    label, color = get_level(score)

    table = Table(
        box=box.SIMPLE,
        show_header=False,
        padding=(0, 1),
        expand=True,
    )
    table.add_column(style="dim", width=26)
    table.add_column(width=22)
    table.add_column(style="dim italic", width=36)

    for key, display_label, bad_val, ok_val in CHECKS_DISPLAY:
        is_bad = key in findings
        icon   = "[red]✗[/red]" if is_bad else "[green]✓[/green]"
        val    = f"[red]{bad_val}[/red]" if is_bad else f"[green]{ok_val}[/green]"
        remed  = REMEDIATION.get(key, "") if is_bad else ""
        table.add_row(f"{icon}  {display_label}", val, remed)

    title = Text()
    title.append(f"  {sam}  ", style="bold white")
    title.append(f" {label} ", style=f"reverse {color}")
    title.append(f"  {score}/100  ", style=color)

    console.print(Panel(table, title=title, border_style=color.split()[-1], expand=False))
    console.print()
