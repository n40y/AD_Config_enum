from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.columns import Columns
from rich.text import Text
from rich import box

from core.scoring import compute_score, get_level

console = Console()

FINDING_LABELS = {
    "pwd_in_description":  ("CRITICAL", "red",    "Mot de passe en clair dans description"),
    "asrep_roastable":     ("CRITICAL", "red",    "AS-REP Roasting possible"),
    "unconstrained_deleg": ("CRITICAL", "red",    "Délégation non contrainte"),
    "no_pwd_required":     ("CRITICAL", "red",    "Aucun mot de passe requis"),
    "kerberoastable":      ("HIGH",     "yellow", "SPN exposé — Kerberoastable"),
    "shadow_credentials":  ("HIGH",     "yellow", "Shadow Credentials présentes"),
    "no_pwd_expiry":       ("HIGH",     "yellow", "Mot de passe sans expiration"),
    "des_only":            ("MEDIUM",   "green",  "Chiffrement DES uniquement"),
    "admin_count":         ("INFO",     "cyan",   "Compte à privilèges (adminCount=1)"),
    "account_disabled":    ("INFO",     "cyan",   "Compte désactivé"),
}


def render_summary(all_findings: list[dict]):
    console.rule("[bold white]Résumé du domaine[/bold white]")
    console.print()

    counts = {"CRITIQUE": 0, "ÉLEVÉ": 0, "MOYEN": 0, "FAIBLE": 0}
    top_risks = []

    for item in all_findings:
        score = compute_score(item["findings"])
        label, _ = get_level(score)
        counts[label] += 1
        if item["findings"]:
            top_risks.append((score, item["user"], item["findings"]))

    top_risks.sort(reverse=True)

    stat_panels = [
        Panel(Text(str(counts["CRITIQUE"]), style="bold red",    justify="center"), title="Critiques", border_style="red"),
        Panel(Text(str(counts["ÉLEVÉ"]),    style="bold yellow", justify="center"), title="Élevés",    border_style="yellow"),
        Panel(Text(str(counts["MOYEN"]),    style="bold green",  justify="center"), title="Moyens",    border_style="green"),
        Panel(Text(str(counts["FAIBLE"]),   style="bold cyan",   justify="center"), title="Faibles",   border_style="cyan"),
    ]
    console.print(Columns(stat_panels, equal=True))
    console.print()

    if top_risks:
        console.print("[bold white]Top risques détectés[/bold white]\n")
        table = Table(box=box.SIMPLE_HEAD, expand=True)
        table.add_column("Compte",    style="bold white", width=20)
        table.add_column("Score",     width=8)
        table.add_column("Niveau",    width=10)
        table.add_column("Findings",  style="dim")

        for score, user, findings in top_risks[:10]:
            label, color = get_level(score)
            finding_text = ", ".join(
                f"[{FINDING_LABELS[f][1]}]{f}[/{FINDING_LABELS[f][1]}]"
                for f in findings
                if f in FINDING_LABELS
            )
            table.add_row(user, str(score), f"[{color.split()[-1]}]{label}[/]", finding_text)

        console.print(table)
        console.print()

    total = len(all_findings)
    global_score = int(sum(compute_score(i["findings"]) for i in all_findings) / total) if total else 0
    g_label, g_color = get_level(global_score)

    console.print(
        Panel(
            f"[dim]Comptes analysés :[/dim]  [bold]{total}[/bold]\n"
            f"[dim]Score global     :[/dim]  [{g_color.split()[-1]}][bold]{global_score}/100  {g_label}[/bold][/]",
            title="Score du domaine",
            border_style=g_color.split()[-1],
            expand=False,
        )
    )
    console.print()
