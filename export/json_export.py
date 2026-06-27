import json
from datetime import datetime
from rich.console import Console

from core.scoring import compute_score, get_level

console = Console()


def export_json(all_findings: list[dict], filepath: str):
    """Exporte les résultats dans un fichier JSON structuré."""
    output = {
        "meta": {
            "generated_at": datetime.now().isoformat(),
            "tool": "AD_Config_enum v1.0",
            "author": "n40y",
        },
        "accounts": [],
    }

    for item in all_findings:
        score = compute_score(item["findings"])
        label, _ = get_level(score)
        output["accounts"].append({
            "user":     item["user"],
            "score":    score,
            "level":    label,
            "findings": item["findings"],
        })

    output["accounts"].sort(key=lambda x: x["score"], reverse=True)

    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(output, f, indent=2, ensure_ascii=False)
        console.print(f"[bold green][ + ][/bold green] Résultats exportés → [bold]{filepath}[/bold]")
    except OSError as e:
        console.print(f"[bold red][ - ][/bold red] Erreur d'export : {e}")
