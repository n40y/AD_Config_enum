SCORE_WEIGHTS = {
    "pwd_in_description":  22,
    "asrep_roastable":     25,
    "unconstrained_deleg": 20,
    "no_pwd_required":     20,
    "kerberoastable":      18,
    "shadow_credentials":  15,
    "no_pwd_expiry":       15,
    "des_only":            10,
    "admin_count":          5,
    "account_disabled":     0,
}

LEVELS = [
    (70, "CRITIQUE", "bold red"),
    (40, "ÉLEVÉ",    "bold yellow"),
    (20, "MOYEN",    "bold green"),
    (0,  "FAIBLE",   "bold cyan"),
]


def compute_score(findings: list[str]) -> int:
    """Retourne un score de 0 à 100 basé sur les findings détectés."""
    return min(sum(SCORE_WEIGHTS.get(f, 0) for f in findings), 100)


def get_level(score: int) -> tuple[str, str]:
    """Retourne (label, couleur Rich) selon le score."""
    for threshold, label, color in LEVELS:
        if score >= threshold:
            return label, color
    return "FAIBLE", "bold cyan"
