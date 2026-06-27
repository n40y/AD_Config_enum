from ldap3 import Server, Connection, NTLM, ANONYMOUS
from rich.console import Console

console = Console()

# Codes d'erreur LDAP courants sur AD
_LDAP_ERRORS = {
    "525":  "Compte introuvable dans le domaine.",
    "52e":  "Mot de passe incorrect.",
    "530":  "Connexion refusée en dehors des horaires autorisés.",
    "531":  "Connexion refusée depuis ce poste.",
    "532":  "Mot de passe expiré — changement requis.",
    "533":  "Compte désactivé.",
    "701":  "Compte expiré.",
    "773":  "Changement de mot de passe requis à la prochaine connexion.",
    "775":  "Compte verrouillé.",
}


def _parse_ldap_error(result: dict) -> str:
    """Extrait un message lisible depuis le résultat ldap3."""
    message = result.get("message", "")
    for code, label in _LDAP_ERRORS.items():
        if f"data {code}" in message:
            return label
    description = result.get("description", "erreur inconnue")
    return f"{description} (code {result.get('result', '?')})"


def build_connection(target: str, domain: str, user: str | None, password: str | None):
    """
    Établit une connexion LDAP vers le DC.
    Retourne (conn, search_base) ou (None, None) en cas d'échec.

    Modes supportés :
      - Null session  : user=None, password=None
      - Mot de passe  : user + password en clair
      - Pass-the-Hash : user + password au format "aad3b435...:NTHASH"
                        (construit par main.py avant l'appel)
    """
    parts = domain.split(".")
    search_base = ",".join([f"dc={p}" for p in parts])

    try:
        server = Server(host=target, port=389, use_ssl=False, get_info="ALL")

        if not user and not password:
            conn = Connection(server, authentication=ANONYMOUS)
        else:
            short_domain = domain.split(".")[0].upper()
            user_complete = f"{short_domain}\\{user}"
            conn = Connection(server, user=user_complete, password=password, authentication=NTLM)

        if not conn.bind():
            reason = _parse_ldap_error(conn.result)
            console.print(f"[bold red][ - ][/bold red] Échec de l'authentification : {reason}")
            return None, None

        return conn, search_base

    except Exception as e:
        console.print(f"[bold red][ - ][/bold red] Erreur de connexion : {e}")
        return None, None
