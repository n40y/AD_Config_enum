from argparse import ArgumentParser
from getpass import getpass
import sys

from core.connection import build_connection
from core.analyzer import analyze_entry
from output.banner import print_banner, print_connection_info
from output.renderer import render_user_panel
from output.summary import render_summary
from export.json_export import export_json

MAX_ATTEMPTS = 3


def parse_args():
    parser = ArgumentParser(
        prog="ad_enum",
        description="Active Directory Enumerator — détection de mauvaises configurations"
    )
    parser.add_argument('-t', '--target',   required=True,  help="IP ou hostname du DC")
    parser.add_argument('-d', '--domain',   required=True,  help="Domaine (ex: corp.local)")
    parser.add_argument('-u', '--user',     default=None,   help="Nom d'utilisateur")
    parser.add_argument('-p', '--password', default=None,   help="Mot de passe en clair")
    parser.add_argument('-H', '--hashNTLM', default=None,   help="Hash NT seul (sans le LM)")
    parser.add_argument('-o', '--output',   default=None,   help="Fichier de sortie JSON")
    parser.add_argument('-v', '--verbose',  action='store_true', help="Afficher tous les comptes")
    return parser.parse_args()


def _resolve_auth(args):
    """
    Détermine le mode d'authentification.
    Retourne (user, password, auth_label).

      - Aucun argument     → null session  (user=None, password=None)
      - -u seul            → prompt interactif  (password=None, géré dans _connect)
      - -u + -p            → mot de passe direct
      - -u + -H            → Pass-the-Hash
      - -H sans -u         → erreur
      - -p sans -u         → erreur
    """
    if args.hashNTLM and not args.user:
        print("[-] --hashNTLM (-H) requiert un nom d'utilisateur (-u).")
        sys.exit(1)
    if args.password and not args.user:
        print("[-] --password (-p) requiert un nom d'utilisateur (-u).")
        sys.exit(1)

    if args.user and args.hashNTLM:
        return args.user, f"aad3b435b51404eeaad3b435b51404ee:{args.hashNTLM}", "Pass-the-Hash"

    if args.user and args.password:
        return args.user, args.password, "Mot de passe"

    if args.user:
        # password=None → prompt interactif dans _connect_with_retry
        return args.user, None, "Mot de passe"

    # Aucun credential → null session
    return None, None, "Null session"


def _connect_with_retry(target, domain, user, password):
    """
    Tente la connexion LDAP.
    - Si password est déjà connu (ou user=None pour null session) : connexion directe.
    - Si user est fourni mais password=None : prompt interactif avec MAX_ATTEMPTS essais.
    """
    # Null session ou password déjà fourni → connexion directe
    if user is None or password is not None:
        return build_connection(target, domain, user, password)

    # Prompt interactif avec retry
    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            pwd = getpass(f"[?] Mot de passe pour {user}: ")
        except KeyboardInterrupt:
            print("\n[-] Annulé.")
            sys.exit(0)

        if not pwd:
            print("[-] Mot de passe vide.")
            continue

        conn, search_base = build_connection(target, domain, user, pwd)
        if conn is not None:
            return conn, search_base

        remaining = MAX_ATTEMPTS - attempt
        if remaining > 0:
            print(f"    {remaining} tentative(s) restante(s).\n")

    print(f"[-] Échec après {MAX_ATTEMPTS} tentatives.")
    sys.exit(1)


def main():
    args = parse_args()
    print_banner()

    user, password, auth_label = _resolve_auth(args)

    conn, search_base = _connect_with_retry(args.target, args.domain, user, password)
    if conn is None:
        sys.exit(1)

    is_pth = args.hashNTLM is not None
    print_connection_info(
        args.target, args.domain,
        user or "(anonyme)",
        is_pth,
        auth_label=auth_label,
    )

    if auth_label == "Null session":
        from rich.console import Console
        Console().print(
            "[bold yellow][!][/bold yellow] Null session — "
            "l'énumération LDAP anonyme est bloquée sur la plupart des AD modernes.\n"
            "    Fournir des credentials (-u / -p ou -H) pour un scan complet.\n"
        )

    search_filter = '(&(objectclass=user)(!(objectClass=computer)))'
    attrs = [
        'sAMAccountName', 'description', 'userAccountControl',
        'msDS-KeyCredentialLink', 'servicePrincipalName', 'adminCount',
        'lastLogonTimestamp', 'pwdLastSet',
    ]
    conn.search(search_base, search_filter, attributes=attrs)

    if not conn.entries:
        from rich.console import Console
        Console().print("[bold yellow][!][/bold yellow] Aucun compte retourné par le DC.")
        sys.exit(0)

    all_findings = []
    for entry in conn.entries:
        findings = analyze_entry(entry)
        if findings or args.verbose:
            render_user_panel(entry, findings)
        all_findings.append({
            "user": str(entry.sAMAccountName),
            "findings": findings,
        })

    render_summary(all_findings)

    if args.output:
        export_json(all_findings, args.output)


if __name__ == "__main__":
    main()
