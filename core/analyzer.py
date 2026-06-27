from regex import search, IGNORECASE

UAC_CHECKS = [
    (2,       "account_disabled"),
    (32,      "no_pwd_required"),
    (65536,   "no_pwd_expiry"),
    (524288,  "unconstrained_deleg"),
    (2097152, "des_only"),
    (4194304, "asrep_roastable"),
]

PWD_PATTERN = r"pass|pwd|mdp|password|motdepasse|secret|cred"


def analyze_entry(entry) -> list[str]:
    """
    Analyse un compte AD et retourne la liste des identifiants de findings.
    Chaque finding est une clé string utilisée par scoring.py et renderer.py.
    """
    findings = []

    _check_description(entry, findings)
    _check_uac(entry, findings)
    _check_spn(entry, findings)
    _check_shadow_credentials(entry, findings)
    _check_admin_count(entry, findings)

    return findings


def _check_description(entry, findings: list):
    if 'description' in entry and entry.description:
        text = str(entry.description)
        if search(PWD_PATTERN, text, flags=IGNORECASE):
            findings.append("pwd_in_description")


def _check_uac(entry, findings: list):
    if 'userAccountControl' not in entry or not entry.userAccountControl:
        return
    try:
        uac = int(entry.userAccountControl.value)
        for flag, key in UAC_CHECKS:
            if uac & flag:
                findings.append(key)
    except (TypeError, ValueError):
        pass


def _check_spn(entry, findings: list):
    if 'servicePrincipalName' in entry and entry.servicePrincipalName:
        findings.append("kerberoastable")


def _check_shadow_credentials(entry, findings: list):
    if 'msDS-KeyCredentialLink' in entry and entry['msDS-KeyCredentialLink']:
        findings.append("shadow_credentials")


def _check_admin_count(entry, findings: list):
    if 'adminCount' in entry and entry.adminCount.value == 1:
        findings.append("admin_count")
