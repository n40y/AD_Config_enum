"""
Mode démo — simule un scan AD sans connexion réelle.
Usage : python3 demo.py
"""

from output.banner import print_banner, print_connection_info
from output.renderer import render_user_panel
from output.summary import render_summary
from export.json_export import export_json

FAKE_ACCOUNTS = [
    {
        "user": "Administrator",
        "findings": [
            "no_pwd_expiry", "asrep_roastable", "unconstrained_deleg",
            "des_only", "no_pwd_required", "pwd_in_description", "admin_count"
        ],
    },
    {
        "user": "svc_backup",
        "findings": ["kerberoastable", "no_pwd_expiry", "admin_count"],
    },
    {
        "user": "svc_sql",
        "findings": ["pwd_in_description", "no_pwd_expiry", "kerberoastable"],
    },
    {
        "user": "j.dupont",
        "findings": ["no_pwd_expiry"],
    },
    {
        "user": "m.martin",
        "findings": [],
    },
    {
        "user": "svc_web",
        "findings": ["shadow_credentials", "unconstrained_deleg"],
    },
    {
        "user": "guest",
        "findings": ["account_disabled", "no_pwd_required"],
    },
]


def main():
    print_banner()
    print_connection_info(
        target="192.168.1.10",
        domain="corp.local",
        user="(démo)",
        is_pth=False,
        auth_label="Null session",
    )

    for item in FAKE_ACCOUNTS:
        render_user_panel(item, item["findings"])

    render_summary(FAKE_ACCOUNTS)
    export_json(FAKE_ACCOUNTS, "demo_rapport.json")


if __name__ == "__main__":
    main()
