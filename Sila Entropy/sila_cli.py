import math
from itertools import product

from sila_analysis import (
    build_attack_assessment,
    contains_khmer_dictionary_term,
    get_guessability_engine_name,
    get_expert_analysis,
    get_strength_label,
    mask_secret,
    summarize_breach_status,
)
from sila_breach import check_pwned_api, load_khmer_dict
from sila_config import ATTACKER_SCALE, BRAND_LOGO, HASH_PROFILES, ONLINE_DEFENSE, NIST_MIN_LENGTH
from sila_models import (
    calculate_bruteforce_time,
    format_duration,
    get_metrics,
    get_offline_guesses_per_second,
    get_online_guesses_per_second,
)


def _build_all_scenarios():
    scenarios = []
    for hash_profile, attacker_profile, online_defense in product(
        HASH_PROFILES.keys(), ATTACKER_SCALE.keys(), ONLINE_DEFENSE.keys()
    ):
        scenarios.append(
            {
                "hash_profile": hash_profile,
                "attacker_profile": attacker_profile,
                "online_defense": online_defense,
            }
        )
    return scenarios


def run_audit():
    try:
        from rich import box
        from rich.console import Console
        from rich.panel import Panel
        from rich.table import Table
    except ImportError:
        print("Missing dependency: rich. Install with: pip install rich")
        return

    console = Console()
    console.print(f"[bold cyan]{BRAND_LOGO}[/bold cyan]")
    console.print(
        Panel(
            "[bold white]SILA ENTROPY | National Security Auditor | v5.6 | Author : Bubble[/bold white]",
            border_style="blue",
        )
    )

    scenarios = _build_all_scenarios()
    console.print(
        f"[dim]Testing all profiles: {len(HASH_PROFILES)} hash x {len(ATTACKER_SCALE)} attacker x "
        f"{len(ONLINE_DEFENSE)} online defense = {len(scenarios)} scenarios[/dim]"
    )
    console.print(f"[dim]Guessability engine: {get_guessability_engine_name()}[/dim]")

    khmer_dict = load_khmer_dict()
    user_input = console.input("\n[bold yellow]Target(s) to Audit (comma separated): [/bold yellow]")
    passwords = [p.strip() for p in user_input.split(",") if p.strip()]

    if not passwords:
        console.print("[red]No valid targets provided.[/red]")
        return

    table = Table(box=box.SQUARE, header_style="bold white", border_style="dim", expand=True)
    table.add_column("TargetID", justify="center")
    table.add_column("Credential", style="cyan")
    table.add_column("Entropy", justify="right")
    table.add_column("Strength", justify="center")
    table.add_column("Breach Status", justify="center")
    table.add_column("Offline Fastest", justify="right")
    table.add_column("Online Fastest", justify="right")

    audit_results = []

    for index, password in enumerate(passwords, start=1):
        entropy, _, _ = get_metrics(password)
        leak_result = check_pwned_api(password)
        nist_status = "[green]PASS[/]" if len(password) >= NIST_MIN_LENGTH else "[red]FAIL[/]"
        breach_text = summarize_breach_status(leak_result)

        scenario_assessments = []
        for scenario in scenarios:
            assessment = build_attack_assessment(
                password,
                entropy,
                hash_profile=scenario["hash_profile"],
                attacker_profile=scenario["attacker_profile"],
                online_defense=scenario["online_defense"],
            )
            scenario_assessments.append({"scenario": scenario, "assessment": assessment})

        fastest_offline = min(
            scenario_assessments,
            key=lambda x: x["assessment"]["offline_conservative"]["expected_seconds"],
        )
        slowest_offline = max(
            scenario_assessments,
            key=lambda x: x["assessment"]["offline_conservative"]["expected_seconds"],
        )
        fastest_online = min(
            scenario_assessments,
            key=lambda x: x["assessment"]["online_conservative"]["expected_seconds"],
        )
        slowest_online = max(
            scenario_assessments,
            key=lambda x: x["assessment"]["online_conservative"]["expected_seconds"],
        )

        strength = get_strength_label(
            password,
            entropy,
            leak_result,
            fastest_offline["assessment"]["offline_conservative"]["expected_seconds"],
        )

        table.add_row(
            str(index),
            mask_secret(password),
            f"{entropy} bits",
            strength,
            breach_text,
            fastest_offline["assessment"]["offline_conservative"]["expected"],
            fastest_online["assessment"]["online_conservative"]["expected"],
        )

        audit_results.append(
            (
                password,
                entropy,
                leak_result,
                nist_status,
                fastest_offline["scenario"],
                fastest_online["scenario"],
                fastest_offline["assessment"],
                fastest_online["assessment"],
                slowest_offline["scenario"],
                slowest_online["scenario"],
                format_duration(slowest_offline["assessment"]["offline_conservative"]["expected_seconds"]),
                format_duration(slowest_online["assessment"]["online_conservative"]["expected_seconds"]),
            )
        )

    console.print(table)

    (
        target,
        entropy,
        leak_result,
        nist_status,
        fastest_offline_scenario,
        fastest_online_scenario,
        fastest_offline_assessment,
        fastest_online_assessment,
        slowest_offline_scenario,
        slowest_online_scenario,
        slowest_offline_expected,
        slowest_online_expected,
    ) = audit_results[0]
    is_khmer = contains_khmer_dictionary_term(target, khmer_dict)
    verdict, explanations = get_expert_analysis(
        target,
        entropy,
        leak_result,
        is_khmer,
        hash_profile=fastest_offline_scenario["hash_profile"],
        attacker_profile=fastest_offline_scenario["attacker_profile"],
        online_defense=fastest_online_scenario["online_defense"],
    )
    explanations.append("[cyan]DETAILED VIEW (Primary Target):[/cyan]")
    explanations.append(
        f"NIST status: {nist_status} | Model driver: "
        f"{fastest_offline_assessment['model_driver']}"
    )
    explanations.append(
        "Offline all-scenario span: "
        f"{fastest_offline_assessment['offline_conservative']['expected']} to {slowest_offline_expected} "
        f"(fastest profile={fastest_offline_scenario['hash_profile']}/{fastest_offline_scenario['attacker_profile']}, "
        f"slowest profile={slowest_offline_scenario['hash_profile']}/{slowest_offline_scenario['attacker_profile']})"
    )
    explanations.append(
        "Online all-scenario span: "
        f"{fastest_online_assessment['online_conservative']['expected']} to {slowest_online_expected} "
        f"(fastest profile={fastest_online_scenario['online_defense']}, "
        f"slowest profile={slowest_online_scenario['online_defense']})"
    )

    analysis_panel = Panel(
        "\n".join(explanations),
        title=f"Security Explanation: [ {verdict} ]",
        subtitle="Baseline: NIST SP 800-63B | all profile combinations tested",
        border_style="green" if "SAFE" in verdict else "red",
        padding=(1, 2),
    )
    console.print(analysis_panel)

    console.print("\n[bold white]Security Scalability Projection[/bold white]")
    for step in range(1, 5):
        projected_entropy = entropy + (step * math.log2(95))
        bar = "#" * (step * 8)
        console.print(
            f"  [dim]+{step} char:[/dim] [blue]{bar}[/blue] "
            f"[white]Random Off (fastest profile): "
            f"{calculate_bruteforce_time(projected_entropy, get_offline_guesses_per_second(fastest_offline_scenario['hash_profile'], fastest_offline_scenario['attacker_profile']))} | "
            f"Random On (fastest profile): "
            f"{calculate_bruteforce_time(projected_entropy, get_online_guesses_per_second(fastest_online_scenario['online_defense']))}[/white]"
        )
