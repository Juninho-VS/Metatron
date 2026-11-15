#!/usr/bin/env python3
"""
METATRON - cvss.py
Calculador oficial e parser de pontuação CVSS v3.1 para o METATRON.
Converte vetores CVSS:3.1 e métricas base em pontuação numérica exata e severidade qualitativa.
"""

import math
from typing import Dict, Any, Tuple


def roundup(val: float) -> float:
    """Função roundup oficial da especificação CVSS v3.1."""
    int_val = round(val * 100000)
    if (int_val % 10000) == 0:
        return int_val / 100000.0
    else:
        return (math.floor(int_val / 10000) + 1) / 10.0


def score_to_severity(score: float) -> str:
    """Classificação qualitativa CVSS v3.1 em português."""
    if score == 0.0:
        return "INFORMATIVA"
    elif 0.1 <= score <= 3.9:
        return "BAIXA"
    elif 4.0 <= score <= 6.9:
        return "MÉDIA"
    elif 7.0 <= score <= 8.9:
        return "ALTA"
    elif 9.0 <= score <= 10.0:
        return "CRÍTICA"
    return "DESCONHECIDO"


def calculate_cvss31(
    av: str = "N",
    ac: str = "L",
    pr: str = "N",
    ui: str = "N",
    scope: str = "U",
    c: str = "N",
    i: str = "N",
    a: str = "N"
) -> Tuple[float, str, str]:
    """
    Calcula pontuação Base CVSS v3.1.
    Retorna (score, vector_string, qualitative_severity).
    """
    av_map = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
    ac_map = {"L": 0.77, "H": 0.44}
    ui_map = {"N": 0.85, "R": 0.62}

    if scope == "U":
        pr_map = {"N": 0.85, "L": 0.62, "H": 0.27}
    else:
        pr_map = {"N": 0.85, "L": 0.68, "H": 0.50}

    cia_map = {"N": 0.0, "L": 0.22, "H": 0.56}

    av_val = av_map.get(av.upper(), 0.85)
    ac_val = ac_map.get(ac.upper(), 0.77)
    ui_val = ui_map.get(ui.upper(), 0.85)
    pr_val = pr_map.get(pr.upper(), 0.85)

    c_val = cia_map.get(c.upper(), 0.0)
    i_val = cia_map.get(i.upper(), 0.0)
    a_val = cia_map.get(a.upper(), 0.0)

    # Impact Sub-Score
    iss = 1.0 - ((1.0 - c_val) * (1.0 - i_val) * (1.0 - a_val))

    if scope.upper() == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

    # Exploitability
    exploitability = 8.22 * av_val * ac_val * pr_val * ui_val

    if impact <= 0:
        base_score = 0.0
    else:
        if scope.upper() == "U":
            base_score = min(impact + exploitability, 10.0)
        else:
            base_score = min(1.08 * (impact + exploitability), 10.0)
        base_score = roundup(base_score)

    vector_str = f"CVSS:3.1/AV:{av.upper()}/AC:{ac.upper()}/PR:{pr.upper()}/UI:{ui.upper()}/S:{scope.upper()}/C:{c.upper()}/I:{i.upper()}/A:{a.upper()}"
    severity = score_to_severity(base_score)
    return base_score, vector_str, severity


def parse_cvss_vector(vector: str) -> Dict[str, Any]:
    """Converte string de vetor CVSS v3.1 para dict de métricas e calcula a nota."""
    cleaned = vector.strip().replace("CVSS:3.1/", "")
    parts = cleaned.split("/")
    metrics = {
        "AV": "N", "AC": "L", "PR": "N", "UI": "N",
        "S": "U", "C": "N", "I": "N", "A": "N"
    }
    for p in parts:
        if ":" in p:
            k, v = p.split(":", 1)
            metrics[k.upper()] = v.upper()

    score, vec, sev = calculate_cvss31(
        av=metrics["AV"], ac=metrics["AC"], pr=metrics["PR"],
        ui=metrics["UI"], scope=metrics["S"],
        c=metrics["C"], i=metrics["I"], a=metrics["A"]
    )

    names = {
        "AV": {"N": "Rede (Network)", "A": "Adjacente", "L": "Local", "P": "Físico"},
        "AC": {"L": "Baixa (Low)", "H": "Alta (High)"},
        "PR": {"N": "Nenhum (None)", "L": "Baixo (Low)", "H": "Alto (High)"},
        "UI": {"N": "Nenhuma (None)", "R": "Requerida (Required)"},
        "S": {"U": "Não Modificado (Unchanged)", "C": "Modificado (Changed)"},
        "C": {"N": "Nenhum (None)", "L": "Baixo (Low)", "H": "Alto (High)"},
        "I": {"N": "Nenhum (None)", "L": "Baixo (Low)", "H": "Alto (High)"},
        "A": {"N": "Nenhum (None)", "L": "Baixo (Low)", "H": "Alto (High)"},
    }

    detailed_metrics = {}
    for k, v in metrics.items():
        detailed_metrics[k] = {
            "code": v,
            "label": names.get(k, {}).get(v, v)
        }

    return {
        "score": score,
        "vector": vec,
        "severity": sev,
        "metrics": detailed_metrics
    }


if __name__ == "__main__":
    test_vec = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    res = parse_cvss_vector(test_vec)
    print(f"Vector: {res['vector']}")
    print(f"Score: {res['score']} | Severity: {res['severity']}")
