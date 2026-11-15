#!/usr/bin/env python3
"""
METATRON - tools.py
Executores de ferramentas no Arch Linux para o METATRON.
Integração direta com tool_manager.py e persistência SQLite.
Utiliza prioritariamente ferramentas instaladas no sistema e pacman para novas instalações.
"""

import sys
import os
import shutil
import subprocess
from typing import Dict, Any, List

_base_dir = os.path.dirname(os.path.abspath(__file__))
if _base_dir not in sys.path:
    sys.path.insert(0, _base_dir)

from tool_manager import run_command, is_tool_installed, ensure_capability, install_tool_pacman


def run_tool(command: list, timeout: int = 120) -> str:
    """
    Executa comando com timeout e captura segura de saída.
    """
    bin_name = command[0]
    installed, _, _ = is_tool_installed(bin_name)
    if not installed:
        return f"[!] Ferramenta não encontrada: {bin_name} — instale no Arch Linux com: sudo pacman -S --needed {bin_name}"

    ret, stdout, stderr = run_command(command, timeout=timeout)
    output = stdout.strip()
    errors = stderr.strip()

    if output and errors:
        return output + "\n[STDERR]\n" + errors
    elif output:
        return output
    elif errors:
        return errors
    else:
        return "[!] Ferramenta executada sem retorno de texto."


def run_nmap(target: str) -> str:
    """Executa nmap se disponível, ou sugere instalação via pacman."""
    installed, _, _ = is_tool_installed("nmap")
    if not installed:
        return "[!] nmap não está instalado. Instale via pacman: sudo pacman -S --needed nmap"
    print(f"  [*] nmap -sV -sC -T4 --open {target}")
    return run_tool(["nmap", "-sV", "-sC", "-T4", "--open", target], timeout=180)


def run_whois(target: str) -> str:
    """Executa whois se disponível."""
    installed, _, _ = is_tool_installed("whois")
    if not installed:
        return "[!] whois não está instalado. Instale via pacman: sudo pacman -S --needed whois"
    print(f"  [*] whois {target}")
    return run_tool(["whois", target], timeout=30)


def run_curl_headers(target: str) -> str:
    """Executa curl -sI para inspeção de cabeçalhos HTTP/HTTPS."""
    print(f"  [*] curl -sI http://{target}")
    output = run_tool([
        "curl", "-sI", "--max-time", "10", "--location", f"http://{target}"
    ], timeout=20)

    https_output = run_tool([
        "curl", "-sI", "--max-time", "10", "--location", "-k", f"https://{target}"
    ], timeout=20)

    return f"[HTTP Headers]\n{output}\n\n[HTTPS Headers]\n{https_output}"


def run_dig(target: str) -> str:
    """Executa dig para consultas DNS detalhadas."""
    installed, _, _ = is_tool_installed("dig")
    if not installed:
        return "[!] dig não está instalado. Instale no Arch Linux com: sudo pacman -S --needed bind"
    print(f"  [*] dig {target} ANY")
    a_rec = run_tool(["dig", "+short", "A", target], timeout=10)
    mx_rec = run_tool(["dig", "+short", "MX", target], timeout=10)
    ns_rec = run_tool(["dig", "+short", "NS", target], timeout=10)
    txt_rec = run_tool(["dig", "+short", "TXT", target], timeout=10)

    return f"[A Records]\n{a_rec}\n\n[MX Records]\n{mx_rec}\n\n[NS Records]\n{ns_rec}\n\n[TXT Records]\n{txt_rec}"


def run_nikto(target: str) -> str:
    """Executa nikto se instalado."""
    installed, _, _ = is_tool_installed("nikto")
    if not installed:
        return "[!] nikto não está instalado. Instale via pacman: sudo pacman -S --needed nikto"
    print(f"  [*] nikto -h {target}")
    return run_tool(["nikto", "-h", target, "-nointeractive"], timeout=300)


def run_default_recon(target: str) -> dict:
    """Executa o pipeline padrão de reconhecimento com ferramentas disponíveis."""
    print(f"\n[*] Iniciando reconhecimento em: {target} (Arch Linux)")
    print("─" * 50)
    results = {
        "curl_headers": run_curl_headers(target),
        "dig": run_dig(target),
        "nmap": run_nmap(target),
        "whois": run_whois(target)
    }
    print("─" * 50)
    print("[+] Reconhecimento concluído.\n")
    return results


def format_recon_for_llm(results: dict) -> str:
    """Formata saídas de reconhecimento para texto legível."""
    output = ""
    for tool, data in results.items():
        output += f"\n{'='*50}\n[ {tool.upper()} OUTPUT ]\n{'='*50}\n"
        output += data.strip() + "\n"
    return output


def run_tool_by_command(command_str: str) -> str:
    """Executa comando permitido no sistema."""
    parts = command_str.strip().split()
    if not parts:
        return "[!] Comando vazio."
    allowed = {"nmap", "whois", "curl", "dig", "nikto", "ss", "ip", "ping"}
    binary = parts[0].lower().split("/")[-1]
    if binary not in allowed:
        return f"[!] Ferramenta '{binary}' não está na lista autorizada: {allowed}"
    return run_tool(parts)
