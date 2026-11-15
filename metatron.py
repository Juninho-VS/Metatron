#!/usr/bin/env python3
"""
METATRON - metatron.py
Ponto de entrada principal da CLI para Arch Linux.
Plataforma Autônoma de Auditoria de Segurança:
 - Persistência 100% local em SQLite (metatron.db)
 - Gerenciamento de ferramentas exclusivo com pacman
 - Operação Offline-first com cache local
 - Processo de auditoria em 7 fases rigorosas
 - Critério estrito de validação (sem hipóteses, apenas evidências)
 - Relatórios individuais em PDF (1 vulnerabilidade validada = 1 PDF independente)
"""

import os
import sys
import time
from datetime import datetime

# Bootstrap para imports locais
_base_dir = os.path.dirname(os.path.abspath(__file__))
if _base_dir not in sys.path:
    sys.path.insert(0, _base_dir)

from db import (
    get_connection, get_all_sessions, get_session, delete_full_session,
    get_all_vulnerabilities, get_vulnerability, get_available_tools,
    get_installed_tools_log, get_actions_for_session, edit_vulnerability,
    delete_vulnerability
)
from tool_manager import (
    scan_and_update_system_tools, is_tool_installed, install_tool_pacman,
    TOOL_CATALOG
)
from audit_engine import AuditEngine
from export import (
    export_vulnerability_pdf, export_all_vulnerabilities_for_session, export_menu
)
from llm import check_ollama_status


# ─────────────────────────────────────────────
# INTERFACE E CORES ANSI
# ─────────────────────────────────────────────

def clear():
    os.system("clear" if os.name == "posix" else "cls")


def banner():
    clear()
    online, model, _ = check_ollama_status()
    ai_status = f"\033[92mCONECTADO ({model})\033[0m" if online else "\033[93mDESCONECTADO (Modo Determinístico)\033[0m"

    print(f"""\033[91m
    ███╗   ███╗███████╗████████╗ █████╗ ████████╗██████╗  ██████╗ ███╗   ██╗
    ████╗ ████║██╔════╝╚══██╔══╝██╔══██╗╚══██╔══╝██╔══██╗██╔═══██╗████╗  ██║
    ██╔████╔██║█████╗     ██║   ███████║   ██║   ██████╔╝██║   ██║██╔██╗ ██║
    ██║╚██╔╝██║██╔══╝     ██║   ██╔══██║   ██║   ██╔══██╗██║   ██║██║╚██╗██║
    ██║ ╚═╝ ██║███████╗   ██║   ██║  ██║   ██║   ██║  ██║╚██████╔╝██║ ╚████║
    ╚═╝     ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝
\033[0m
    \033[96mPlataforma Autônoma de Auditoria\033[0m | \033[93mArch Linux (pacman)\033[0m | \033[92mSQLite 3\033[0m
    IA Local (Ollama): {ai_status}
    \033[90m─────────────────────────────────────────────────────────────────────────────\033[0m
""")


def divider(label: str = ""):
    if label:
        print(f"\n\033[33m{'─'*22} {label} {'─'*22}\033[0m")
    else:
        print(f"\033[90m{'─'*68}\033[0m")


def prompt(text: str) -> str:
    return input(f"\033[36m{text}\033[0m").strip()


def success(text: str):
    print(f"\033[92m[+] {text}\033[0m")


def warn(text: str):
    print(f"\033[93m[!] {text}\033[0m")


def error(text: str):
    print(f"\033[91m[✗] {text}\033[0m")


def info(text: str):
    print(f"\033[94m[*] {text}\033[0m")


def confirm(question: str) -> bool:
    ans = prompt(f"{question} [s/N]: ").lower()
    return ans in ["s", "sim", "y", "yes"]


# ─────────────────────────────────────────────
# 1. NOVA AUDITORIA (7 FASES)
# ─────────────────────────────────────────────

def new_audit():
    divider("NOVA AUDITORIA AUTÔNOMA DE SEGURANÇA")
    print("O processo de auditoria é executado em 7 fases rigorosas:")
    print("  1. Reconhecimento  2. Enumeração  3. Descoberta de Superfície")
    print("  4. Validação Estrita (sem hipóteses)  5. Coleta de Evidências (SHA-256)")
    print("  6. Classificação CVSS v3.1  7. Geração de Relatórios (1 Vuln = 1 PDF)")
    divider()

    target = prompt("[?] Digite o IP, domínio ou URL do alvo: ")
    if not target:
        warn("Nenhum alvo foi informado. Operação cancelada.")
        return

    # Pergunta sobre modo offline
    offline = True
    print("\nModo de Operação:")
    print("  [1] Offline-First (Priorizar cache e recursos locais) [Recomendado]")
    print("  [2] Online Completo (Permitir consultas externas irrestritas)")
    off_choice = prompt("Escolha [1/2]: ")
    if off_choice == "2":
        offline = False

    info(f"Inicializando motor de auditoria para o alvo: {target}")
    engine = AuditEngine(target=target, offline_first=offline)

    try:
        results = engine.run_full_audit()
        vulns = results.get("vulnerabilities", [])
        pdfs = results.get("pdf_reports", [])

        if vulns:
            divider("RESUMO DE VULNERABILIDADES VALIDADAS")
            for v in vulns:
                vid = v.get("id", "-")
                vtitle = v.get("title", "")
                vsev = v.get("calculated_severity", v.get("severity", "DESCONHECIDO"))
                vscore = v.get("calculated_score", v.get("cvss_score", 0.0))
                print(f"  \033[91m[#{vid}]\033[0m \033[93m[{vsev} - CVSS {vscore:.1f}]\033[0m {vtitle}")

            divider("RELATÓRIOS INDEPENDENTES GERADOS")
            success(f"{len(pdfs)} PDFs independentes foram gerados com sucesso na pasta 'reports/':")
            for pdf in pdfs:
                print(f"   📄 {pdf}")
        else:
            info("Nenhuma vulnerabilidade com evidência real foi confirmada no alvo.")

    except Exception as e:
        error(f"Erro durante a execução da auditoria: {e}")
        import traceback
        traceback.print_exc()


# ─────────────────────────────────────────────
# 2. HISTÓRICO DE SESSÕES & AUDITORIAS
# ─────────────────────────────────────────────

def view_history():
    divider("HISTÓRICO DE SESSÕES SALVAS NO SQLITE")
    sessions = get_all_sessions()
    if not sessions:
        warn("Nenhuma sessão registrada no banco SQLite ainda.")
        return

    print(f"{'SL#':<6} | {'ALVO':<28} | {'DATA INÍCIO':<19} | {'STATUS':<10} | {'RISCO':<10} | {'VULNS'}")
    divider()
    for s in sessions:
        sl = s["id"]
        tgt = (s["target"] or "")[:28]
        dt = (s["start_time"] or "")[:19]
        st = s["status"]
        rk = s["risk_level"] or "DESCONHECIDO"
        nv = s["total_vulns"]
        print(f"#{sl:<5} | {tgt:<28} | {dt:<19} | {st:<10} | {rk:<10} | {nv}")

    divider()
    sel = prompt("Digite o SL# da sessão para abrir detalhes (ou Enter para voltar): ")
    if not sel or not sel.isdigit():
        return

    session_id = int(sel)
    data = get_session(session_id)
    if not data or not data.get("session"):
        error(f"Sessão #{session_id} não encontrada.")
        return

    s = data["session"]
    vulns = data["vulnerabilities"]
    scans = data["scans"]
    actions = data["actions"]

    divider(f"DETALHES DA SESSÃO #{session_id} - {s['target']}")
    print(f"Alvo        : {s['target']}")
    print(f"Início      : {s['start_time']} | Término: {s['end_time'] or 'Em andamento'}")
    print(f"Risco Global: {s['risk_level']} | Total Vulns: {len(vulns)}")
    print(f"Sumário     : {s['summary'] or 'Nenhum'}")

    if vulns:
        print("\n\033[93m[ VULNERABILIDADES VALIDADAS ]\033[0m")
        for v in vulns:
            print(f"  • [#{v['id']}] [{v['severity']} | CVSS {v['cvss_score']:.1f}] {v['title']}")
            print(f"    Porta: {v['port']} | Vetor: {v['cvss_vector']}")

    if scans:
        print(f"\n\033[94m[ SCANS EXECUTADOS: {len(scans)} ]\033[0m")
        for sc in scans:
            print(f"  • [{sc['phase']}] Ferramenta: {sc['tool_name']} ({sc['status']}) - {sc['command']}")

    print("\nAções disponíveis:")
    print("  [1] Gerar PDFs individuais para todas as vulnerabilidades desta sessão")
    print("  [2] Selecionar uma vulnerabilidade para exportar PDF")
    print("  [3] Excluir permanentemente esta sessão")
    print("  [4] Voltar")

    act = prompt("Opção: ")
    if act == "1":
        pdfs = export_all_vulnerabilities_for_session(session_id)
        success(f"{len(pdfs)} PDFs gerados com sucesso na pasta 'reports/':")
        for p in pdfs:
            print(f"  • {p}")
    elif act == "2":
        export_menu(data)
    elif act == "3":
        if confirm(f"Tem certeza que deseja apagar a sessão #{session_id} e todos os seus dados?"):
            delete_full_session(session_id)
            success(f"Sessão #{session_id} removida do banco SQLite.")


# ─────────────────────────────────────────────
# 3. BASE DE DADOS DE VULNERABILIDADES
# ─────────────────────────────────────────────

def view_vulnerability_database():
    divider("BASE DE DADOS DE VULNERABILIDADES VALIDADAS (SQLITE)")
    all_vulns = get_all_vulnerabilities()
    if not all_vulns:
        warn("Nenhuma vulnerabilidade validada encontrada no banco de dados.")
        return

    print(f"{'ID':<5} | {'SEVERIDADE':<10} | {'CVSS':<5} | {'ALVO':<22} | {'TÍTULO'}")
    divider()
    for v in all_vulns:
        vid = v["id"]
        sev = v["severity"]
        score = v["cvss_score"]
        tgt = (v.get("session_target") or "")[:22]
        title = (v["title"] or "")[:40]
        print(f"#{vid:<4} | {sev:<10} | {score:<5.1f} | {tgt:<22} | {title}")

    divider()
    print("Opções:")
    print("  [1] Visualizar detalhes e evidências de uma vulnerabilidade")
    print("  [2] Exportar PDF independente de uma vulnerabilidade")
    print("  [3] Exportar PDFs de TODAS as vulnerabilidades listadas")
    print("  [4] Voltar")

    choice = prompt("Opção: ")
    if choice == "1":
        vid_str = prompt("Digite o ID da vulnerabilidade: ")
        if vid_str.isdigit():
            v = get_vulnerability(int(vid_str))
            if v:
                divider(f"VULNERABILIDADE #{v['id']} - {v['title']}")
                print(f"Severidade : {v['severity']} (CVSS {v['cvss_score']:.1f})")
                print(f"Vetor CVSS : {v['cvss_vector']}")
                print(f"Superfície : {v['attack_surface']} | Porta/Serviço: {v['port']}/{v['service']}")
                print(f"Data       : {v['discovery_date']}")
                print(f"\nDescrição:\n{v['description']}")
                print(f"\nPassos para Reprodução:\n{v['reproduction_steps']}")
                print(f"\nImpacto Técnico:\n{v['technical_impact']}")
                print(f"\nCorreção Recomendada:\n{v['remediation']}")
                print(f"\nHash SHA-256 da Evidência: {v.get('evidence_hash')}")
                if confirm("Deseja gerar o PDF independente desta vulnerabilidade agora?"):
                    pdf = export_vulnerability_pdf(v["id"])
                    success(f"PDF gerado com sucesso: {pdf}")
            else:
                error("Vulnerabilidade não encontrada.")
    elif choice == "2":
        vid_str = prompt("Digite o ID da vulnerabilidade a exportar: ")
        if vid_str.isdigit():
            try:
                pdf = export_vulnerability_pdf(int(vid_str))
                success(f"PDF gerado: {pdf}")
            except Exception as e:
                error(f"Erro ao gerar PDF: {e}")
    elif choice == "3":
        info("Gerando relatórios individuais para todas as vulnerabilidades...")
        count = 0
        for v in all_vulns:
            try:
                export_vulnerability_pdf(v["id"])
                count += 1
            except Exception as e:
                error(f"Falha ao gerar PDF para vuln #{v['id']}: {e}")
        success(f"{count} relatórios individuais gerados em 'reports/'.")


# ─────────────────────────────────────────────
# 4. GERENCIADOR DE FERRAMENTAS (ARCH LINUX / PACMAN)
# ─────────────────────────────────────────────

def tool_manager_menu():
    divider("GERENCIADOR DE FERRAMENTAS NO ARCH LINUX")
    print("Regras Operacionais:")
    print("  • Gerenciador exclusivo: pacman (sem yay / paru / AUR)")
    print("  • Prioridade: Reutilizar ferramentas já existentes no ambiente")
    print("  • Instalação sob demanda: Apenas quando estritamente necessário")
    print("  • Registro persistente em SQLite de todas as instalações")
    divider()

    tools = scan_and_update_system_tools()
    print(f"{'FERRAMENTA':<14} | {'STATUS':<12} | {'PACOTE PACMAN':<18} | {'CAPACIDADES'}")
    divider()
    for name, data in tools.items():
        st = "\033[92mINSTALADO\033[0m" if data["installed"] else "\033[91mFALTANDO\033[0m"
        pkg = data["package"]
        caps = ", ".join(data["capabilities"][:3])
        print(f"{name:<14} | {st:<21} | {pkg:<18} | {caps}")

    divider()
    print("Opções:")
    print("  [1] Instalar uma ferramenta faltante via pacman")
    print("  [2] Ver histórico de instalações dinâmicas registradas no SQLite")
    print("  [3] Re-escanear ferramentas do sistema")
    print("  [4] Voltar")

    choice = prompt("Opção: ")
    if choice == "1":
        name = prompt("Digite o nome da ferramenta a instalar (ex: nmap, whois, nikto): ").strip().lower()
        if name in TOOL_CATALOG:
            pkg = TOOL_CATALOG[name]["package"]
            if tools.get(name, {}).get("installed"):
                warn(f"A ferramenta '{name}' já está instalada no sistema.")
            else:
                info(f"Tentando instalar '{name}' (pacote '{pkg}') via pacman...")
                ok, log_msg = install_tool_pacman(name, pkg)
                if ok:
                    success(log_msg)
                else:
                    error(log_msg)
        else:
            error(f"Ferramenta '{name}' não catalogada. Ferramentas suportadas: {', '.join(TOOL_CATALOG.keys())}")
    elif choice == "2":
        logs = get_installed_tools_log()
        divider("HISTÓRICO DE INSTALAÇÕES VIA PACMAN (SQLITE)")
        if not logs:
            info("Nenhuma instalação dinâmica registrada no SQLite ainda.")
        else:
            for l in logs:
                res = "\033[92mSUCESSO\033[0m" if l["success"] else "\033[91mFALHA\033[0m"
                print(f"[{l['installed_at']}] Ferramenta: {l['tool_name']} ({l['package_name']}) | Status: {res}")
                print(f"  Comando: {l['pacman_cmd']}")
                if l["log_output"]:
                    print(f"  Log    : {l['log_output'][:100]}")


# ─────────────────────────────────────────────
# 5. MENU PRINCIPAL
# ─────────────────────────────────────────────

def main_menu():
    while True:
        banner()
        print("  \033[92m[1]\033[0m  Nova Auditoria Autônoma de Segurança (7 Fases & PDFs)")
        print("  \033[92m[2]\033[0m  Histórico de Sessões de Auditoria (SQLite)")
        print("  \033[92m[3]\033[0m  Base de Vulnerabilidades Validadas (Relatórios 1:1)")
        print("  \033[92m[4]\033[0m  Gerenciador de Ferramentas (Arch Linux / pacman)")
        print("  \033[92m[5]\033[0m  Sair")
        divider()

        choice = prompt("metatron> ")

        if choice == "1":
            new_audit()
            prompt("\nPressione Enter para continuar...")
        elif choice == "2":
            view_history()
            prompt("\nPressione Enter para continuar...")
        elif choice == "3":
            view_vulnerability_database()
            prompt("\nPressione Enter para continuar...")
        elif choice == "4":
            tool_manager_menu()
            prompt("\nPressione Enter para continuar...")
        elif choice == "5":
            print("\n\033[91m[*] Encerrando METATRON. Auditoria concluída com persistência segura.\033[0m\n")
            sys.exit(0)
        else:
            warn("Escolha inválida. Selecione uma opção válida de 1 a 5.")
            time.sleep(1)


if __name__ == "__main__":
    # Garante verificação do banco de dados na inicialização
    try:
        conn = get_connection()
        conn.close()
    except Exception as e:
        error(f"Falha crítica ao acessar banco SQLite metatron.db: {e}")
        sys.exit(1)

    main_menu()
