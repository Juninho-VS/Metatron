#!/usr/bin/env python3
"""
METATRON - tool_manager.py
Gerenciador inteligente de ferramentas para Arch Linux.
Regras estritas:
 1. Sempre verifica se a ferramenta necessária já está instalada.
 2. Prioriza prioritariamente ferramentas já existentes no ambiente.
 3. Evita instalar ferramentas com funcionalidades já cobertas por ferramentas existentes.
 4. Instala novas ferramentas apenas sob demanda quando estritamente necessárias.
 5. Utiliza EXCLUSIVAMENTE o gerenciador de pacotes pacman.
 6. NUNCA utiliza yay, paru ou outros AUR helpers.
 7. Registra toda instalação realizada no banco SQLite (tabela installed_tools).
"""

import os
import sys
import shutil
import subprocess
from typing import Dict, List, Optional, Tuple, Any

# Bootstrap: Garante acesso aos pacotes instalados no venv local (ex: reportlab)
_base_dir = os.path.dirname(os.path.abspath(__file__))
for _py_ver in ["python3.13", "python3.14"]:
    _venv_site = os.path.join(_base_dir, "venv", "lib", _py_ver, "site-packages")
    if os.path.exists(_venv_site) and _venv_site not in sys.path:
        sys.path.insert(0, _venv_site)

from db import upsert_tool, log_tool_installation, get_available_tools, get_installed_tools_log


# ─────────────────────────────────────────────
# CATÁLOGO DE FERRAMENTAS E CAPACIDADES NO ARCH LINUX
# ─────────────────────────────────────────────

# Mapeamento oficial de ferramentas conhecidas para pacotes do repositório oficial do Arch Linux
TOOL_CATALOG = {
    # Reconhecimento / DNS / Headers
    "curl": {
        "package": "curl",
        "category": "recon_web",
        "capabilities": ["http_request", "http_headers", "http_probe", "tls_check"],
        "check_cmd": ["curl", "--version"],
    },
    "dig": {
        "package": "bind",
        "category": "recon_dns",
        "capabilities": ["dns_lookup", "dns_any", "dns_mx", "dns_ns", "dns_txt", "dns_ptr"],
        "check_cmd": ["dig", "-v"],
    },
    "openssl": {
        "package": "openssl",
        "category": "recon_tls",
        "capabilities": ["tls_inspect", "ssl_cert", "cipher_check"],
        "check_cmd": ["openssl", "version"],
    },
    "whois": {
        "package": "whois",
        "category": "recon_osint",
        "capabilities": ["whois_lookup", "rdap_lookup"],
        "check_cmd": ["whois", "--version"],
    },
    # Enumeração e Rede
    "nmap": {
        "package": "nmap",
        "category": "enum_network",
        "capabilities": ["port_scan", "service_version", "os_fingerprint", "nse_scan"],
        "check_cmd": ["nmap", "--version"],
    },
    "ss": {
        "package": "iproute2",
        "category": "enum_system",
        "capabilities": ["local_socket_enum", "listening_ports"],
        "check_cmd": ["ss", "--version"],
    },
    "ip": {
        "package": "iproute2",
        "category": "enum_system",
        "capabilities": ["interface_enum", "routing_table"],
        "check_cmd": ["ip", "-V"],
    },
    "ping": {
        "package": "iputils",
        "category": "enum_network",
        "capabilities": ["icmp_echo", "host_alive"],
        "check_cmd": ["ping", "-V"],
    },
    "nikto": {
        "package": "nikto",
        "category": "web_vuln",
        "capabilities": ["web_server_misconfig", "dangerous_files"],
        "check_cmd": ["nikto", "-Version"],
    },
    "python3": {
        "package": "python",
        "category": "runtime",
        "capabilities": ["raw_socket_scan", "http_request", "banner_grab", "tls_inspect", "pdf_generation"],
        "check_cmd": ["python3", "--version"],
    },
    "sqlite3": {
        "package": "sqlite",
        "category": "persistence",
        "capabilities": ["sqlite_query", "db_persistence"],
        "check_cmd": ["sqlite3", "--version"],
    },
    "reportlab": {
        "package": "python-reportlab",
        "category": "reporting",
        "capabilities": ["pdf_generation"],
        "check_cmd": ["python3", "-c", "import reportlab"],
    }
}


def is_tool_installed(tool_name: str) -> Tuple[bool, Optional[str], str]:
    """
    Verifica se uma ferramenta está instalada no sistema.
    Retorna (is_installed, binary_path, version_string).
    """
    if tool_name == "reportlab":
        try:
            import reportlab
            return True, sys.executable, str(reportlab.__version__)
        except ImportError:
            pass
        return False, None, ""

    bin_path = shutil.which(tool_name)
    if not bin_path:
        return False, None, ""

    # Obtém versão da ferramenta
    tool_info = TOOL_CATALOG.get(tool_name)
    version_str = "instalado"
    if tool_info and "check_cmd" in tool_info:
        try:
            res = subprocess.run(tool_info["check_cmd"], capture_output=True, text=True, timeout=5)
            output = (res.stdout or res.stderr).strip().splitlines()
            if output:
                version_str = output[0][:80]
        except Exception:
            pass

    return True, bin_path, version_str


def scan_and_update_system_tools() -> Dict[str, Dict[str, Any]]:
    """
    Varre as ferramentas catalogadas no ambiente Arch Linux e
    atualiza o banco SQLite com o estado atual.
    """
    status_map = {}
    for tool_name, info in TOOL_CATALOG.items():
        installed, path, ver = is_tool_installed(tool_name)
        caps = ",".join(info["capabilities"])
        upsert_tool(
            tool_name=tool_name,
            binary_path=path,
            category=info["category"],
            capabilities=caps,
            is_installed=installed,
            version=ver
        )
        status_map[tool_name] = {
            "installed": installed,
            "path": path,
            "version": ver,
            "package": info["package"],
            "capabilities": info["capabilities"]
        }
    return status_map


def get_installed_tools_covering(capability: str) -> List[str]:
    """Retorna a lista de ferramentas instaladas que cobrem uma dada capacidade."""
    covering = []
    for tool_name, info in TOOL_CATALOG.items():
        if capability in info["capabilities"]:
            installed, _, _ = is_tool_installed(tool_name)
            if installed:
                covering.append(tool_name)
    return covering


def ensure_capability(capability: str, preferred_tool: Optional[str] = None) -> Tuple[bool, str]:
    """
    Garante que uma dada capacidade está disponível no ambiente.
    Regra de ouro:
    - Se uma ferramenta existente já cobre a capacidade, REUTILIZA sem instalar nada.
    - Apenas tenta instalar via pacman se NENHUMA ferramenta instalada puder cobrir a etapa.
    """
    # 1. Verifica se já temos ferramenta instalada cobrindo a capacidade
    installed_covering = get_installed_tools_covering(capability)
    if preferred_tool and preferred_tool in installed_covering:
        return True, f"Capacidade '{capability}' coberta pela ferramenta instalada: {preferred_tool}"
    if installed_covering:
        return True, f"Capacidade '{capability}' já coberta por ferramenta(s) existente(s): {', '.join(installed_covering)}"

    # 2. Se nenhuma ferramenta existente cobre, seleciona a ferramenta necessária
    target_tool = preferred_tool
    if not target_tool:
        for tool_name, info in TOOL_CATALOG.items():
            if capability in info["capabilities"]:
                target_tool = tool_name
                break

    if not target_tool or target_tool not in TOOL_CATALOG:
        return False, f"Nenhuma ferramenta catalogada para suprir a capacidade: {capability}"

    # 3. Instala EXCLUSIVAMENTE via pacman
    pkg = TOOL_CATALOG[target_tool]["package"]
    success, log_msg = install_tool_pacman(target_tool, pkg)
    return success, log_msg


def install_tool_pacman(tool_name: str, package_name: str) -> Tuple[bool, str]:
    """
    Instala um pacote EXCLUSIVAMENTE via pacman no Arch Linux.
    NÃO utiliza yay, paru nem outros AUR helpers.
    Registra o evento no banco SQLite (tabela installed_tools).
    """
    print(f"\n[PACMAN] Verificando pacote '{package_name}' para fornecer '{tool_name}'...")

    # Verifica se pacman está disponível
    pacman_bin = shutil.which("pacman")
    if not pacman_bin:
        err = "Erro crítico: gerenciador de pacotes pacman não encontrado no sistema."
        log_tool_installation(tool_name, package_name, "pacman", False, err)
        return False, err

    # Comando de instalação estrito: pacman -S --noconfirm <pkg>
    # Verifica se precisa de sudo
    is_root = (os.geteuid() == 0)
    cmd = ["pacman", "-S", "--noconfirm", "--needed", package_name]
    if not is_root:
        cmd = ["sudo", "-n", "pacman", "-S", "--noconfirm", "--needed", package_name]

    cmd_str = " ".join(cmd)
    print(f"[PACMAN] Executando: {cmd_str}")

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=180
        )
        output = (proc.stdout + "\n" + proc.stderr).strip()

        if proc.returncode == 0:
            msg = f"Pacote '{package_name}' instalado com sucesso via pacman."
            print(f"[PACMAN] [+] {msg}")
            log_tool_installation(tool_name, package_name, cmd_str, True, output)
            # Atualiza catálogo
            scan_and_update_system_tools()
            return True, msg
        else:
            msg = f"Falha na instalação de '{package_name}' via pacman (código {proc.returncode})."
            if "sudo" in cmd_str and ("password" in output.lower() or "privilégios" in output.lower()):
                msg += " Permissões de superusuário requeridas. Execute manualmente: sudo pacman -S --needed " + package_name
            print(f"[PACMAN] [!] {msg}\n{output}")
            log_tool_installation(tool_name, package_name, cmd_str, False, output)
            return False, msg

    except subprocess.TimeoutExpired:
        msg = f"Tempo limite excedido ao executar pacman para '{package_name}'."
        log_tool_installation(tool_name, package_name, cmd_str, False, msg)
        return False, msg
    except Exception as e:
        msg = f"Exceção ao tentar instalar '{package_name}': {e}"
        log_tool_installation(tool_name, package_name, cmd_str, False, msg)
        return False, msg


def run_command(cmd_list: List[str], timeout: int = 60) -> Tuple[int, str, str]:
    """
    Executa um comando seguro no sistema sem vulnerabilidades de shell injection.
    Retorna (returncode, stdout, stderr).
    """
    try:
        res = subprocess.run(
            cmd_list,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return res.returncode, res.stdout, res.stderr
    except subprocess.TimeoutExpired:
        return -1, "", f"[TIMEOUT] Comando excedeu tempo limite de {timeout}s: {' '.join(cmd_list)}"
    except FileNotFoundError:
        return -2, "", f"[NOT FOUND] Binário '{cmd_list[0]}' não encontrado no PATH."
    except Exception as e:
        return -3, "", f"[ERROR] Erro ao executar '{cmd_list[0]}': {e}"


# Inicializa o estado das ferramentas ao carregar
scan_and_update_system_tools()

if __name__ == "__main__":
    tools = scan_and_update_system_tools()
    print("=== CATÁLOGO DE FERRAMENTAS METATRON (ARCH LINUX) ===")
    for name, data in tools.items():
        status = "INSTALADO" if data["installed"] else "FALTANDO"
        print(f"[{status}] {name:<12} | Pacote: {data['package']:<15} | Caps: {', '.join(data['capabilities'][:3])}")
