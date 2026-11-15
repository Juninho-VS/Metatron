#!/usr/bin/env python3
"""
METATRON - audit_engine.py
Motor autônomo de auditoria de segurança em 7 fases para Arch Linux.
Processo rigoroso:
  1. Reconhecimento
  2. Enumeração
  3. Descoberta de superfícies de ataque
  4. Validação de vulnerabilidades (sem hipóteses, apenas achados confirmados)
  5. Coleta de evidências (com hashes criptográficos SHA-256)
  6. Classificação de severidade (CVSS v3.1 exato)
  7. Geração de relatórios (1 vulnerabilidade validada = 1 PDF independente)
"""

import os
import sys
import time
import socket
import ssl
import json
import urllib.parse
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple

# Bootstrap para módulos do METATRON
_base_dir = os.path.dirname(os.path.abspath(__file__))
if _base_dir not in sys.path:
    sys.path.insert(0, _base_dir)

from db import (
    create_session, finish_session, save_memory, get_memory,
    save_scan_result, save_evidence, save_vulnerability,
    log_action, finish_action, cache_get, cache_put
)
from tool_manager import (
    is_tool_installed, ensure_capability, run_command, scan_and_update_system_tools
)
from cvss import calculate_cvss31, parse_cvss_vector
from export import export_all_vulnerabilities_for_session
from llm import (
    check_ollama_status, enrich_vulnerability_with_llm, generate_executive_summary_llm
)


# ─────────────────────────────────────────────
# CONFIGURAÇÃO DE AUDITORIA E CONSTANTES
# ─────────────────────────────────────────────

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 139, 143, 443, 445,
    993, 995, 1433, 1521, 2049, 3306, 3389, 5432, 5900,
    6379, 8000, 8080, 8443, 8888, 9200, 27017
]

PORT_SERVICE_MAP = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPC", 139: "NetBIOS", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "Oracle", 2049: "NFS", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
    8000: "HTTP-Alt", 8080: "HTTP-Proxy/Tomcat", 8443: "HTTPS-Alt",
    8888: "HTTP-Alt", 9200: "Elasticsearch", 27017: "MongoDB"
}

SENSITIVE_PATHS = [
    "/.git/HEAD",
    "/.env",
    "/robots.txt",
    "/server-status",
    "/phpinfo.php",
    "/.well-known/security.txt",
    "/swagger.json",
    "/api/v1",
]


class AuditEngine:
    """Motor de orquestração do ciclo de auditoria de segurança autônomo."""

    def __init__(self, target: str, session_id: Optional[int] = None, offline_first: bool = True):
        self.raw_target = target.strip()
        self.offline_first = offline_first
        
        target_info = self._normalize_target(self.raw_target)
        self.host = target_info["host"]
        self.port = target_info["port"]
        self.scheme = target_info["scheme"]
        self.path = target_info["path"]
        self.query = target_info["query"]
        self.has_query = target_info["has_query"]
        self.base_origin = target_info["base_origin"]
        self.target_url = target_info["full_url"]
        self.page_body = ""
        self.page_headers = ""
        self.page_status = ""

        self.session_id = session_id or create_session(
            target=self.raw_target,
            metadata={
                "host": self.host, "port": self.port, "scheme": self.scheme,
                "path": self.path, "query": self.query, "has_query": self.has_query,
                "target_url": self.target_url, "offline_first": offline_first
            }
        )
        self.open_ports: List[Dict[str, Any]] = []
        self.recon_data: Dict[str, Any] = {}
        self.validated_vulns: List[Dict[str, Any]] = []
        self.generated_pdfs: List[str] = []

        # Detecção automática de IA local via Ollama
        self.llm_online, self.llm_model, self.llm_models = check_ollama_status()
        if self.llm_online:
            self.log("IA Local", f"Ollama CONECTADO! Modelo ativo: {self.llm_model} ({len(self.llm_models)} disponíveis)", "SUCCESS")
        else:
            self.log("IA Local", "Ollama desconectado. Modo determinístico ativo (instale com 'sudo pacman -S ollama').", "INFO")

    def _normalize_target(self, target: str) -> Dict[str, Any]:
        """Normaliza alvo, preservando host, porta, protocolo, caminho e parâmetros (query string)."""
        target_clean = target.strip()
        if "://" not in target_clean:
            if target_clean.startswith("localhost") or target_clean.startswith("127.0.0.1"):
                target_clean = f"http://{target_clean}"
            else:
                target_clean = f"https://{target_clean}"

        parsed = urllib.parse.urlparse(target_clean)
        scheme = parsed.scheme or "http"
        host = parsed.hostname or (parsed.netloc.split(":")[0] if parsed.netloc else target_clean)
        port = parsed.port or (443 if scheme == "https" else 80)
        path = parsed.path if parsed.path else "/"
        query = parsed.query or ""
        has_query = bool(query)

        port_suffix = f":{port}" if (scheme == "http" and port != 80) or (scheme == "https" and port != 443) else ""
        base_origin = f"{scheme}://{host}{port_suffix}"
        full_url = f"{base_origin}{path}"
        if query:
            full_url += f"?{query}"

        return {
            "host": host,
            "port": port,
            "scheme": scheme,
            "path": path,
            "query": query,
            "has_query": has_query,
            "base_origin": base_origin,
            "full_url": full_url
        }

    def log(self, phase: str, message: str, level: str = "INFO"):
        """Exibe log formatado com cores no terminal e salva na memória de execução."""
        color = "\033[94m"  # azul
        if level == "SUCCESS":
            color = "\033[92m"  # verde
        elif level == "WARN":
            color = "\033[93m"  # amarelo
        elif level == "CRITICAL":
            color = "\033[91m"  # vermelho

        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"{color}[{timestamp}] [{phase.upper()}] {message}\033[0m")
        save_memory(self.session_id, f"log_{time.time()}", f"[{phase}] {message}", category="audit_log")

    # ─────────────────────────────────────────────
    # FASE 1: RECONHECIMENTO (RECONNAISSANCE)
    # ─────────────────────────────────────────────
    def phase_1_reconnaissance(self) -> Dict[str, Any]:
        """
        Fase 1: Reconhecimento passivo e ativo de baixo ruído.
        Executa consultas DNS, resolução de endereços, inspeção de certificados TLS.
        """
        phase_name = "Reconhecimento"
        act_id = log_action(self.session_id, phase_name, "DNS_and_Host_Resolution", self.host, "dig / socket", "running")
        self.log(phase_name, f"Iniciando reconhecimento do alvo: {self.host}")

        recon = {
            "host": self.host,
            "ip_addresses": [],
            "dns_records": {},
            "tls_certificate": None,
            "http_headers": None
        }

        # 1. Resolução de IP via socket local (offline-friendly)
        try:
            addr_info = socket.getaddrinfo(self.host, None)
            ips = list(set([a[4][0] for a in addr_info if a[4]]))
            recon["ip_addresses"] = ips
            self.log(phase_name, f"Endereços IP resolvidos: {', '.join(ips)}", "SUCCESS")
        except Exception as e:
            self.log(phase_name, f"Falha na resolução local de IP para '{self.host}': {e}", "WARN")

        # 2. Consulta DNS detalhada via 'dig' (se instalado) ou cache offline
        cache_key = f"dns_{self.host}"
        cached_dns = cache_get(cache_key) if self.offline_first else None

        if cached_dns:
            self.log(phase_name, "Utilizando registros DNS persistidos no cache offline.")
            recon["dns_records"] = json.loads(cached_dns)
        else:
            has_dig, dig_path, _ = is_tool_installed("dig")
            if has_dig:
                dns_out = {}
                for rtype in ["A", "MX", "NS", "TXT"]:
                    ret, out, _ = run_command(["dig", "+short", rtype, self.host], timeout=10)
                    if ret == 0 and out.strip():
                        dns_out[rtype] = out.strip().splitlines()
                recon["dns_records"] = dns_out
                cache_put(cache_key, "dns_records", dns_out)
                save_scan_result(self.session_id, phase_name, "dig", self.host, f"dig +short ANY {self.host}", json.dumps(dns_out))

        # 3. Inspeção de Certificado TLS (Porta 443 ou especificada)
        check_port = self.port if self.port else 443
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((self.host, check_port), timeout=4) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.host) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    cipher = ssock.cipher()
                    proto = ssock.version()
                    recon["tls_certificate"] = {
                        "protocol": proto,
                        "cipher": cipher,
                        "subject": cert.get("subject") if cert else None,
                        "issuer": cert.get("issuer") if cert else None,
                        "expires": cert.get("notAfter") if cert else None,
                    }
                    self.log(phase_name, f"Certificado TLS detectado ({proto} | {cipher[0] if cipher else 'N/A'})", "SUCCESS")
        except Exception:
            # Não suporta TLS ou porta fechada
            pass

        finish_action(act_id, "completed", f"Reconhecimento concluído. IPs: {len(recon['ip_addresses'])}")
        self.recon_data = recon
        save_memory(self.session_id, "recon_data", recon, category="recon")
        return recon

    # ─────────────────────────────────────────────
    # FASE 2: ENUMERAÇÃO (ENUMERATION)
    # ─────────────────────────────────────────────
    def phase_2_enumeration(self) -> List[Dict[str, Any]]:
        """
        Fase 2: Enumeração ativa de portas, serviços, banners e rotas web.
        Prioriza socket scanning nativo em Python ou ferramentas já instaladas no Arch.
        """
        phase_name = "Enumeração"
        act_id = log_action(self.session_id, phase_name, "Port_and_Service_Scan", self.host, "socket_scan", "running")
        self.log(phase_name, f"Enumerando portas e serviços no alvo: {self.host}")

        ports_to_test = [self.port] if self.port else COMMON_PORTS
        open_ports = []

        # Varredura de portas via socket nativo (rápido, determinístico e offline)
        for p in ports_to_test:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.7)
                res = s.connect_ex((self.host, p))
                if res == 0:
                    banner = ""
                    # Tenta capturar banner de boas-vindas
                    try:
                        s.settimeout(1.0)
                        if p in [80, 8080, 8000]:
                            s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                        banner_bytes = s.recv(1024)
                        banner = banner_bytes.decode("utf-8", errors="replace").strip()
                    except Exception:
                        pass

                    service_guess = PORT_SERVICE_MAP.get(p, "desconhecido")
                    open_ports.append({
                        "port": p,
                        "service": service_guess,
                        "banner": banner[:200]
                    })
                    self.log(phase_name, f"Porta ABERTA encontrada: {p} ({service_guess})", "SUCCESS")
                s.close()
            except Exception:
                pass

        # Enumeração Web se portas 80/443/8080 estiverem abertas
        web_ports = [p["port"] for p in open_ports if p["port"] in [80, 443, 8080, 8000, 8443]]
        if not web_ports and (self.scheme in ["http", "https"]):
            # Se nenhuma porta foi aberta mas foi passado URL, testa a porta do scheme
            web_ports = [443 if self.scheme == "https" else 80]

        web_findings = []
        has_curl, _, _ = is_tool_installed("curl")

        # 1. Se o usuário forneceu uma URL específica com parâmetros ou rota, inspeciona o endpoint alvo diretamente
        if self.has_query or self.path != "/":
            self.log(phase_name, f"Inspecionando endpoint específico da aplicação: {self.target_url}", "INFO")
            if has_curl:
                # Captura cabeçalhos seguindo redirects
                cmd_hdr = ["curl", "-sI", "-L", "-k", "--max-time", "10", self.target_url]
                ret_h, out_h, _ = run_command(cmd_hdr, timeout=12)
                if ret_h == 0 and out_h.strip():
                    self.page_headers = out_h.strip()
                    lines = self.page_headers.splitlines()
                    self.page_status = lines[0] if lines else ""

                # Captura corpo da resposta da URL para análise semântica
                cmd_body = ["curl", "-s", "-L", "-k", "--max-time", "10", self.target_url]
                ret_b, out_b, _ = run_command(cmd_body, timeout=12)
                if ret_b == 0 and out_b:
                    self.page_body = out_b[:40000]
                    self.log(phase_name, f"Conteúdo da aplicação recebido ({len(out_b)} bytes, status: {self.page_status})", "SUCCESS")
                
                web_findings.append({
                    "url": self.target_url,
                    "path": f"{self.path}?{self.query}" if self.query else self.path,
                    "port": self.port,
                    "status": self.page_status or "HTTP/1.1 200 OK",
                    "headers": self.page_headers,
                    "has_parameters": self.has_query
                })
        else:
            # 2. Se for alvo raiz/domínio genérico sem parâmetros, realiza varredura padrão de arquivos conhecidos
            self.log(phase_name, "Alvo sem parâmetros dinâmicos. Executando varredura ampla de caminhos conhecidos...", "INFO")
            for wp in web_ports:
                wp_scheme = "https" if wp in [443, 8443] else "http"
                base_origin_url = f"{wp_scheme}://{self.host}:{wp}" if (wp not in [80, 443]) else f"{wp_scheme}://{self.host}"

                for path in SENSITIVE_PATHS:
                    check_url = f"{base_origin_url}{path}"
                    if has_curl:
                        cmd = ["curl", "-sI", "-k", "--max-time", "5", check_url]
                        ret, out, err = run_command(cmd, timeout=8)
                        if ret == 0 and out.strip():
                            status_line = out.splitlines()[0] if out.splitlines() else ""
                            if "200" in status_line or "301" in status_line or "302" in status_line or "403" in status_line:
                                web_findings.append({
                                    "url": check_url,
                                    "path": path,
                                    "port": wp,
                                    "status": status_line,
                                    "headers": out.strip(),
                                    "has_parameters": False
                                })
                                self.log(phase_name, f"Endpoint detectado: {path} -> {status_line}", "INFO")

        scan_summary = {
            "open_ports": open_ports,
            "web_endpoints": web_findings
        }
        save_scan_result(
            self.session_id, phase_name, "metatron_enum", self.host,
            f"port_scan {self.host}", json.dumps(scan_summary, ensure_ascii=False)
        )
        finish_action(act_id, "completed", f"Portas abertas: {len(open_ports)} | Endpoints: {len(web_findings)}")
        self.open_ports = open_ports
        save_memory(self.session_id, "open_ports", open_ports, category="enum")
        save_memory(self.session_id, "web_findings", web_findings, category="enum")
        return open_ports

    # ─────────────────────────────────────────────
    # FASE 3: DESCOBERTA DE SUPERFÍCIES DE ATAQUE
    # ─────────────────────────────────────────────
    def phase_3_attack_surface_discovery(self) -> List[Dict[str, Any]]:
        """
        Fase 3: Identifica superfícies potenciais baseadas nos dados enumerados.
        Gera hipóteses que DEVERÃO ser estritamente validadas na Fase 4.
        """
        phase_name = "Superfície de Ataque"
        act_id = log_action(self.session_id, phase_name, "Analyze_Attack_Surfaces", self.host, "analyzer", "running")
        self.log(phase_name, "Analisando ativos enumerados para mapear superfícies de ataque...")

        candidate_surfaces = []
        web_findings = json.loads(get_memory(self.session_id, "web_findings") or "[]")

        # 1. Se o alvo possui rota ou query string específica (?param=val), mapeia superfícies da URL informada
        if self.has_query:
            candidate_surfaces.append({
                "type": "QUERY_PARAMETER_ANALYSIS",
                "surface": f"Parâmetro Dinâmico de Aplicação: ?{self.query}",
                "port": self.port,
                "service": self.scheme.upper(),
                "url": self.target_url,
                "query": self.query
            })
            candidate_surfaces.append({
                "type": "CACHE_CONTROL_PARAMETER",
                "surface": f"Política de Cache em URL Parametrizada: {self.target_url}",
                "port": self.port,
                "service": self.scheme.upper(),
                "url": self.target_url
            })

        # 2. Superfície: Headers HTTP e Configuração de Servidor Web no Endpoint
        has_web = any(p["port"] in [80, 443, 8080, 8000, 8443] for p in self.open_ports) or (len(web_findings) > 0)
        if has_web or self.raw_target:
            candidate_surfaces.append({
                "type": "HTTP_SECURITY_HEADERS",
                "surface": f"Cabeçalhos de Segurança HTTP no Endpoint: {self.target_url}",
                "port": self.port or (443 if self.scheme == "https" else 80),
                "service": self.scheme.upper(),
            })
            candidate_surfaces.append({
                "type": "HTTP_METHODS",
                "surface": f"Métodos HTTP Perigosos (TRACE / TRACK / OPTIONS) em {self.target_url}",
                "port": self.port or (443 if self.scheme == "https" else 80),
                "service": self.scheme.upper(),
            })
            candidate_surfaces.append({
                "type": "SERVER_INFO_LEAKAGE",
                "surface": f"Vazamento de Informações de Versão do Servidor em {self.target_url}",
                "port": self.port or (443 if self.scheme == "https" else 80),
                "service": self.scheme.upper(),
            })

        # 2. Superfície: Arquivos e Endpoints Sensíveis
        for wf in web_findings:
            if "200" in wf["status"] and wf["path"] in ["/.git/HEAD", "/.env", "/phpinfo.php", "/server-status"]:
                candidate_surfaces.append({
                    "type": "SENSITIVE_FILE_EXPOSURE",
                    "surface": f"Exposição de Arquivo Sensível: {wf['path']}",
                    "port": wf["port"],
                    "service": "HTTP/HTTPS",
                    "path": wf["path"],
                    "url": wf["url"]
                })

        # 3. Superfície: Portas e Serviços em Texto Claro
        for op in self.open_ports:
            if op["port"] in [21, 23]:
                candidate_surfaces.append({
                    "type": "CLEARTEXT_PROTOCOL",
                    "surface": f"Protocolo Não Criptografado ({op['service']}) na Porta {op['port']}",
                    "port": op["port"],
                    "service": op["service"]
                })
            elif op["port"] in [6379, 9200, 27017]:
                candidate_surfaces.append({
                    "type": "UNAUTHENTICATED_SERVICE",
                    "surface": f"Serviço de Banco/Cache Exposto ({op['service']}) na Porta {op['port']}",
                    "port": op["port"],
                    "service": op["service"]
                })

        finish_action(act_id, "completed", f"Superfícies mapeadas: {len(candidate_surfaces)}")
        self.log(phase_name, f"Total de superfícies identificadas para validação: {len(candidate_surfaces)}", "SUCCESS")
        save_memory(self.session_id, "candidate_surfaces", candidate_surfaces, category="surface")
        return candidate_surfaces

    # ─────────────────────────────────────────────
    # FASE 4: VALIDAÇÃO DE VULNERABILIDADES (STRICT)
    # ─────────────────────────────────────────────
    def phase_4_vulnerability_validation(self) -> List[Dict[str, Any]]:
        """
        Fase 4: Validação rigorosa e reproduzível das superfícies de ataque.
        CRITÉRIO ESTRITO:
          - Não registrar hipóteses sem evidência.
          - Não registrar potenciais vulnerabilidades sem validação.
          - Priorizar achados reproduzíveis com logs de suporte.
        """
        phase_name = "Validação de Vulns"
        act_id = log_action(self.session_id, phase_name, "Execute_Strict_Validation", self.host, "active_probe", "running")
        self.log(phase_name, "Iniciando bateria de validação estrita. Hipóteses sem prova serão descartadas...")

        candidate_surfaces = json.loads(get_memory(self.session_id, "candidate_surfaces") or "[]")
        validated_findings = []

        base_url = f"{self.scheme}://{self.host}"
        if self.port and self.port not in [80, 443]:
            base_url = f"{self.scheme}://{self.host}:{self.port}"

        # Utiliza o endpoint completo com rota e parâmetros se fornecido pelo usuário
        eval_url = self.target_url if (self.has_query or self.path != "/") else base_url
        self.log(phase_name, f"Executando validação de cabeçalhos e segurança no endpoint: {eval_url}", "INFO")

        # ── Teste 1: Validação de Cabeçalhos HTTP de Segurança ──
        headers_probe_cmd = ["curl", "-sI", "-L", "-k", "--max-time", "10", eval_url]
        ret, headers_out, err = run_command(headers_probe_cmd, timeout=12)

        if ret == 0 and headers_out.strip():
            headers_lower = headers_out.lower()
            resp_lines = headers_out.splitlines()
            status_line = resp_lines[0] if resp_lines else ""

            # Validação 1.1: Ausência de HSTS (Strict-Transport-Security) em HTTPS
            if self.scheme == "https" or any(p["port"] in [443, 8443] for p in self.open_ports):
                if "strict-transport-security" not in headers_lower:
                    validated_findings.append({
                        "title": "Ausência do Cabeçalho HTTP Strict-Transport-Security (HSTS)",
                        "severity_suggestion": "MÉDIA",
                        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:L/A:N",
                        "port": str(self.port or 443),
                        "service": "HTTPS",
                        "attack_surface": f"Camada de Transporte / Endpoint: {eval_url}",
                        "description": (
                            f"O endpoint '{eval_url}' responde a conexões HTTPS sem emitir o cabeçalho 'Strict-Transport-Security' (HSTS). "
                            "Isso permite que invasores em redes compartilhadas realizem ataques de downgrade de SSL/TLS (SSL Stripping), "
                            "forçando a vítima a comunicar-se via HTTP em texto claro e capturando parâmetros sensíveis ou cookies de sessão."
                        ),
                        "reproduction_steps": (
                            f"1. Execute a requisição com curl inspecionando os cabeçalhos de resposta no endpoint:\n"
                            f"   curl -sI -L -k \"{eval_url}\"\n"
                            f"2. Verifique a ausência do cabeçalho 'Strict-Transport-Security' nas linhas retornadas pelo servidor.\n"
                            f"3. Confirme que conexões subsequentes podem sofrer downgrade para HTTP inseguro."
                        ),
                        "technical_impact": (
                            "Comprometimento da confidencialidade e integridade do tráfego. Ataques Man-in-the-Middle podem interceptar "
                            "tokens de autenticação e credenciais transmitidas pelo usuário final sem que o navegador emita alertas."
                        ),
                        "remediation": (
                            "Habilitar o cabeçalho HSTS no servidor web com tempo de expiração de pelo menos 1 ano (31536000 segundos) e incluir subdomínios:\n"
                            "- Nginx: add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\" always;\n"
                            "- Apache: Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\"\n"
                            "- Caddy: header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\""
                        ),
                        "tools_used": "curl (Arch Linux pacman: curl)",
                        "evidence_type": "HTTP_RESPONSE_HEADERS",
                        "command_executed": " ".join(headers_probe_cmd),
                        "raw_evidence": f"[COMANDO]\n{' '.join(headers_probe_cmd)}\n\n[RESPOSTA RECEBIDA]\n{headers_out.strip()}"
                    })
                    self.log(phase_name, "VALIDADO: Ausência de HSTS confirmada no endpoint.", "CRITICAL")

            # Validação 1.2: Ausência de X-Frame-Options e frame-ancestors (Clickjacking)
            if ("x-frame-options" not in headers_lower) and ("frame-ancestors" not in headers_lower):
                validated_findings.append({
                    "title": "Vulnerabilidade de Clickjacking devido à Ausência de Proteção contra Framing (X-Frame-Options / CSP)",
                    "severity_suggestion": "MÉDIA",
                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
                    "port": str(self.port or (443 if self.scheme == "https" else 80)),
                    "service": self.scheme.upper(),
                    "attack_surface": f"Proteção do Navegador / Framing UI em: {eval_url}",
                    "description": (
                        f"O endpoint '{eval_url}' não define o cabeçalho 'X-Frame-Options' nem a diretiva 'frame-ancestors' no 'Content-Security-Policy'. "
                        "Essa omissão permite que a página e suas ações sejam renderizadas dentro de um elemento <iframe> em páginas de terceiros, viabilizando ataques de "
                        "Clickjacking (UI Redressing) nos quais o usuário é induzido a interagir com controles da aplicação sem consentimento."
                    ),
                    "reproduction_steps": (
                        f"1. Consulte os cabeçalhos de resposta HTTP da aplicação no endpoint:\n"
                        f"   curl -sI -L -k \"{eval_url}\"\n"
                        f"2. Confirme a ausência de 'X-Frame-Options' e 'Content-Security-Policy: frame-ancestors'.\n"
                        f"3. Crie um arquivo HTML local de teste contendo:\n"
                        f"   <iframe src=\"{eval_url}\" width=\"800\" height=\"600\"></iframe>\n"
                        f"4. Abra no navegador e comprove que a página é embutida com sucesso."
                    ),
                    "technical_impact": (
                        "Permite a condução de ações não autorizadas em nome do usuário autenticado através de camadas visuais transparentes sobrepostas."
                    ),
                    "remediation": (
                        "Adicionar o cabeçalho de proteção contra emolduramento:\n"
                        "- Nginx: add_header X-Frame-Options \"DENY\" always;\n"
                        "  add_header Content-Security-Policy \"frame-ancestors 'none';\" always;\n"
                        "- Apache: Header always set X-Frame-Options \"DENY\"\n"
                        "  Header always set Content-Security-Policy \"frame-ancestors 'none';\""
                    ),
                    "tools_used": "curl (Arch Linux pacman: curl)",
                    "evidence_type": "HTTP_RESPONSE_HEADERS",
                    "command_executed": " ".join(headers_probe_cmd),
                    "raw_evidence": f"[COMANDO]\n{' '.join(headers_probe_cmd)}\n\n[RESPOSTA RECEBIDA]\n{headers_out.strip()}"
                })
                self.log(phase_name, "VALIDADO: Ausência de proteção contra Clickjacking comprovada.", "CRITICAL")

            # Validação 1.3: Ausência de X-Content-Type-Options: nosniff
            if "x-content-type-options" not in headers_lower:
                validated_findings.append({
                    "title": "Ausência do Cabeçalho de Proteção MIME Sniffing (X-Content-Type-Options)",
                    "severity_suggestion": "BAIXA",
                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
                    "port": str(self.port or (443 if self.scheme == "https" else 80)),
                    "service": self.scheme.upper(),
                    "attack_surface": f"Proteção do Navegador / Interpretação MIME em: {eval_url}",
                    "description": (
                        f"O endpoint '{eval_url}' não define o cabeçalho 'X-Content-Type-Options: nosniff'. "
                        "Sem este cabeçalho, certos navegadores tentam inferir o tipo de mídia (MIME sniffing) além do declarado no cabeçalho Content-Type, "
                        "o que pode transformar arquivos de texto ou respostas dinâmicas contendo scripts em vetores de execução de código (Cross-Site Scripting)."
                    ),
                    "reproduction_steps": (
                        f"1. Inspecione os cabeçalhos de resposta HTTP:\n"
                        f"   curl -sI -L -k \"{eval_url}\"\n"
                        f"2. Verifique a ausência da linha 'X-Content-Type-Options: nosniff'."
                    ),
                    "technical_impact": (
                        "Possibilidade de exploração de Cross-Site Scripting (XSS) caso a aplicação permita upload ou reflexão de conteúdo pelo usuário."
                    ),
                    "remediation": (
                        "Configurar o cabeçalho no servidor web:\n"
                        "- Nginx: add_header X-Content-Type-Options \"nosniff\" always;\n"
                        "- Apache: Header always set X-Content-Type-Options \"nosniff\""
                    ),
                    "tools_used": "curl (Arch Linux pacman: curl)",
                    "evidence_type": "HTTP_RESPONSE_HEADERS",
                    "command_executed": " ".join(headers_probe_cmd),
                    "raw_evidence": f"[COMANDO]\n{' '.join(headers_probe_cmd)}\n\n[RESPOSTA RECEBIDA]\n{headers_out.strip()}"
                })
                self.log(phase_name, "VALIDADO: Ausência de X-Content-Type-Options comprovada.", "SUCCESS")

            # Validação 1.4: Ausência de Cache-Control: no-store em URL parametrizada
            if self.has_query:
                if "no-store" not in headers_lower:
                    validated_findings.append({
                        "title": f"Ausência de Diretiva 'Cache-Control: no-store' em Endpoint com Parâmetros Dinâmicos",
                        "severity_suggestion": "BAIXA",
                        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
                        "port": str(self.port or (443 if self.scheme == "https" else 80)),
                        "service": self.scheme.upper(),
                        "attack_surface": f"Camada de Aplicação Web / Gerenciamento de Cache: {eval_url}",
                        "description": (
                            f"O endpoint parametrizado '{eval_url}' responde a requisições com dados dinâmicos (?{self.query}) sem a diretiva 'Cache-Control: no-store'. "
                            "Isso permite que intermediários de rede (proxies reversos, gateways, CDNs) ou o cache do navegador local armazenem em cache respostas associadas a parâmetros do usuário, "
                            "podendo resultar no vazamento de informações dinâmicas ou dados sensíveis transmitidos na query string."
                        ),
                        "reproduction_steps": (
                            f"1. Inspecione a resposta do endpoint com parâmetros:\n"
                            f"   curl -sI -L -k \"{eval_url}\"\n"
                            f"2. Verifique o cabeçalho 'Cache-Control' e confirme a ausência de 'no-store'."
                        ),
                        "technical_impact": (
                            "Vazamento de dados dinâmicos e histórico de navegação em caches intermediários não confiáveis ou dispositivos compartilhados."
                        ),
                        "remediation": (
                            "Definir cabeçalhos estritos de controle de cache para todas as respostas parametrizadas:\n"
                            "- Header set Cache-Control \"no-store, no-cache, must-revalidate, max-age=0\"\n"
                            "- Header set Pragma \"no-cache\""
                        ),
                        "tools_used": "curl (Arch Linux pacman: curl)",
                        "evidence_type": "HTTP_RESPONSE_HEADERS",
                        "command_executed": " ".join(headers_probe_cmd),
                        "raw_evidence": f"[COMANDO]\n{' '.join(headers_probe_cmd)}\n\n[RESPOSTA RECEBIDA]\n{headers_out.strip()}"
                    })
                    self.log(phase_name, "VALIDADO: Ausência de 'Cache-Control: no-store' comprovada no endpoint parametrizado.", "SUCCESS")

            # Validação 1.5: Vazamento de Informações de Versão do Servidor
            server_hdr = [line for line in resp_lines if line.lower().startswith("server:") or line.lower().startswith("x-powered-by:")]
            for shdr in server_hdr:
                if any(char.isdigit() for char in shdr):
                    validated_findings.append({
                        "title": f"Vazamento de Informações de Versão do Servidor ({shdr.split(':')[0]})",
                        "severity_suggestion": "BAIXA",
                        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                        "port": str(self.port or (443 if self.scheme == "https" else 80)),
                        "service": self.scheme.upper(),
                        "attack_surface": f"Reconhecimento / Fingerprinting do Servidor em: {eval_url}",
                        "description": (
                            f"O endpoint '{eval_url}' expõe publicamente a versão exata do software no cabeçalho '{shdr.strip()}'. "
                            "Essa divulgação fornece a invasores o mapeamento preciso de versões e tecnologias em execução, "
                            "facilitando a identificação imediata de vulnerabilidades conhecidas (CVEs) aplicáveis ao ambiente."
                        ),
                        "reproduction_steps": (
                            f"1. Execute a requisição e filtre pelos cabeçalhos de versão:\n"
                            f"   curl -sI -L -k \"{eval_url}\" | grep -iE \"^(server|x-powered-by):\"\n"
                            f"2. Observe a exibição explícita da versão do software."
                        ),
                        "technical_impact": (
                            "Facilita o reconhecimento direcionado e mapeamento de falhas conhecidas contra versões específicas."
                        ),
                        "remediation": (
                            "Desativar a emissão de versões nos servidores:\n"
                            "- Nginx: server_tokens off;\n"
                            "- Apache: ServerTokens Prod e ServerSignature Off\n"
                            "- PHP: expose_php = Off no php.ini"
                        ),
                        "tools_used": "curl (Arch Linux pacman: curl)",
                        "evidence_type": "HTTP_RESPONSE_HEADERS",
                        "command_executed": f"curl -sI -L -k \"{eval_url}\"",
                        "raw_evidence": f"[CABEÇALHOS CAPTURADOS]\n{shdr.strip()}\n\n[CONTEXTO COMPLETO]\n{headers_out.strip()}"
                    })
                    self.log(phase_name, f"VALIDADO: Divulgação de versão confirmada: {shdr.strip()}", "SUCCESS")
                    break

        # ── Teste 2: Validação de Métodos HTTP Inseguros (TRACE / OPTIONS) ──
        trace_probe_cmd = ["curl", "-sI", "-L", "-k", "-X", "TRACE", "--max-time", "8", eval_url]
        ret_t, trace_out, _ = run_command(trace_probe_cmd, timeout=10)
        if ret_t == 0 and trace_out.strip():
            trace_status = trace_out.splitlines()[0] if trace_out.splitlines() else ""
            if "200" in trace_status:
                validated_findings.append({
                    "title": "Método HTTP TRACE Habilitado (Cross-Site Tracing - XST)",
                    "severity_suggestion": "MÉDIA",
                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
                    "port": str(self.port or 80),
                    "service": self.scheme.upper(),
                    "attack_surface": "Métodos HTTP / Protocolo Web",
                    "description": (
                        "O método HTTP TRACE está ativo no servidor web. O método TRACE ecoa o conteúdo recebido de volta ao cliente, "
                        "permitindo que ataques de Cross-Site Tracing (XST) capturem cookies protegidos com o atributo HttpOnly através de scripts maliciosos injetados via XSS."
                    ),
                    "reproduction_steps": (
                        f"1. Envie uma requisição com o método TRACE no endpoint:\n"
                        f"   curl -i -s -L -k -X TRACE \"{eval_url}\"\n"
                        f"2. Observe o retorno com status HTTP 200 OK ecoando os cabeçalhos recebidos."
                    ),
                    "technical_impact": (
                        "Bypass de proteções HttpOnly de cookies de autenticação, viabilizando o sequestro de sessão."
                    ),
                    "remediation": (
                        "Desabilitar o método TRACE:\n"
                        "- Apache: TraceEnable Off no httpd.conf\n"
                        "- Nginx: if ($request_method = TRACE) { return 405; }"
                    ),
                    "tools_used": "curl (Arch Linux pacman: curl)",
                    "evidence_type": "HTTP_RESPONSE_TRACE",
                    "command_executed": " ".join(trace_probe_cmd),
                    "raw_evidence": f"[COMANDO]\n{' '.join(trace_probe_cmd)}\n\n[RESPOSTA]\n{trace_out.strip()}"
                })
                self.log(phase_name, "VALIDADO: Método HTTP TRACE ativo confirmado com código 200.", "CRITICAL")

        # ── Teste 3: Validação Estrita de Exposição de Arquivos Sensíveis (ex: .git/HEAD) ──
        git_url = f"{base_url}/.git/HEAD"
        git_probe_cmd = ["curl", "-s", "-k", "--max-time", "8", git_url]
        ret_g, git_out, _ = run_command(git_probe_cmd, timeout=10)
        if ret_g == 0 and ("ref: refs/" in git_out):
            # Prova inequívoca de repositório git exposto
            validated_findings.append({
                "title": "Exposição Crítica de Repositório Git Público (/.git/HEAD)",
                "severity_suggestion": "CRÍTICA",
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                "port": str(self.port or 80),
                "service": self.scheme.upper(),
                "attack_surface": "Controle de Versão / Código Fonte Exposto",
                "description": (
                    "O diretório '.git' da aplicação está acessível publicamente via web. A requisição para '/.git/HEAD' retornou o ponteiro do branch ativo. "
                    "Invasores podem realizar o download completo do histórico de commits, código-fonte integral, chaves de API, senhas embutidas e credenciais de banco de dados."
                ),
                "reproduction_steps": (
                    f"1. Execute a requisição direta para o endpoint:\n"
                    f"   curl -s -k \"{git_url}\"\n"
                    f"2. Confirme o conteúdo retornado contendo a estrutura de branch 'ref: refs/heads/...'.\n"
                    f"3. Utilize ferramentas como 'git-dumper' para recuperar todo o repositório."
                ),
                "technical_impact": (
                    "Vazamento integral do código-fonte e histórico de versionamento da aplicação, segredos, tokens e propriedade intelectual."
                ),
                "remediation": (
                    "Bloquear imediatamente o acesso a diretórios que iniciam com ponto (.git, .env) na configuração do servidor web:\n"
                    "- Nginx: location ~ /\\.git { deny all; return 404; }\n"
                    "- Apache: <DirectoryMatch \"/\\.git\"> Require all denied </DirectoryMatch>"
                ),
                "tools_used": "curl (Arch Linux pacman: curl)",
                "evidence_type": "EXPOSED_FILE_CONTENT",
                "command_executed": " ".join(git_probe_cmd),
                "raw_evidence": f"[COMANDO]\n{' '.join(git_probe_cmd)}\n\n[CONTEÚDO RECEBIDO]\n{git_out.strip()}"
            })
            self.log(phase_name, "VALIDADO: Repositório Git (.git/HEAD) exposto publicamente!", "CRITICAL")

        finish_action(act_id, "completed", f"Validações finalizadas. Achados estritos confirmados: {len(validated_findings)}")
        self.validated_vulns = validated_findings
        save_memory(self.session_id, "validated_findings", validated_findings, category="vuln_validation")
        return validated_findings

    # ─────────────────────────────────────────────
    # FASE 5: COLETA DE EVIDÊNCIAS
    # ─────────────────────────────────────────────
    def phase_5_evidence_collection(self) -> List[Dict[str, Any]]:
        """
        Fase 5: Coleta, formatação e geração de hashes criptográficos de evidências.
        Garante a cadeia de custódia e reprodutibilidade de cada vulnerabilidade.
        """
        phase_name = "Coleta de Evidências"
        act_id = log_action(self.session_id, phase_name, "Store_Evidence_Hashes", self.host, "sha256_audit", "running")
        self.log(phase_name, "Processando cadeia de custódia e hashes criptográficos SHA-256 para cada evidência...")

        for v in self.validated_vulns:
            ev_id = save_evidence(
                session_id=self.session_id,
                evidence_type=v.get("evidence_type", "GENERIC_EVIDENCE"),
                command_executed=v.get("command_executed", "N/A"),
                raw_evidence=v.get("raw_evidence", ""),
                reproduction_command=v.get("reproduction_steps", "")
            )
            v["evidence_id"] = ev_id
            self.log(phase_name, f"Evidência arquivada (ID #{ev_id}) para: {v['title']}", "SUCCESS")

        finish_action(act_id, "completed", f"Evidências salvas: {len(self.validated_vulns)}")
        return self.validated_vulns

    # ─────────────────────────────────────────────
    # FASE 6: CLASSIFICAÇÃO DE SEVERIDADE (CVSS v3.1)
    # ─────────────────────────────────────────────
    def phase_6_severity_classification(self) -> List[Dict[str, Any]]:
        """
        Fase 6: Calcula pontuação matemática e vetor CVSS v3.1 oficial para cada vulnerabilidade.
        Persiste no banco SQLite com todos os campos estruturados.
        """
        phase_name = "Classificação CVSS"
        act_id = log_action(self.session_id, phase_name, "CVSS_Calculation", self.host, "cvss31_engine", "running")
        self.log(phase_name, "Calculando scores CVSS v3.1 exatos e persistindo no banco SQLite...")

        if self.llm_online and self.validated_vulns:
            self.log(phase_name, f"Enriquecendo achados técnicos com a LLM local ({self.llm_model})...", "INFO")
            for v in self.validated_vulns:
                try:
                    enrich_vulnerability_with_llm(v)
                except Exception as e:
                    self.log(phase_name, f"Aviso ao consultar LLM: {e}", "WARN")

        for v in self.validated_vulns:
            vector_str = v.get("cvss_vector", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")
            parsed = parse_cvss_vector(vector_str)
            score = parsed["score"]
            severity = parsed["severity"]

            vuln_id = save_vulnerability(
                session_id=self.session_id,
                title=v["title"],
                severity=severity,
                cvss_score=score,
                cvss_vector=vector_str,
                port=v.get("port", "-"),
                service=v.get("service", "-"),
                attack_surface=v.get("attack_surface", "Rede / Web"),
                description=v["description"],
                reproduction_steps=v["reproduction_steps"],
                technical_impact=v["technical_impact"],
                remediation=v["remediation"],
                tools_used=v.get("tools_used", "METATRON Core"),
                evidence_id=v.get("evidence_id"),
                is_validated=1,
                validation_notes="Confirmado através de teste ativo reproduzível."
            )
            v["id"] = vuln_id
            v["calculated_score"] = score
            v["calculated_severity"] = severity
            self.log(phase_name, f"Vulnerabilidade #{vuln_id} registrada: [{severity}] {v['title']} (CVSS {score:.1f})", "SUCCESS")

        # Atualiza a sessão
        max_score = max([v.get("calculated_score", 0.0) for v in self.validated_vulns], default=0.0)
        overall_risk = "BAIXO"
        if max_score >= 9.0:
            overall_risk = "CRÍTICO"
        elif max_score >= 7.0:
            overall_risk = "ALTO"
        elif max_score >= 4.0:
            overall_risk = "MÉDIO"

        summary_text = f"Auditoria concluída com {len(self.validated_vulns)} vulnerabilidade(s) validada(s). Risco global: {overall_risk}."
        if self.llm_online and self.validated_vulns:
            try:
                llm_summary = generate_executive_summary_llm(self.raw_target, self.validated_vulns, 0.0)
                if llm_summary:
                    summary_text = f"{summary_text}\n\n[SUMÁRIO EXECUTIVO - METATRON AI]\n{llm_summary}"
            except Exception:
                pass

        finish_session(self.session_id, overall_risk, summary_text, len(self.validated_vulns))
        finish_action(act_id, "completed", f"Classificação concluída. Risco: {overall_risk}")
        return self.validated_vulns

    # ─────────────────────────────────────────────
    # FASE 7: GERAÇÃO DE RELATÓRIO (1 VULN = 1 PDF)
    # ─────────────────────────────────────────────
    def phase_7_report_generation(self, output_dir: str = "reports") -> List[str]:
        """
        Fase 7: Gera um PDF independente para CADA vulnerabilidade validada.
        Regra estrita: 1 vulnerabilidade = 1 PDF. 5 vulnerabilidades = 5 PDFs.
        """
        phase_name = "Geração de PDFs"
        act_id = log_action(self.session_id, phase_name, "Export_Independent_PDFs", self.host, "reportlab", "running")
        self.log(phase_name, "Iniciando geração de relatórios técnicos independentes em PDF...")

        if not self.validated_vulns:
            self.log(phase_name, "Nenhuma vulnerabilidade validada encontrada. Nenhum PDF individual gerado.", "WARN")
            finish_action(act_id, "completed", "Nenhuma vuln para exportação")
            return []

        pdf_files = export_all_vulnerabilities_for_session(self.session_id, output_dir=output_dir)
        self.generated_pdfs = pdf_files

        self.log(phase_name, f"Sucesso: {len(pdf_files)} relatório(s) PDF independente(s) gerado(s) em '{output_dir}/':", "SUCCESS")
        for f in pdf_files:
            print(f"   📄 {f}")

        finish_action(act_id, "completed", f"PDFs gerados: {len(pdf_files)}")
        return pdf_files

    # ─────────────────────────────────────────────
    # EXECUÇÃO DO PIPELINE COMPLETO
    # ─────────────────────────────────────────────
    def run_full_audit(self) -> Dict[str, Any]:
        """Executa sequencialmente as 7 fases da auditoria autônoma."""
        print(f"\n\033[95m{'='*65}\033[0m")
        print(f"\033[95m🔱 METATRON :: AUDITORIA AUTÔNOMA DE SEGURANÇA NO ARCH LINUX\033[0m")
        print(f"Alvo: {self.raw_target} | Sessão SQLite: #{self.session_id}")
        print(f"\033[95m{'='*65}\033[0m\n")

        t0 = time.time()
        self.phase_1_reconnaissance()
        self.phase_2_enumeration()
        self.phase_3_attack_surface_discovery()
        self.phase_4_vulnerability_validation()
        self.phase_5_evidence_collection()
        self.phase_6_severity_classification()
        pdfs = self.phase_7_report_generation()
        duration = time.time() - t0

        print(f"\n\033[92m{'='*65}\033[0m")
        print(f"\033[92m[+] AUDITORIA CONCLUÍDA EM {duration:.1f} SEGUNDOS\033[0m")
        print(f"Total de vulnerabilidades validadas : {len(self.validated_vulns)}")
        print(f"Total de PDFs independentes gerados : {len(pdfs)}")
        print(f"\033[92m{'='*65}\033[0m\n")

        return {
            "session_id": self.session_id,
            "target": self.raw_target,
            "vulnerabilities": self.validated_vulns,
            "pdf_reports": pdfs,
            "duration_seconds": duration
        }


if __name__ == "__main__":
    test_target = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    engine = AuditEngine(test_target)
    engine.run_full_audit()
