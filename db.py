#!/usr/bin/env python3
"""
METATRON - db.py
Camada de persistência local em SQLite para o METATRON no Arch Linux.
Substitui completamente o MariaDB, armazenando:
 - Memória de execução
 - Resultados de scans
 - Evidências coletadas (com hashes criptográficos SHA-256)
 - Vulnerabilidades validadas
 - Ferramentas disponíveis
 - Ferramentas instaladas dinamicamente via pacman
 - Histórico cronológico de ações
 - Cache offline de inteligência e assinaturas
"""

import os
import json
import sqlite3
import hashlib
from datetime import datetime
from typing import Dict, List, Any, Optional

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "metatron.db")


def get_connection(db_path: str = DB_PATH) -> sqlite3.Connection:
    """Retorna uma conexão SQLite com suporte a Row e Foreign Keys ativadas."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA journal_mode = WAL;")
    return conn


def init_db(db_path: str = DB_PATH):
    """Cria e migra todas as tabelas necessárias no SQLite."""
    conn = get_connection(db_path)
    c = conn.cursor()

    # 1. Sessões de Auditoria
    c.execute("""
    CREATE TABLE IF NOT EXISTS sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target TEXT NOT NULL,
        start_time TEXT NOT NULL,
        end_time TEXT,
        status TEXT NOT NULL DEFAULT 'active',
        risk_level TEXT DEFAULT 'DESCONHECIDO',
        summary TEXT,
        total_vulns INTEGER DEFAULT 0,
        metadata TEXT
    );
    """)

    # 2. Memória de Execução
    c.execute("""
    CREATE TABLE IF NOT EXISTS execution_memory (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id INTEGER,
        key TEXT NOT NULL,
        value TEXT,
        category TEXT DEFAULT 'general',
        updated_at TEXT NOT NULL,
        FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
    );
    """)

    # 3. Resultados de Scans
    c.execute("""
    CREATE TABLE IF NOT EXISTS scan_results (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id INTEGER NOT NULL,
        phase TEXT NOT NULL,
        tool_name TEXT NOT NULL,
        target TEXT NOT NULL,
        command TEXT,
        raw_output TEXT NOT NULL,
        parsed_data TEXT,
        status TEXT NOT NULL,
        executed_at TEXT NOT NULL,
        FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
    );
    """)

    # 4. Evidências Coletadas
    c.execute("""
    CREATE TABLE IF NOT EXISTS evidence (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id INTEGER NOT NULL,
        vuln_id INTEGER,
        evidence_type TEXT NOT NULL,
        command_executed TEXT NOT NULL,
        raw_evidence TEXT NOT NULL,
        evidence_hash TEXT NOT NULL,
        reproduction_command TEXT,
        collected_at TEXT NOT NULL,
        FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
    );
    """)

    # 5. Vulnerabilidades Validadas
    c.execute("""
    CREATE TABLE IF NOT EXISTS vulnerabilities (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        severity TEXT NOT NULL,
        cvss_score REAL NOT NULL,
        cvss_vector TEXT NOT NULL,
        port TEXT,
        service TEXT,
        attack_surface TEXT,
        description TEXT NOT NULL,
        evidence_id INTEGER,
        reproduction_steps TEXT NOT NULL,
        technical_impact TEXT NOT NULL,
        remediation TEXT NOT NULL,
        tools_used TEXT NOT NULL,
        discovery_date TEXT NOT NULL,
        is_validated INTEGER DEFAULT 1,
        validation_notes TEXT,
        FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE,
        FOREIGN KEY (evidence_id) REFERENCES evidence(id) ON DELETE SET NULL
    );
    """)

    # 6. Catálogo de Ferramentas Disponíveis
    c.execute("""
    CREATE TABLE IF NOT EXISTS available_tools (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tool_name TEXT UNIQUE NOT NULL,
        binary_path TEXT,
        category TEXT NOT NULL,
        capabilities TEXT NOT NULL,
        is_installed INTEGER DEFAULT 0,
        version TEXT,
        last_checked TEXT NOT NULL
    );
    """)

    # 7. Ferramentas Instaladas Dinamicamente (pacman)
    c.execute("""
    CREATE TABLE IF NOT EXISTS installed_tools (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tool_name TEXT NOT NULL,
        package_name TEXT NOT NULL,
        installed_at TEXT NOT NULL,
        pacman_cmd TEXT NOT NULL,
        success INTEGER NOT NULL,
        log_output TEXT
    );
    """)

    # 8. Histórico Cronológico de Ações
    c.execute("""
    CREATE TABLE IF NOT EXISTS action_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id INTEGER,
        phase TEXT NOT NULL,
        action_name TEXT NOT NULL,
        target TEXT,
        command TEXT,
        status TEXT NOT NULL,
        start_time TEXT NOT NULL,
        end_time TEXT,
        details TEXT,
        FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
    );
    """)

    # 9. Cache Offline
    c.execute("""
    CREATE TABLE IF NOT EXISTS offline_cache (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        cache_key TEXT UNIQUE NOT NULL,
        cache_type TEXT NOT NULL,
        data TEXT NOT NULL,
        created_at TEXT NOT NULL,
        expires_at TEXT
    );
    """)

    conn.commit()
    conn.close()


# ─────────────────────────────────────────────
# GERENCIAMENTO DE SESSÕES
# ─────────────────────────────────────────────

def create_session(target: str, metadata: Optional[Dict[str, Any]] = None) -> int:
    """Cria uma nova sessão de auditoria no SQLite e retorna seu ID."""
    conn = get_connection()
    c = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    meta_json = json.dumps(metadata or {}, ensure_ascii=False)
    c.execute(
        "INSERT INTO sessions (target, start_time, status, metadata) VALUES (?, ?, ?, ?)",
        (target, now, "active", meta_json)
    )
    conn.commit()
    session_id = c.lastrowid
    conn.close()
    return session_id


def finish_session(session_id: int, risk_level: str, summary: str, total_vulns: int = 0):
    """Finaliza a sessão registrando término, risco e sumário."""
    conn = get_connection()
    c = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute("""
        UPDATE sessions 
        SET end_time = ?, status = 'completed', risk_level = ?, summary = ?, total_vulns = ?
        WHERE id = ?
    """, (now, risk_level, summary, total_vulns, session_id))
    conn.commit()
    conn.close()


def get_session(session_id: int) -> Dict[str, Any]:
    """Retorna detalhes completos de uma sessão e seus registros vinculados."""
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM sessions WHERE id = ?", (session_id,))
    session = c.fetchone()
    if not session:
        conn.close()
        return {}

    c.execute("SELECT * FROM vulnerabilities WHERE session_id = ? ORDER BY cvss_score DESC", (session_id,))
    vulns = [dict(row) for row in c.fetchall()]

    c.execute("SELECT * FROM scan_results WHERE session_id = ? ORDER BY id ASC", (session_id,))
    scans = [dict(row) for row in c.fetchall()]

    c.execute("SELECT * FROM evidence WHERE session_id = ? ORDER BY id ASC", (session_id,))
    evidences = [dict(row) for row in c.fetchall()]

    c.execute("SELECT * FROM action_history WHERE session_id = ? ORDER BY id ASC", (session_id,))
    actions = [dict(row) for row in c.fetchall()]

    c.execute("SELECT * FROM execution_memory WHERE session_id = ? ORDER BY id ASC", (session_id,))
    memory = [dict(row) for row in c.fetchall()]

    conn.close()
    return {
        "session": dict(session),
        "vulnerabilities": vulns,
        "scans": scans,
        "evidence": evidences,
        "actions": actions,
        "memory": memory,
    }


def get_all_sessions() -> List[Dict[str, Any]]:
    """Retorna lista de todas as sessões ordenadas pela data decrescente."""
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM sessions ORDER BY id DESC")
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows


def delete_full_session(session_id: int):
    """Remove permanentemente uma sessão e todos os registros associados em cascata."""
    conn = get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM sessions WHERE id = ?", (session_id,))
    conn.commit()
    conn.close()


# ─────────────────────────────────────────────
# MEMÓRIA DE EXECUÇÃO
# ─────────────────────────────────────────────

def save_memory(session_id: Optional[int], key: str, value: Any, category: str = "general"):
    """Armazena ou atualiza uma variável na memória de execução."""
    conn = get_connection()
    c = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    val_str = json.dumps(value, ensure_ascii=False) if not isinstance(value, str) else value
    c.execute("""
        INSERT INTO execution_memory (session_id, key, value, category, updated_at)
        VALUES (?, ?, ?, ?, ?)
    """, (session_id, key, val_str, category, now))
    conn.commit()
    conn.close()


def get_memory(session_id: Optional[int], key: str) -> Optional[str]:
    """Recupera valor mais recente da chave na memória de execução."""
    conn = get_connection()
    c = conn.cursor()
    if session_id is not None:
        c.execute("""
            SELECT value FROM execution_memory 
            WHERE session_id = ? AND key = ? 
            ORDER BY id DESC LIMIT 1
        """, (session_id, key))
    else:
        c.execute("""
            SELECT value FROM execution_memory 
            WHERE key = ? 
            ORDER BY id DESC LIMIT 1
        """, (key,))
    row = c.fetchone()
    conn.close()
    return row["value"] if row else None


# ─────────────────────────────────────────────
# RESULTADOS DE SCANS
# ─────────────────────────────────────────────

def save_scan_result(session_id: int, phase: str, tool_name: str, target: str,
                     command: str, raw_output: str, parsed_data: Optional[Dict[str, Any]] = None,
                     status: str = "success") -> int:
    """Registra saída bruta e dados estruturados de uma varredura."""
    conn = get_connection()
    c = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    parsed_json = json.dumps(parsed_data or {}, ensure_ascii=False)
    c.execute("""
        INSERT INTO scan_results (session_id, phase, tool_name, target, command, raw_output, parsed_data, status, executed_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (session_id, phase, tool_name, target, command, raw_output, parsed_json, status, now))
    conn.commit()
    scan_id = c.lastrowid
    conn.close()
    return scan_id


def get_scan_results(session_id: int) -> List[Dict[str, Any]]:
    """Retorna todas as varreduras de uma sessão."""
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM scan_results WHERE session_id = ? ORDER BY id ASC", (session_id,))
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows


# ─────────────────────────────────────────────
# EVIDÊNCIAS
# ─────────────────────────────────────────────

def save_evidence(session_id: int, evidence_type: str, command_executed: str,
                  raw_evidence: str, reproduction_command: Optional[str] = None,
                  vuln_id: Optional[int] = None) -> int:
    """Salva evidência com cálculo de hash criptográfico SHA-256 para integridade."""
    conn = get_connection()
    c = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    evidence_hash = hashlib.sha256(raw_evidence.encode("utf-8", errors="replace")).hexdigest()
    repro = reproduction_command or command_executed

    c.execute("""
        INSERT INTO evidence (session_id, vuln_id, evidence_type, command_executed, raw_evidence, evidence_hash, reproduction_command, collected_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (session_id, vuln_id, evidence_type, command_executed, raw_evidence, evidence_hash, repro, now))
    conn.commit()
    evidence_id = c.lastrowid
    conn.close()
    return evidence_id


def link_evidence_to_vuln(evidence_id: int, vuln_id: int):
    """Associa uma evidência já coletada a uma vulnerabilidade registrada."""
    conn = get_connection()
    c = conn.cursor()
    c.execute("UPDATE evidence SET vuln_id = ? WHERE id = ?", (vuln_id, evidence_id))
    c.execute("UPDATE vulnerabilities SET evidence_id = ? WHERE id = ?", (evidence_id, vuln_id))
    conn.commit()
    conn.close()


def get_evidence(evidence_id: int) -> Optional[Dict[str, Any]]:
    """Retorna detalhes de uma evidência pelo ID."""
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM evidence WHERE id = ?", (evidence_id,))
    row = c.fetchone()
    conn.close()
    return dict(row) if row else None


# ─────────────────────────────────────────────
# VULNERABILIDADES VALIDADAS
# ─────────────────────────────────────────────

def save_vulnerability(session_id: int, title: str, severity: str, cvss_score: float,
                       cvss_vector: str, port: str, service: str, attack_surface: str,
                       description: str, reproduction_steps: str, technical_impact: str,
                       remediation: str, tools_used: str, evidence_id: Optional[int] = None,
                       is_validated: int = 1, validation_notes: str = "") -> int:
    """Insere uma vulnerabilidade estritamente validada no banco de dados."""
    conn = get_connection()
    c = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    c.execute("""
        INSERT INTO vulnerabilities (
            session_id, title, severity, cvss_score, cvss_vector, port, service,
            attack_surface, description, evidence_id, reproduction_steps, technical_impact,
            remediation, tools_used, discovery_date, is_validated, validation_notes
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        session_id, title, severity.upper(), cvss_score, cvss_vector, port, service,
        attack_surface, description, evidence_id, reproduction_steps, technical_impact,
        remediation, tools_used, now, is_validated, validation_notes
    ))
    conn.commit()
    vuln_id = c.lastrowid

    if evidence_id:
        c.execute("UPDATE evidence SET vuln_id = ? WHERE id = ?", (vuln_id, evidence_id))
        conn.commit()

    conn.close()
    return vuln_id


def get_vulnerability(vuln_id: int) -> Optional[Dict[str, Any]]:
    """Retorna uma vulnerabilidade específica com sua evidência associada."""
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
        SELECT v.*, e.raw_evidence, e.evidence_hash, e.command_executed, e.reproduction_command
        FROM vulnerabilities v
        LEFT JOIN evidence e ON v.evidence_id = e.id
        WHERE v.id = ?
    """, (vuln_id,))
    row = c.fetchone()
    conn.close()
    return dict(row) if row else None


def get_all_vulnerabilities() -> List[Dict[str, Any]]:
    """Retorna todas as vulnerabilidades salvas em todas as sessões."""
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
        SELECT v.*, s.target as session_target, e.evidence_hash
        FROM vulnerabilities v
        JOIN sessions s ON v.session_id = s.id
        LEFT JOIN evidence e ON v.evidence_id = e.id
        ORDER BY v.cvss_score DESC, v.id DESC
    """)
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows


def get_vulnerabilities(session_id: int) -> List[Dict[str, Any]]:
    """Retorna vulnerabilidades de uma sessão específica."""
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
        SELECT v.*, e.raw_evidence, e.evidence_hash, e.command_executed, e.reproduction_command
        FROM vulnerabilities v
        LEFT JOIN evidence e ON v.evidence_id = e.id
        WHERE v.session_id = ?
        ORDER BY v.cvss_score DESC
    """, (session_id,))
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows


def edit_vulnerability(vuln_id: int, field: str, value: Any):
    """Atualiza um campo específico de uma vulnerabilidade."""
    conn = get_connection()
    c = conn.cursor()
    allowed_fields = {
        "title", "severity", "cvss_score", "cvss_vector", "port", "service",
        "attack_surface", "description", "reproduction_steps", "technical_impact",
        "remediation", "tools_used", "validation_notes"
    }
    if field not in allowed_fields:
        conn.close()
        raise ValueError(f"Campo não permitido para edição: {field}")

    c.execute(f"UPDATE vulnerabilities SET {field} = ? WHERE id = ?", (value, vuln_id))
    conn.commit()
    conn.close()


def delete_vulnerability(vuln_id: int):
    """Exclui uma vulnerabilidade."""
    conn = get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM vulnerabilities WHERE id = ?", (vuln_id,))
    conn.commit()
    conn.close()


# ─────────────────────────────────────────────
# GERENCIAMENTO DE FERRAMENTAS
# ─────────────────────────────────────────────

def upsert_tool(tool_name: str, binary_path: Optional[str], category: str,
                capabilities: str, is_installed: bool, version: str = ""):
    """Registra ou atualiza o estado de uma ferramenta no Arch Linux."""
    conn = get_connection()
    c = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute("""
        INSERT INTO available_tools (tool_name, binary_path, category, capabilities, is_installed, version, last_checked)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(tool_name) DO UPDATE SET
            binary_path = excluded.binary_path,
            category = excluded.category,
            capabilities = excluded.capabilities,
            is_installed = excluded.is_installed,
            version = excluded.version,
            last_checked = excluded.last_checked
    """, (tool_name, binary_path, category, capabilities, 1 if is_installed else 0, version, now))
    conn.commit()
    conn.close()


def get_available_tools() -> List[Dict[str, Any]]:
    """Retorna todas as ferramentas catalogadas."""
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM available_tools ORDER BY category ASC, tool_name ASC")
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows


def log_tool_installation(tool_name: str, package_name: str, pacman_cmd: str,
                          success: bool, log_output: str):
    """Registra a instalação dinâmica de uma ferramenta via pacman."""
    conn = get_connection()
    c = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute("""
        INSERT INTO installed_tools (tool_name, package_name, installed_at, pacman_cmd, success, log_output)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (tool_name, package_name, now, pacman_cmd, 1 if success else 0, log_output))
    conn.commit()
    conn.close()


def get_installed_tools_log() -> List[Dict[str, Any]]:
    """Retorna o histórico de instalações dinâmicas de ferramentas."""
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM installed_tools ORDER BY id DESC")
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows


# ─────────────────────────────────────────────
# HISTÓRICO DE AÇÕES
# ─────────────────────────────────────────────

def log_action(session_id: Optional[int], phase: str, action_name: str, target: str,
               command: str, status: str, details: str = "") -> int:
    """Registra início de uma ação no fluxo de auditoria."""
    conn = get_connection()
    c = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute("""
        INSERT INTO action_history (session_id, phase, action_name, target, command, status, start_time, details)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (session_id, phase, action_name, target, command, status, now, details))
    conn.commit()
    action_id = c.lastrowid
    conn.close()
    return action_id


def finish_action(action_id: int, status: str, details: str = ""):
    """Finaliza registro de uma ação com timestamp e status."""
    conn = get_connection()
    c = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute("""
        UPDATE action_history 
        SET status = ?, end_time = ?, details = details || ' ' || ?
        WHERE id = ?
    """, (status, now, details, action_id))
    conn.commit()
    conn.close()


def get_actions_for_session(session_id: int) -> List[Dict[str, Any]]:
    """Retorna histórico cronológico de ações de uma sessão."""
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM action_history WHERE session_id = ? ORDER BY id ASC", (session_id,))
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows


# ─────────────────────────────────────────────
# CACHE OFFLINE
# ─────────────────────────────────────────────

def cache_put(cache_key: str, cache_type: str, data: Any, expires_at: Optional[str] = None):
    """Armazena um resultado no cache offline."""
    conn = get_connection()
    c = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    data_str = json.dumps(data, ensure_ascii=False) if not isinstance(data, str) else data
    c.execute("""
        INSERT INTO offline_cache (cache_key, cache_type, data, created_at, expires_at)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(cache_key) DO UPDATE SET
            data = excluded.data,
            created_at = excluded.created_at,
            expires_at = excluded.expires_at
    """, (cache_key, cache_type, data_str, now, expires_at))
    conn.commit()
    conn.close()


def cache_get(cache_key: str) -> Optional[str]:
    """Recupera dados do cache offline se não expirados."""
    conn = get_connection()
    c = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute("""
        SELECT data FROM offline_cache 
        WHERE cache_key = ? AND (expires_at IS NULL OR expires_at > ?)
    """, (cache_key, now))
    row = c.fetchone()
    conn.close()
    return row["data"] if row else None


# Auto-inicializa o schema do banco se executado ou importado
init_db()

if __name__ == "__main__":
    print(f"[+] Banco SQLite METATRON inicializado com sucesso em: {DB_PATH}")
