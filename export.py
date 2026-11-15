#!/usr/bin/env python3
"""
METATRON - export.py
Gerador de relatórios técnicos profissionais independentes em PDF para o METATRON no Arch Linux.
Regra fundamental:
  1 vulnerabilidade validada = 1 PDF independente.
  5 vulnerabilidades = 5 PDFs distintos.

Cada PDF gerado contém obrigatoriamente:
 - Título da vulnerabilidade
 - Severidade
 - CVSS (Score e Vetor v3.1 completo)
 - Evidências (logs brutos, payloads, respostas de servidor, hash SHA-256)
 - Passos para reprodução (reproduzíveis e verificados)
 - Impacto (técnico e de negócio)
 - Correção recomendada (diretivas técnicas e passos acionáveis)
 - Ferramentas utilizadas
 - Data e hora da descoberta
"""

import os
import sys
import re
from datetime import datetime
from typing import Dict, Any, List, Optional

# Bootstrap para reportlab
_base_dir = os.path.dirname(os.path.abspath(__file__))
for _py_ver in ["python3.13", "python3.14"]:
    _site = os.path.join(_base_dir, "venv", "lib", _py_ver, "site-packages")
    if os.path.exists(_site) and _site not in sys.path:
        sys.path.insert(0, _site)

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable, KeepTogether
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
from reportlab.pdfgen import canvas

from db import get_vulnerability, get_vulnerabilities, get_session
from cvss import parse_cvss_vector


# ─────────────────────────────────────────────
# PALETA DE CORES E ESTILOS
# ─────────────────────────────────────────────

SEVERITY_COLORS = {
    "CRÍTICA":     "#990000",
    "CRITICA":     "#990000",
    "CRITICAL":    "#990000",
    "ALTA":        "#d35400",
    "HIGH":        "#d35400",
    "MÉDIA":       "#d4ac0d",
    "MEDIA":       "#d4ac0d",
    "MEDIUM":      "#d4ac0d",
    "BAIXA":       "#27ae60",
    "LOW":         "#27ae60",
    "INFORMATIVA": "#2980b9",
    "INFO":        "#2980b9",
    "DESCONHECIDO":"#7f8c8d"
}


class NumberedCanvas(canvas.Canvas):
    """Canvas com numeração de páginas dinâmicas 'Página X de Y'."""
    def __init__(self, *args, **kwargs):
        super(NumberedCanvas, self).__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_number(num_pages)
            canvas.Canvas.showPage(self)
        canvas.Canvas.save(self)

    def draw_page_number(self, page_count):
        self.saveState()
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#7f8c8d"))

        # Linha de rodapé
        self.setStrokeColor(colors.HexColor("#e0e0e0"))
        self.setLineWidth(0.5)
        self.line(15 * mm, 12 * mm, 195 * mm, 12 * mm)

        # Texto do rodapé
        footer_text = "METATRON | Relatório de Auditoria de Vulnerabilidade Independente | Arch Linux"
        page_str = f"Página {self._pageNumber} de {page_count}"
        self.drawString(15 * mm, 8 * mm, footer_text)
        self.drawRightString(195 * mm, 8 * mm, page_str)
        self.restoreState()


def clean_text_for_pdf(text: Optional[str]) -> str:
    """Escapa entidades XML/HTML para exibição segura no ReportLab."""
    if not text:
        return ""
    t = str(text)
    t = t.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return t


def sanitize_filename(name: str) -> str:
    """Gera nome de arquivo limpo para o sistema de arquivos."""
    clean = re.sub(r"[^a-zA-Z0-9_\-]", "_", name)
    return clean[:50].strip("_")


# ─────────────────────────────────────────────
# GERADOR DE PDF INDIVIDUAL DE VULNERABILIDADE
# ─────────────────────────────────────────────

def export_vulnerability_pdf(vuln_id: int, output_dir: str = "reports") -> str:
    """
    Gera um relatório PDF independente para uma única vulnerabilidade validada.
    Atende ao critério de 1 vulnerabilidade = 1 PDF.
    """
    vuln = get_vulnerability(vuln_id)
    if not vuln:
        raise ValueError(f"Vulnerabilidade ID {vuln_id} não encontrada no banco SQLite.")

    os.makedirs(output_dir, exist_ok=True)

    title = vuln.get("title") or "Vulnerabilidade sem título"
    sev = (vuln.get("severity") or "DESCONHECIDO").upper()
    score = vuln.get("cvss_score") or 0.0
    vector = vuln.get("cvss_vector") or "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"
    target = vuln.get("session_target") or "Alvo não especificado"
    discovery_date = vuln.get("discovery_date") or datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Nome único e padronizado do arquivo
    slug = sanitize_filename(title.lower())
    filename = os.path.join(output_dir, f"METATRON_VULN_{vuln_id:03d}_{slug}.pdf")

    doc = SimpleDocTemplate(
        filename,
        pagesize=A4,
        topMargin=15 * mm,
        bottomMargin=18 * mm,
        leftMargin=15 * mm,
        rightMargin=15 * mm
    )

    sev_color = colors.HexColor(SEVERITY_COLORS.get(sev, "#7f8c8d"))

    # Estilos de texto
    title_style = ParagraphStyle(
        "DocTitle",
        fontName="Helvetica-Bold",
        fontSize=20,
        leading=24,
        textColor=colors.HexColor("#1a252f"),
        spaceAfter=4
    )
    subtitle_style = ParagraphStyle(
        "DocSubtitle",
        fontName="Helvetica",
        fontSize=10,
        leading=13,
        textColor=colors.HexColor("#555555"),
        spaceAfter=8
    )
    section_heading = ParagraphStyle(
        "SectionHeading",
        fontName="Helvetica-Bold",
        fontSize=12,
        leading=16,
        textColor=colors.HexColor("#2c3e50"),
        spaceBefore=10,
        spaceAfter=4
    )
    body_style = ParagraphStyle(
        "BodyText",
        fontName="Helvetica",
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#2d3436"),
        alignment=TA_LEFT,
        spaceAfter=4
    )
    code_block = ParagraphStyle(
        "CodeBlock",
        fontName="Courier",
        fontSize=7.5,
        leading=10.5,
        textColor=colors.HexColor("#2c3e50"),
        backColor=colors.HexColor("#f8f9fa"),
        borderPadding=6,
        spaceBefore=4,
        spaceAfter=6
    )
    badge_style = ParagraphStyle(
        "BadgeStyle",
        fontName="Helvetica-Bold",
        fontSize=10,
        leading=12,
        textColor=colors.white,
        alignment=TA_CENTER
    )

    story = []

    # 1. Cabeçalho de Identidade
    meta_top = [
        [
            Paragraph("<b>METATRON</b> | Auditoria Autônoma de Segurança", subtitle_style),
            Paragraph(f"<b>DATA:</b> {discovery_date}", ParagraphStyle("r", fontName="Helvetica", fontSize=9, alignment=TA_RIGHT, textColor=colors.HexColor("#555555")))
        ]
    ]
    t_top = Table(meta_top, colWidths=[110 * mm, 70 * mm])
    t_top.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("PADDING", (0, 0), (-1, -1), 0),
    ]))
    story.append(t_top)
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#2c3e50"), spaceBefore=3, spaceAfter=8))

    # 2. Título da Vulnerabilidade e Badge de Severidade
    badge_table_data = [[
        Paragraph(f"<b>VULNERABILIDADE #{vuln_id:03d}</b><br/>{clean_text_for_pdf(title)}", title_style),
        Table(
            [[Paragraph(f"<b>{sev}</b><br/><font size=8>CVSS {score:.1f}</font>", badge_style)]],
            colWidths=[38 * mm],
            style=[
                ("BACKGROUND", (0, 0), (-1, -1), sev_color),
                ("PADDING", (0, 0), (-1, -1), 6),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]
        )
    ]]
    t_header = Table(badge_table_data, colWidths=[140 * mm, 40 * mm])
    t_header.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("PADDING", (0, 0), (-1, -1), 0),
    ]))
    story.append(t_header)
    story.append(Spacer(1, 8))

    # 3. Metadados Gerais da Descoberta
    port_service = f"{vuln.get('port') or '-'} / {vuln.get('service') or '-'}"
    ev_hash = vuln.get("evidence_hash") or "Não registrado"
    if len(ev_hash) > 32:
        ev_hash_short = ev_hash[:16] + "..." + ev_hash[-16:]
    else:
        ev_hash_short = ev_hash

    overview_data = [
        ["Alvo Auditado:", clean_text_for_pdf(target), "Severidade:", sev],
        ["Porta / Serviço:", port_service, "CVSS v3.1 Score:", f"{score:.1f} ({sev})"],
        ["Superfície de Ataque:", clean_text_for_pdf(vuln.get("attack_surface") or "Rede / Web"), "Vetor CVSS:", vector],
        ["Ferramentas Utilizadas:", clean_text_for_pdf(vuln.get("tools_used") or "METATRON Core"), "Validação:", "CONFIRMADA COM EVIDÊNCIA REAL"],
        ["Data da Descoberta:", discovery_date, "SHA-256 Evidência:", ev_hash_short]
    ]
    t_meta = Table(overview_data, colWidths=[36 * mm, 54 * mm, 36 * mm, 54 * mm])
    t_meta.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTNAME", (2, 0), (2, -1), "Helvetica-Bold"),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#2c3e50")),
        ("TEXTCOLOR", (2, 0), (2, -1), colors.HexColor("#2c3e50")),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.HexColor("#f8f9fa"), colors.white]),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#e0e0e0")),
        ("PADDING", (0, 0), (-1, -1), 4),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    story.append(t_meta)
    story.append(Spacer(1, 8))

    # 4. Seção: Descrição Técnica
    story.append(Paragraph("1. Descrição Técnica e Superfície de Ataque", section_heading))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#bdc3c7"), spaceAfter=4))
    desc_text = clean_text_for_pdf(vuln.get("description") or "Sem descrição fornecida.")
    for p in desc_text.split("\n\n"):
        story.append(Paragraph(p.strip(), body_style))
    story.append(Spacer(1, 6))

    # 5. Seção: Métricas Detalhadas do CVSS v3.1
    story.append(Paragraph("2. Classificação de Severidade (Métricas CVSS v3.1)", section_heading))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#bdc3c7"), spaceAfter=4))
    parsed_cvss = parse_cvss_vector(vector)
    m = parsed_cvss["metrics"]

    cvss_table_data = [
        ["Métrica", "Sigla", "Valor Selecionado", "Métrica", "Sigla", "Valor Selecionado"],
        ["Vetor de Ataque (AV)", m["AV"]["code"], m["AV"]["label"], "Escopo (S)", m["S"]["code"], m["S"]["label"]],
        ["Complexidade (AC)", m["AC"]["code"], m["AC"]["label"], "Confidencialidade (C)", m["C"]["code"], m["C"]["label"]],
        ["Privilégios Requeridos (PR)", m["PR"]["code"], m["PR"]["label"], "Integridade (I)", m["I"]["code"], m["I"]["label"]],
        ["Interação do Usuário (UI)", m["UI"]["code"], m["UI"]["label"], "Disponibilidade (A)", m["A"]["code"], m["A"]["label"]],
    ]
    t_cvss = Table(cvss_table_data, colWidths=[38 * mm, 12 * mm, 40 * mm, 38 * mm, 12 * mm, 40 * mm])
    t_cvss.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 7.5),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#e0e0e0")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#fdfefe"), colors.white]),
        ("PADDING", (0, 0), (-1, -1), 3),
        ("ALIGN", (1, 0), (1, -1), "CENTER"),
        ("ALIGN", (4, 0), (4, -1), "CENTER"),
    ]))
    story.append(t_cvss)
    story.append(Spacer(1, 6))

    # 6. Seção: Passos para Reprodução
    story.append(Paragraph("3. Passos para Reprodução (Verificação Independente)", section_heading))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#bdc3c7"), spaceAfter=4))
    repro_text = clean_text_for_pdf(vuln.get("reproduction_steps") or "Sem passos detalhados.")
    repro_lines = repro_text.splitlines()
    for line in repro_lines:
        line_clean = line.strip()
        if line_clean:
            if line_clean.startswith("curl") or line_clean.startswith("nmap") or line_clean.startswith("openssl") or line_clean.startswith("dig"):
                story.append(Paragraph(f"<code>{line_clean}</code>", code_block))
            else:
                story.append(Paragraph(line_clean, body_style))
    story.append(Spacer(1, 6))

    # 7. Seção: Análise de Impacto
    story.append(Paragraph("4. Análise de Impacto Técnico e de Negócio", section_heading))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#bdc3c7"), spaceAfter=4))
    impact_text = clean_text_for_pdf(vuln.get("technical_impact") or "Impacto não documentado.")
    for p in impact_text.split("\n\n"):
        story.append(Paragraph(p.strip(), body_style))
    story.append(Spacer(1, 6))

    # 8. Seção: Evidências Técnicas Coletadas
    story.append(Paragraph("5. Evidências Técnicas Coletadas (Proof-of-Concept)", section_heading))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#bdc3c7"), spaceAfter=4))

    raw_ev = vuln.get("raw_evidence") or "Nenhuma saída bruta arquivada."
    # Trunca com segurança se for gigantesco para não estourar páginas
    if len(raw_ev) > 3000:
        raw_ev = raw_ev[:3000] + "\n\n[... EVIDÊNCIA TRUNCADA PARA EXIBIÇÃO NO RELATÓRIO ...]"

    ev_clean = clean_text_for_pdf(raw_ev).replace("\n", "<br/>").replace(" ", "&nbsp;")
    story.append(Paragraph(f"<b>Hash de Integridade (SHA-256):</b> <code>{ev_hash}</code>", body_style))
    story.append(Paragraph(ev_clean, code_block))
    story.append(Spacer(1, 6))

    # 9. Seção: Correção Recomendada e Guia de Remediação
    story.append(Paragraph("6. Correção Recomendada e Passos de Remediação", section_heading))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#bdc3c7"), spaceAfter=4))
    rem_text = clean_text_for_pdf(vuln.get("remediation") or "Sem recomendação cadastrada.")
    for p in rem_text.split("\n\n"):
        story.append(Paragraph(p.strip(), body_style))
    story.append(Spacer(1, 6))

    # 10. Seção: Ferramentas e Auditoria
    story.append(Paragraph("7. Ferramentas Utilizadas & Trilha de Auditoria", section_heading))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#bdc3c7"), spaceAfter=4))
    audit_text = (
        f"<b>Ferramentas do Ambiente:</b> {clean_text_for_pdf(vuln.get('tools_used') or 'N/A')}<br/>"
        f"<b>Plataforma de Execução:</b> Arch Linux (pacman nativo)<br/>"
        f"<b>Critério de Validação:</b> Ativo / Passivo Reproduzível (Sem falsos positivos / hipóteses)"
    )
    story.append(Paragraph(audit_text, body_style))
    story.append(Spacer(1, 6))

    # 11. Seção Opcional: Análise Cognitiva da IA Local (se disponível)
    llm_insights = vuln.get("llm_insights")
    if llm_insights:
        story.append(Paragraph("8. Análise Cognitiva Avançada (METATRON AI)", section_heading))
        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#bdc3c7"), spaceAfter=4))
        story.append(Paragraph(clean_text_for_pdf(llm_insights).replace("\n", "<br/>"), body_style))
        story.append(Spacer(1, 6))

    story.append(Spacer(1, 4))

    # Constrói o PDF com numeração dinâmica
    doc.build(story, canvasmaker=NumberedCanvas)
    return filename


def export_all_vulnerabilities_for_session(session_id: int, output_dir: str = "reports") -> List[str]:
    """
    Gera um PDF independente para CADA vulnerabilidade validada da sessão.
    Retorna a lista com os caminhos dos PDFs gerados.
    Exemplo: 5 vulnerabilidades validadas = 5 arquivos PDF gerados.
    """
    vulns = get_vulnerabilities(session_id)
    generated_files = []
    for v in vulns:
        pdf_path = export_vulnerability_pdf(v["id"], output_dir=output_dir)
        generated_files.append(pdf_path)
    return generated_files


def export_menu(session_data: Dict[str, Any]):
    """Menu interativo de exportação chamado pela CLI metatron.py."""
    session = session_data.get("session") or session_data.get("history")
    if not session:
        print("[!] Dados de sessão inválidos.")
        return

    # Compatibilidade com formatos de dict/tuple
    sl_no = session["id"] if isinstance(session, dict) and "id" in session else session[0]
    target = session["target"] if isinstance(session, dict) and "target" in session else session[1]

    vulns = session_data.get("vulnerabilities") or session_data.get("vulns") or []
    if not vulns:
        print(f"[!] A sessão #{sl_no} ({target}) não possui vulnerabilidades validadas para exportação.")
        return

    print(f"\n\033[33m{'─'*20} EXPORTAR RELATÓRIOS INDIVIDUAIS {'─'*20}\033[0m")
    print(f"Alvo: {target} (Sessão #{sl_no}) | Total de Vulnerabilidades: {len(vulns)}")
    print("  [1] Gerar 1 PDF independente para CADA vulnerabilidade (Recomendado)")
    print("  [2] Selecionar uma vulnerabilidade específica para gerar PDF")
    print("  [3] Voltar")

    choice = input("\nmetatron/export> ").strip()
    if choice == "1":
        print(f"\n[*] Gerando {len(vulns)} relatórios individuais em PDF...")
        files = export_all_vulnerabilities_for_session(sl_no)
        print(f"\n\033[92m[+] {len(files)} PDFs individuais gerados com sucesso no diretório 'reports/':\033[0m")
        for f in files:
            print(f"  • {f}")
    elif choice == "2":
        print("\nVulnerabilidades disponíveis:")
        for v in vulns:
            vid = v["id"] if isinstance(v, dict) else v[0]
            vtitle = v["title"] if isinstance(v, dict) else v[2]
            vsev = v["severity"] if isinstance(v, dict) else v[3]
            print(f"  [{vid}] [{vsev}] {vtitle}")

        sel = input("Digite o ID da vulnerabilidade: ").strip()
        if sel.isdigit():
            try:
                pdf_path = export_vulnerability_pdf(int(sel))
                print(f"\n\033[92m[+] PDF individual gerado com sucesso: {pdf_path}\033[0m")
            except Exception as e:
                print(f"[!] Erro ao gerar PDF: {e}")
        else:
            print("[!] ID inválido.")


if __name__ == "__main__":
    print("[*] Testando módulo export.py...")
    # Se houver vulnerabilidades no banco, testa a exportação da primeira
    from db import get_all_vulnerabilities
    all_v = get_all_vulnerabilities()
    if all_v:
        p = export_vulnerability_pdf(all_v[0]["id"])
        print(f"[+] PDF gerado: {p}")
    else:
        print("[*] Nenhuma vulnerabilidade encontrada para teste.")
