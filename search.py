#!/usr/bin/env python3
"""
METATRON - search.py
Busca web gratuita via DuckDuckGo — sem chave de API necessária.
Também busca e extrai texto simples de URLs.
Usado pelo dispatch de ferramentas da LLM quando a IA escreve [SEARCH: query]
"""

import requests
from bs4 import BeautifulSoup
from ddgs import DDGS   # pip install duckduckgo-search


# ─────────────────────────────────────────────
# DDG SEARCH
# ─────────────────────────────────────────────

def web_search(query: str, max_results: int = 5) -> str:
    """
    Pesquisa DuckDuckGo e retorna resultados formatados.
    Sem chave de API. Sem problemas de limite de taxa para uso razoável.
    Retorna uma string pronta para colar no prompt da LLM.
    """
    print(f"  [*] Pesquisando: {query}")
    try:
        with DDGS() as ddgs:
            results = list(ddgs.text(query, max_results=max_results))

        if not results:
            return "[!] Nenhum resultado de busca encontrado."

        output = f"[RESULTADOS DE BUSCA WEB PARA: {query}]\n"
        output += "─" * 50 + "\n"
        for i, r in enumerate(results, 1):
            output += f"\n[{i}] {r['title']}\n"
            output += f"    URL     : {r['href']}\n"
            output += f"    Trecho : {r['body']}\n"

        return output

    except Exception as e:
        return f"[!] Busca falhou: {e}"


# ─────────────────────────────────────────────
# CVE SPECIFIC SEARCH
# ─────────────────────────────────────────────

def search_cve(cve_id: str) -> str:
    """
    Pesquisa por um CVE específico.
    Consulta DDG e depois acessa cve.mitre.org diretamente.
    """
    print(f"  [*] Looking up {cve_id}...")

    # DDG search first
    ddg_results = web_search(f"{cve_id} vulnerability exploit details", max_results=3)

    # Direct MITRE fetch
    mitre_url = f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}"
    mitre_data = fetch_page(mitre_url, max_chars=2000)

    return f"{ddg_results}\n\n[BUSCA CVE MITRE: {cve_id}]\n{mitre_data}"


def search_exploit(service: str, version: str) -> str:
    """
    Pesquisa por exploits conhecidos para uma combinação de serviço + versão.
    ex: search_exploit("apache", "2.4.49")
    """
    query = f"{service} {version} exploit CVE vulnerability 2023 2024"
    return web_search(query, max_results=5)


def search_fix(vuln_name: str) -> str:
    """
    Pesquisa por mitigação/correção de uma vulnerabilidade.
    """
    query = f"how to fix {vuln_name} security mitigation patch"
    return web_search(query, max_results=3)


# ─────────────────────────────────────────────
# PAGE FETCHER
# ─────────────────────────────────────────────

def fetch_page(url: str, max_chars: int = 3000) -> str:
    """
    Busca uma URL e retorna texto simples extraído.
    Remove todas as tags HTML. Truncado para max_chars para contexto de LLM.
    """
    try:
        headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/120.0"}
        resp = requests.get(url, headers=headers, timeout=15)
        resp.raise_for_status()

        soup = BeautifulSoup(resp.text, "html.parser")

        # remove nav/footer/script noise
        for tag in soup(["script", "style", "nav", "footer", "header", "aside"]):
            tag.decompose()

        text = soup.get_text(separator="\n", strip=True)

        # collapse blank lines
        lines = [l for l in text.splitlines() if l.strip()]
        clean = "\n".join(lines)

        if len(clean) > max_chars:
            clean = clean[:max_chars] + f"\n... [truncated at {max_chars} chars]"

        return clean

    except requests.exceptions.ConnectionError:
        return "[!] Could not connect to URL — check network."
    except requests.exceptions.Timeout:
        return "[!] Page fetch timed out."
    except requests.exceptions.HTTPError as e:
        return f"[!] HTTP error: {e}"
    except Exception as e:
        return f"[!] Fetch failed: {e}"


# ─────────────────────────────────────────────
# TOOL DISPATCH HANDLER
# ─────────────────────────────────────────────

def handle_search_dispatch(query: str) -> str:
    """
    Called by llm.py when AI writes [SEARCH: something].
    Smartly routes to CVE lookup, exploit search, or general search.
    """
    query = query.strip()

    # CVE pattern — CVE-YYYY-NNNNN
    import re
    cve_pattern = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)
    cve_match = cve_pattern.search(query)
    if cve_match:
        return search_cve(cve_match.group())

    # exploit keywords
    if any(word in query.lower() for word in ["exploit", "poc", "payload", "rce", "lfi", "sqli"]):
        return web_search(query + " exploit poc github", max_results=5)

    # fix/patch keywords
    if any(word in query.lower() for word in ["fix", "patch", "mitigate", "harden", "secure"]):
        return search_fix(query)

    # default general search
    return web_search(query, max_results=5)


# ─────────────────────────────────────────────
# QUICK TEST
# ─────────────────────────────────────────────

if __name__ == "__main__":
    print("[ search.py test ]\n")
    print("[1] General search")
    print("[2] CVE lookup")
    print("[3] Fetch a URL")
    choice = input("Choice: ").strip()

    if choice == "1":
        q = input("Query: ").strip()
        print(web_search(q))

    elif choice == "2":
        cve = input("CVE ID (e.g. CVE-2021-44228): ").strip()
        print(search_cve(cve))

    elif choice == "3":
        url = input("URL: ").strip()
        print(fetch_page(url))
