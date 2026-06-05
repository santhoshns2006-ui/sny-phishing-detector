"""
SNY Phishing Detector  v2.0
Founder: Santhosh
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
A heuristic phishing detection engine for URLs and emails.
"""

import re, sys, json, math, time, os, urllib.parse
from datetime import datetime
from dataclasses import dataclass, field
from typing import Optional

# ── ANSI colors ──────────────────────────────────────────────────────────────
R  = "\033[0m"
B  = "\033[1m"
DM = "\033[2m"
IT = "\033[3m"
RD = "\033[91m"
YL = "\033[93m"
GN = "\033[92m"
CY = "\033[96m"
MG = "\033[95m"
BL = "\033[94m"
GR = "\033[90m"
WH = "\033[97m"

# ── Data models ───────────────────────────────────────────────────────────────
@dataclass
class ThreatSignal:
    name: str
    weight: float
    triggered: bool
    detail: str = ""

@dataclass
class ScanResult:
    target: str
    scan_type: str
    score: float
    verdict: str
    signals: list = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    @property
    def triggered_signals(self):
        return [s for s in self.signals if s.triggered]

    def to_dict(self):
        return {
            "target": self.target, "scan_type": self.scan_type,
            "score": round(self.score, 3), "verdict": self.verdict,
            "signals": [{"name": s.name, "weight": s.weight,
                         "triggered": s.triggered, "detail": s.detail} for s in self.signals],
            "timestamp": self.timestamp
        }

# ── URL Analyzer ──────────────────────────────────────────────────────────────
class URLAnalyzer:
    BRAND_KEYWORDS = [
        "paypal","google","amazon","apple","microsoft","facebook","instagram",
        "netflix","bank","chase","wellsfargo","citibank","twitter","linkedin",
        "dropbox","icloud","outlook","office365","ebay","walmart","fedex",
        "ups","usps","irs","dmv","secure","login","signin","account","verify","update","confirm"
    ]
    RISKY_TLDS  = {".tk",".ml",".ga",".cf",".gq",".xyz",".top",".club",".online",
                   ".site",".work",".click",".link",".bid",".win",".review",".loan",".download",".stream"}
    URL_SHORTENERS = {"bit.ly","tinyurl.com","t.co","ow.ly","goo.gl","short.link",
                      "rebrand.ly","lnkd.in","is.gd","buff.ly"}

    def analyze(self, url: str) -> ScanResult:
        url = url.strip()
        if not url.startswith(("http://","https://")):
            url = "http://" + url
        try:
            parsed   = urllib.parse.urlparse(url)
            hostname = parsed.hostname or ""
            path     = parsed.path or ""
        except Exception:
            hostname = ""; path = ""

        parts      = hostname.split(".")
        tld        = "." + parts[-1] if parts else ""
        subdomain  = ".".join(parts[:-2]) if len(parts) > 2 else ""
        base_domain= ".".join(parts[-2:]) if len(parts) >= 2 else hostname

        signals = []
        def add(name, weight, triggered, detail=""):
            signals.append(ThreatSignal(name, weight, triggered, detail))

        add("No HTTPS / insecure connection",        0.15, not url.startswith("https://"),
            "HTTP sites don't encrypt traffic — phishing sites skip SSL")
        add("IP address used instead of domain",     0.25, bool(re.match(r"^(\d{1,3}\.){3}\d{1,3}$", hostname)),
            f"Host is '{hostname}' — real sites use domain names")
        add(f"High-risk TLD  ({tld})",               0.20, tld in self.RISKY_TLDS,
            "This TLD is heavily abused in phishing campaigns")
        add("URL shortener detected",                0.20, base_domain in self.URL_SHORTENERS,
            f"'{base_domain}' hides the real destination URL")
        brand_sub = any(b in subdomain.lower() for b in self.BRAND_KEYWORDS)
        add("Brand keyword in subdomain",            0.30, brand_sub,
            f"Subdomain '{subdomain}' contains a brand name — classic spoofing")
        add("Excessive subdomain depth  (≥4 labels)",0.15, len(parts) >= 4,
            f"Hostname has {len(parts)} labels; legitimate sites rarely exceed 3")
        add("@ symbol in URL",                       0.25, "@" in url,
            "Everything before '@' is ignored by browsers — a known obfuscation trick")
        kws  = ["login","signin","bank","verify","secure","account","update","password","credential","auth"]
        hits = [k for k in kws if k in path.lower()]
        add("Sensitive keywords in URL path",        0.15, bool(hits), f"Found: {', '.join(hits)}")
        add("Unusually long URL  (>75 chars)",       0.10, len(url) > 75, f"{len(url)} characters")
        ts = re.search(r"(paypa1|g[o0][o0]gle|amaz[o0]n|micr[o0]s[o0]ft|faceb[o0][o0]k|appl[3e]|tw[i1]tter)",
                       hostname.lower())
        add("Typosquatting pattern",                 0.35, bool(ts),
            f"Match: '{ts.group()}' — character-substituted brand name" if ts else "")
        add("IDN / Punycode domain  (homograph risk)",0.30, "xn--" in hostname.lower(),
            "Internationalized domains can visually mimic legit sites")
        ent = self._entropy(parts[-2] if len(parts) >= 2 else hostname)
        add("High domain entropy  (random-looking)", 0.15, ent > 3.5,
            f"Entropy = {ent:.2f} bits — typical of auto-generated phishing domains")

        score   = self._score(signals)
        verdict = self._verdict(score)
        return ScanResult(target=url, scan_type="url", score=score, verdict=verdict, signals=signals)

    @staticmethod
    def _entropy(s):
        if not s: return 0.0
        freq = {}
        for c in s: freq[c] = freq.get(c, 0) + 1
        n = len(s)
        return -sum((v/n)*math.log2(v/n) for v in freq.values())

    @staticmethod
    def _score(signals):
        total   = sum(s.weight for s in signals)
        trig    = sum(s.weight for s in signals if s.triggered)
        crit    = {"Typosquatting pattern","IP address used instead of domain","Brand keyword in subdomain"}
        boost   = min(sum(1 for s in signals if s.triggered and s.name.split("  ")[0].strip() in crit) * 0.10, 0.25)
        return min((trig/total if total else 0) + boost, 1.0)

    @staticmethod
    def _verdict(score):
        return "PHISHING" if score >= 0.55 else "SUSPICIOUS" if score >= 0.25 else "SAFE"


# ── Email Analyzer ────────────────────────────────────────────────────────────
class EmailAnalyzer:
    PHISHING_PHRASES = [
        "verify your account","confirm your identity","update your information",
        "click here immediately","urgent action required","your account has been suspended",
        "login to your account","congratulations you won","claim your prize",
        "security alert","unusual activity","your password has expired",
        "submit your credentials","validate your details","we detected suspicious",
        "dear customer","dear user","dear valued member","final notice",
        "limited time offer","act now","no credit card","risk-free"
    ]

    def analyze(self, raw: str) -> ScanResult:
        lower = raw.lower()
        signals = []
        def add(name, weight, triggered, detail=""):
            signals.append(ThreatSignal(name, weight, triggered, detail))

        from_line  = (re.search(r"from\s*:\s*(.+)", raw, re.I) or ["",""])[0]
        from_line  = re.search(r"from\s*:\s*(.+)", raw, re.I)
        from_line  = from_line.group(1).strip() if from_line else ""
        reply_line = re.search(r"reply-to\s*:\s*(.+)", raw, re.I)
        reply_line = reply_line.group(1).strip() if reply_line else ""

        display_spoof = bool(re.search(r'"[^"]*"\s*<[^>]+>', from_line)) and \
                        any(b in from_line.lower() for b in URLAnalyzer.BRAND_KEYWORDS)
        add("Display name spoofing a brand",              0.30, display_spoof,
            f"From: {from_line[:70]}")

        from_dom  = (re.search(r"@([\w.\-]+)", from_line)  or [None,None])[1]  if from_line  else None
        reply_dom = (re.search(r"@([\w.\-]+)", reply_line) or [None,None])[1] if reply_line else None
        from_dom  = re.search(r"@([\w.\-]+)", from_line);  from_dom  = from_dom.group(1)  if from_dom  else None
        reply_dom = re.search(r"@([\w.\-]+)", reply_line); reply_dom = reply_dom.group(1) if reply_dom else None
        add("Reply-To domain differs from From domain",   0.30,
            bool(from_dom and reply_dom and from_dom != reply_dom),
            f"From: {from_dom or '?'}  →  Reply-To: {reply_dom or '?'}")

        has_auth = bool(re.search(r"(authentication-results|dkim-signature|received-spf)", raw, re.I))
        add("Missing SPF / DKIM / DMARC authentication",  0.20, not has_auth,
            "Legitimate bulk email always includes auth headers")

        urgency_words = ["urgent","immediately","asap","act now","expires today",
                         "within 24 hours","respond now","final notice","last chance"]
        uhits = [w for w in urgency_words if w in lower]
        add("Urgency / pressure language",                0.15, bool(uhits),
            f"Phrases: {', '.join(uhits[:3])}")

        phits = [p for p in self.PHISHING_PHRASES if p in lower]
        add("Known phishing phrases detected",            0.25, bool(phits),
            f"{len(phits)} found: {', '.join(phits[:2])}")

        links = re.findall(r"https?://[^\s\"'<>]+", raw)
        ua    = URLAnalyzer()
        bad   = [(l[:55], ua.analyze(l).verdict) for l in links[:5]
                 if ua.analyze(l).verdict in ("PHISHING","SUSPICIOUS")]
        add("Suspicious / phishing URLs in body",         0.35, bool(bad),
            f"{len(bad)} bad link(s): " + "; ".join(f"{u} [{v}]" for u,v in bad[:2]))

        pairs    = re.findall(r'href=["\']([^"\']+)["\'][^>]*>([^<]+)<', raw, re.I)
        mismatch = [(h,t) for h,t in pairs
                    if t.startswith("http") and
                    (urllib.parse.urlparse(t).hostname or "") != (urllib.parse.urlparse(h).hostname or "")]
        add("Misleading link text  (href ≠ display text)",0.25, bool(mismatch),
            f"Display: '{mismatch[0][1][:35]}' → Href: '{mismatch[0][0][:35]}'" if mismatch else "")

        has_html  = bool(re.search(r"<html|<body", raw, re.I))
        has_plain = "content-type: text/plain" in lower
        add("HTML-only email  (no plain text part)",      0.10, has_html and not has_plain,
            "Phishing uses HTML-only for richer deceptive formatting")

        add("Generic / impersonal salutation",            0.10,
            bool(re.search(r"\bdear\s+(customer|user|member|client|valued)\b", lower, re.I)),
            "Legitimate orgs address you by name")

        exclaim = raw.count("!")
        add("Excessive exclamation marks",                0.05, exclaim > 3,
            f"{exclaim} exclamation marks found")

        score   = URLAnalyzer._score(signals)
        verdict = URLAnalyzer._verdict(score)
        return ScanResult(target=from_line or "(unknown sender)", scan_type="email",
                          score=score, verdict=verdict, signals=signals)


# ── Helpers ───────────────────────────────────────────────────────────────────
def is_url(inp: str) -> bool:
    return (
        inp.startswith(("http://","https://","ftp://","www.")) or
        bool(re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61})?(\.[a-zA-Z]{2,})+(/\S*)?$", inp))
    )

def is_email_content(inp: str) -> bool:
    has_from    = bool(re.search(r"^from\s*:",    inp, re.M|re.I))
    has_subject = bool(re.search(r"^subject\s*:", inp, re.M|re.I))
    has_at      = bool(re.search(r"[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}", inp.lower()))
    has_headers = bool(re.search(r"^(reply-to|dkim|received|content-type)\s*:", inp, re.M|re.I))
    return has_from or (has_subject and has_at) or (has_headers and has_at)


# ── UI ────────────────────────────────────────────────────────────────────────
def cls():
    os.system("cls" if os.name == "nt" else "clear")

def banner():
    print(f"""
{CY}╔══════════════════════════════════════════════════════════════════════════╗
║                                                                          ║
║   {B}{WH} ███████╗███╗  ██╗██╗   ██╗     {CY}                                      ║
║   {B}{WH} ██╔════╝████╗ ██║╚██╗ ██╔╝     {CY}                                      ║
║   {B}{WH} ███████╗██╔██╗██║ ╚████╔╝      {CY}  {WH}Phishing & Email Detector  v2.0 {CY}  ║
║   {B}{WH} ╚════██║██║╚████║  ╚██╔╝       {CY}  {DM}Heuristic · Multi-signal · Fast {R}{CY}  ║
║   {B}{WH} ███████║██║ ╚███║   ██║        {CY}                                      ║
║   {B}{WH} ╚══════╝╚═╝  ╚══╝   ╚═╝        {CY}  {GR}founder: {MG}Santhosh{CY}               ║
║                                                                          ║
╚══════════════════════════════════════════════════════════════════════════╝{R}""")

def divider(label="", color=GR):
    w = 72
    if label:
        pad = (w - len(label) - 2) // 2
        print(f"  {color}{'─'*pad} {WH}{B}{label}{R} {color}{'─'*pad}{R}")
    else:
        print(f"  {color}{'─'*w}{R}")

def spinner(msg="Scanning"):
    frames = ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"]
    for i in range(14):
        print(f"\r  {CY}{frames[i%len(frames)]}{R}  {DM}{msg}...{R}", end="", flush=True)
        time.sleep(0.05)
    print("\r" + " "*40 + "\r", end="")

def print_result(result: ScanResult):
    vc = RD if result.verdict == "PHISHING" else YL if result.verdict == "SUSPICIOUS" else GN
    vi = "✗" if result.verdict == "PHISHING" else "⚡" if result.verdict == "SUSPICIOUS" else "✓"
    pct = int(result.score * 100)
    bar_len = int(result.score * 36)
    bar = f"{vc}{'█'*bar_len}{GR}{'░'*(36-bar_len)}{R}"

    divider()
    print(f"  {CY}{B}SNY DETECTOR{R}  {GR}│{R}  {B}{result.scan_type.upper()} ANALYSIS{R}  {GR}│{R}  {DM}{result.timestamp}{R}")
    divider()
    print(f"  {GR}target  {R}{DM}{result.target[:62]}{R}")
    print(f"  {GR}score   {R}{bar}  {vc}{B}{pct}%{R}")
    print(f"  {GR}verdict {R}{vc}{B} {vi} {result.verdict}{R}")
    divider()

    triggered = result.triggered_signals
    if triggered:
        print(f"\n  {RD}{B}⚠  {len(triggered)} threat signal{'s' if len(triggered)>1 else ''} fired:{R}\n")
        for s in triggered:
            w_bar = f"{RD}{'▮'*int(s.weight*10)}{GR}{'▯'*(10-int(s.weight*10))}{R}"
            print(f"  {RD} ▸{R} {B}{s.name}{R}  {w_bar}  {GR}{s.weight:.0%}{R}")
            if s.detail:
                print(f"      {DM}{IT}{s.detail[:70]}{R}")
        print(f"\n  {GR}  {len(result.signals)-len(triggered)} checks passed silently{R}")
    else:
        print(f"\n  {GN}{B}✓  All {len(result.signals)} checks passed — target appears safe{R}")

    divider()
    print()

def print_stats(results: list[ScanResult]):
    if not results:
        print(f"\n  {YL}  No scans recorded yet.{R}\n"); return
    total    = len(results)
    phishing = sum(1 for r in results if r.verdict=="PHISHING")
    susp     = sum(1 for r in results if r.verdict=="SUSPICIOUS")
    safe     = sum(1 for r in results if r.verdict=="SAFE")
    avg_score= sum(r.score for r in results)/total
    divider("SESSION STATS", CY)
    print(f"  {GR}total scans   {R}  {B}{total}{R}")
    print(f"  {RD}phishing      {R}  {B}{phishing}{R}  {GR}({phishing/total:.0%}){R}")
    print(f"  {YL}suspicious    {R}  {B}{susp}{R}  {GR}({susp/total:.0%}){R}")
    print(f"  {GN}safe          {R}  {B}{safe}{R}  {GR}({safe/total:.0%}){R}")
    print(f"  {CY}avg score     {R}  {B}{avg_score:.1%}{R}")
    divider()
    print()

def print_history(results: list[ScanResult]):
    if not results:
        print(f"\n  {YL}  No history yet.{R}\n"); return
    divider("SCAN HISTORY", CY)
    for i, r in enumerate(results[-10:], 1):
        vc = RD if r.verdict=="PHISHING" else YL if r.verdict=="SUSPICIOUS" else GN
        vi = "✗" if r.verdict=="PHISHING" else "⚡" if r.verdict=="SUSPICIOUS" else "✓"
        short = r.target[:45] + ("…" if len(r.target)>45 else "")
        print(f"  {GR}{i:2}.{R}  {vc}{vi}{R}  {DM}{r.scan_type:5}{R}  {GR}{r.score:.0%}{R}  {short}")
    divider()
    print()

def print_tips():
    divider("SECURITY TIPS", MG)
    tips = [
        ("Check the domain",      "Hover over links before clicking. Real PayPal is paypal.com, not paypal-secure.tk"),
        ("Look for HTTPS",        "Padlock icon + https:// = encrypted. Missing it? Danger sign."),
        ("Inspect headers",       "Gmail → ⋮ → Show original — look for SPF/DKIM/DMARC pass results"),
        ("Beware urgency",        "Fake emails pressure you with '24-hour deadlines' and 'account suspended' threats"),
        ("Check sender address",  "Display name can say anything. Always verify the actual @domain."),
        ("Don't enter creds",     "Never enter passwords on a page you reached via an email link"),
        ("Use 2FA everywhere",    "Even if credentials are stolen, 2FA blocks the attacker"),
        ("Report phishing",       "Gmail: Report phishing. Outlook: Report as junk → phishing scam"),
    ]
    for title, tip in tips:
        print(f"  {MG} ›{R}  {B}{title}{R}")
        print(f"      {DM}{tip}{R}")
    divider()
    print()

def help_text():
    divider("COMMANDS", CY)
    cmds = [
        ("scan url <url>",  "Analyze a URL — type it inline or be prompted"),
        ("scan email",      "Enter multi-line email paste mode (press Enter twice to finish)"),
        ("history",         "Show last 10 scans this session"),
        ("stats",           "Session statistics — totals, verdicts, average score"),
        ("tips",            "Security tips to stay safe from phishing"),
        ("json",            "Toggle JSON output mode on/off"),
        ("export",          "Save this session's results to results.json"),
        ("clear",           "Clear screen and redraw banner"),
        ("help",            "Show this help"),
        ("quit / exit",     "Exit SNY Detector"),
    ]
    for cmd, desc in cmds:
        print(f"  {CY}  {cmd:<20}{R}  {desc}")
    print(f"\n  {DM}  Tip: You can also type a URL directly — it auto-detects!{R}")
    divider()
    print()

def collect_multiline() -> str:
    print(f"\n  {CY}[EMAIL PASTE MODE]{R}  Paste raw email below.")
    print(f"  {DM}  Include From/Reply-To/Subject headers + body for best results.")
    print(f"  {DM}  Gmail → ⋮ → 'Show original' to copy full raw email.{R}")
    print(f"  {DM}  Press {B}Enter twice{DM} when done.{R}\n")
    lines, blanks = [], 0
    while True:
        try:
            line = input()
        except (EOFError, KeyboardInterrupt):
            break
        if line == "":
            blanks += 1
            if blanks >= 2: break
            lines.append(line)
        else:
            blanks = 0
            lines.append(line)
    return "\n".join(lines).strip()


# ── Main loop ─────────────────────────────────────────────────────────────────
def main():
    banner()
    print(f"  {GR}Type {CY}help{GR} to see all commands. Type {CY}quit{GR} to exit.{R}\n")

    ua      = URLAnalyzer()
    ea      = EmailAnalyzer()
    history = []
    output_json = False

    while True:
        try:
            inp = input(f"  {CY}sny{R}{GR}›{R} ").strip()
        except (EOFError, KeyboardInterrupt):
            print(f"\n  {GR}Stay secure. — Santhosh{R}\n"); break

        if not inp:
            continue

        cmd = inp.lower()

        if cmd in ("quit","exit"):
            print(f"\n  {GN}✓  Exiting SNY Detector. Stay secure. — {MG}Santhosh{R}\n"); break

        elif cmd == "help":
            help_text()

        elif cmd == "clear":
            cls(); banner()
            print(f"  {GR}Type {CY}help{GR} for commands.{R}\n")

        elif cmd == "json":
            output_json = not output_json
            state = f"{GN}ON{R}" if output_json else f"{GR}OFF{R}"
            print(f"\n  {CY}JSON mode: {state}\n")

        elif cmd == "history":
            print_history(history)

        elif cmd == "stats":
            print_stats(history)

        elif cmd == "tips":
            print_tips()

        elif cmd == "export":
            fname = f"sny_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(fname, "w") as f:
                json.dump([r.to_dict() for r in history], f, indent=2)
            print(f"\n  {GN}✓  Exported {len(history)} result(s) to {B}{fname}{R}\n")

        elif cmd.startswith("scan url"):
            parts   = inp.split(None, 2)
            url_val = parts[2].strip() if len(parts) > 2 else input(f"  {GR}URL: {R}").strip()
            if url_val:
                spinner("Scanning URL")
                result = ua.analyze(url_val)
                history.append(result)
                if output_json: print(json.dumps(result.to_dict(), indent=2))
                else: print_result(result)

        elif cmd.startswith("scan email") or cmd == "scan":
            raw = collect_multiline()
            if not raw:
                print(f"\n  {YL}  ⚠  Nothing pasted.{R}\n"); continue
            if not is_email_content(raw):
                print(f"\n  {RD}  ✗  Doesn't look like a valid email.{R}")
                print(f"  {DM}     Make sure to include From: / Subject: headers.{R}")
                print(f"  {DM}     Gmail → ⋮ → 'Show original' for full raw email.{R}\n")
                continue
            spinner("Analyzing email")
            result = ea.analyze(raw)
            history.append(result)
            if output_json: print(json.dumps(result.to_dict(), indent=2))
            else: print_result(result)

        elif is_url(inp):
            spinner("Scanning URL")
            result = ua.analyze(inp)
            history.append(result)
            if output_json: print(json.dumps(result.to_dict(), indent=2))
            else: print_result(result)

        elif is_email_content(inp):
            spinner("Analyzing email")
            result = ea.analyze(inp)
            history.append(result)
            if output_json: print(json.dumps(result.to_dict(), indent=2))
            else: print_result(result)

        else:
            print(f"\n  {YL}  ?  Unknown command.{R}  Type {CY}help{R} to see all commands.")
            print(f"  {DM}     To scan a URL, type it directly.")
            print(f"  {DM}     To scan an email, use: {R}{CY}scan email{R}\n")


if __name__ == "__main__":
    main()
