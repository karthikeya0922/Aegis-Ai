"""Generates the Aegis pitch deck (Team Future Bytes) as a native .pptx.

Content follows the outline the team supplied; phrasing is tightened where it
touches claims the rest of the project is careful about (e.g. "exact secrets"
-> "known-pattern secrets", "100% uptime" -> "automated failover", since the
backend's own honesty rules disclaim absolute guarantees -- see
docs/AEGIS_PROBLEM_STATEMENT.md section 11).

Run:
    python presentation/generate_deck.py

Output:
    presentation/Aegis_Future_Bytes.pptx
"""

from __future__ import annotations

from pathlib import Path

from pptx import Presentation
from pptx.util import Inches, Pt, Emu
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN, MSO_ANCHOR
from pptx.enum.shapes import MSO_SHAPE
from pptx.oxml.ns import qn

OUT = Path(__file__).resolve().parent / "Aegis_Future_Bytes.pptx"

# --- palette ----------------------------------------------------------------
NAVY = RGBColor(0x0B, 0x12, 0x27)      # deep background / header bar
NAVY_2 = RGBColor(0x11, 0x1C, 0x3A)    # secondary panel
INK = RGBColor(0x1E, 0x29, 0x3B)       # body text on white
SLATE = RGBColor(0x47, 0x55, 0x69)     # secondary text
CYAN = RGBColor(0x06, 0xB6, 0xD4)      # primary accent
CYAN_DK = RGBColor(0x0E, 0x74, 0x90)
AMBER = RGBColor(0xF5, 0x9E, 0x0B)     # warning / secondary accent
WHITE = RGBColor(0xFF, 0xFF, 0xFF)
FAINT = RGBColor(0xE2, 0xE8, 0xF0)
GREEN = RGBColor(0x10, 0xB9, 0x81)

FONT = "Segoe UI"
FONT_SEMIBOLD = "Segoe UI Semibold"

SLIDE_W = Inches(13.333)
SLIDE_H = Inches(7.5)


def new_deck() -> Presentation:
    prs = Presentation()
    prs.slide_width = SLIDE_W
    prs.slide_height = SLIDE_H
    return prs


def blank_slide(prs: Presentation):
    return prs.slides.add_slide(prs.slide_layouts[6])  # fully blank


def set_fill(shape, color: RGBColor):
    shape.fill.solid()
    shape.fill.fore_color.rgb = color
    shape.line.fill.background()


def no_shadow(shape):
    el = shape._element.spPr
    existing = el.find(qn("a:effectLst"))
    if existing is None:
        from pptx.oxml.ns import nsmap
        import lxml.etree as etree
        eff = etree.SubElement(el, qn("a:effectLst"))
    return shape


def rect(slide, x, y, w, h, color=None):
    shp = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, x, y, w, h)
    shp.shadow.inherit = False
    if color is not None:
        set_fill(shp, color)
    else:
        shp.fill.background()
        shp.line.fill.background()
    return shp


def textbox(slide, x, y, w, h, anchor=MSO_ANCHOR.TOP):
    tb = slide.shapes.add_textbox(x, y, w, h)
    tf = tb.text_frame
    tf.word_wrap = True
    tf.vertical_anchor = anchor
    tf.margin_left = 0
    tf.margin_right = 0
    tf.margin_top = 0
    tf.margin_bottom = 0
    return tb, tf


def set_run(run, text, size, color, bold=False, italic=False, font=FONT):
    run.text = text
    run.font.size = Pt(size)
    run.font.color.rgb = color
    run.font.bold = bold
    run.font.italic = italic
    run.font.name = font


def footer(slide, index: int, total: int, label: str = "AEGIS  ·  Zero-Trust Responsible AI Gateway"):
    rect(slide, 0, SLIDE_H - Inches(0.32), SLIDE_W, Inches(0.32), NAVY)
    _, tf = textbox(slide, Inches(0.5), SLIDE_H - Inches(0.32), Inches(8), Inches(0.32), MSO_ANCHOR.MIDDLE)
    p = tf.paragraphs[0]
    r = p.add_run()
    set_run(r, label, 10, RGBColor(0x9C, 0xA9, 0xBD))

    _, tf2 = textbox(slide, SLIDE_W - Inches(2.0), SLIDE_H - Inches(0.32), Inches(1.5), Inches(0.32), MSO_ANCHOR.MIDDLE)
    p2 = tf2.paragraphs[0]
    p2.alignment = PP_ALIGN.RIGHT
    r2 = p2.add_run()
    set_run(r2, f"{index:02d} / {total:02d}", 10, RGBColor(0x9C, 0xA9, 0xBD))


def header_bar(slide, kicker: str, title: str, bar_color=NAVY):
    rect(slide, 0, 0, SLIDE_W, Inches(1.35), bar_color)
    rect(slide, 0, Inches(1.35), SLIDE_W, Pt(3), CYAN)

    _, tf_k = textbox(slide, Inches(0.6), Inches(0.28), Inches(11), Inches(0.4))
    p = tf_k.paragraphs[0]
    r = p.add_run()
    set_run(r, kicker.upper(), 13, CYAN, bold=True)
    _set_letter_spacing(r, 200)

    _, tf_t = textbox(slide, Inches(0.6), Inches(0.62), Inches(12.0), Inches(0.65))
    p2 = tf_t.paragraphs[0]
    r2 = p2.add_run()
    set_run(r2, title, 30, WHITE, bold=True)


def _set_letter_spacing(run, val_hundredths_pt: int):
    rPr = run._r.get_or_add_rPr()
    rPr.set("spc", str(val_hundredths_pt))


def bullet_block(slide, x, y, w, lead: str, body: str, lead_color=NAVY, body_color=SLATE,
                  lead_size=15, body_size=13, gap_after=Pt(14), dot_color=CYAN):
    """One feature line: coloured dot, bold lead phrase, then description."""
    dot = slide.shapes.add_shape(MSO_SHAPE.OVAL, x, y + Pt(6), Pt(9), Pt(9))
    set_fill(dot, dot_color)

    tb, tf = textbox(slide, x + Inches(0.28), y - Pt(2), w - Inches(0.28), Inches(1.2))
    p = tf.paragraphs[0]
    p.line_spacing = 1.18
    r1 = p.add_run()
    set_run(r1, lead, lead_size, lead_color, bold=True, font=FONT_SEMIBOLD)
    r2 = p.add_run()
    set_run(r2, "  " + body, body_size, body_color)
    return tb


def stat_chip(slide, x, y, w, h, big_text, small_text, accent=CYAN):
    box = rect(slide, x, y, w, h, RGBColor(0xF4, 0xF7, 0xFB))
    box.line.color.rgb = RGBColor(0xE1, 0xE7, 0xEF)
    box.line.width = Pt(0.75)
    bar = rect(slide, x, y, Pt(4), h, accent)

    _, tf = textbox(slide, x + Inches(0.22), y + Inches(0.12), w - Inches(0.4), h - Inches(0.24), MSO_ANCHOR.MIDDLE)
    p1 = tf.paragraphs[0]
    r1 = p1.add_run()
    set_run(r1, big_text, 22, NAVY, bold=True)
    p2 = tf.add_paragraph()
    p2.space_before = Pt(2)
    r2 = p2.add_run()
    set_run(r2, small_text, 11, SLATE)


def pipeline_chip(slide, x, y, w, h, label, accent=CYAN):
    box = rect(slide, x, y, w, h, NAVY_2)
    box.line.color.rgb = accent
    box.line.width = Pt(1)
    _, tf = textbox(slide, x, y, w, h, MSO_ANCHOR.MIDDLE)
    p = tf.paragraphs[0]
    p.alignment = PP_ALIGN.CENTER
    r = p.add_run()
    set_run(r, label, 11.5, WHITE, bold=True)


def arrow(slide, x, y, w, h, color=CYAN):
    shp = slide.shapes.add_shape(MSO_SHAPE.CHEVRON, x, y, w, h)
    set_fill(shp, color)
    return shp


# =============================================================================
prs = new_deck()
TOTAL = 9

# -----------------------------------------------------------------------------
# SLIDE 1 -- Introduction
# -----------------------------------------------------------------------------
s = blank_slide(prs)
rect(s, 0, 0, SLIDE_W, SLIDE_H, NAVY)
rect(s, 0, 0, SLIDE_W, Inches(0.12), CYAN)

# shield-style badge (simple geometric mark, not a photo/logo): a pentagon
# rotated to read as a shield silhouette, with a checkmark accent inside.
shield = s.shapes.add_shape(MSO_SHAPE.PENTAGON, Inches(0.9), Inches(0.8), Inches(1.15), Inches(1.35))
shield.rotation = 180
set_fill(shield, CYAN)
shield.line.color.rgb = WHITE
shield.line.width = Pt(1.5)

check = s.shapes.add_shape(MSO_SHAPE.CHEVRON, Inches(1.18), Inches(1.25), Inches(0.55), Inches(0.55))
check.rotation = 90
set_fill(check, WHITE)

_, tf = textbox(s, Inches(0.6), Inches(2.55), Inches(11.8), Inches(1.3))
p = tf.paragraphs[0]
r = p.add_run(); set_run(r, "AEGIS", 60, WHITE, bold=True, font=FONT_SEMIBOLD)
r2 = p.add_run(); set_run(r2, "  :: Zero-Trust Responsible AI Gateway", 26, CYAN)

_, tf2 = textbox(s, Inches(0.62), Inches(3.55), Inches(11.5), Inches(0.5))
p2 = tf2.paragraphs[0]
r = p2.add_run(); set_run(r, "A Security & Governance Platform Built by Team Future Bytes", 16, FAINT)

# philosophy quote panel
rect(s, Inches(0.6), Inches(4.35), Inches(11.6), Inches(0.9), NAVY_2)
rect(s, Inches(0.6), Inches(4.35), Pt(4), Inches(0.9), AMBER)
_, tfq = textbox(s, Inches(0.95), Inches(4.35), Inches(11.0), Inches(0.9), MSO_ANCHOR.MIDDLE)
pq = tfq.paragraphs[0]
rq = pq.add_run()
set_run(rq, "“ Never trust the user input, and never blindly trust the LLM output. ”", 16, WHITE, italic=True)

# dual layer architecture cards
card_w = Inches(5.55)
card_h = Inches(1.55)
y0 = Inches(5.5)
rect(s, Inches(0.6), y0, card_w, card_h, NAVY_2).line.color.rgb = CYAN
_, tfa = textbox(s, Inches(0.9), y0 + Inches(0.12), card_w - Inches(0.6), card_h - Inches(0.2))
pa = tfa.paragraphs[0]
ra = pa.add_run(); set_run(ra, "THE BRAIN", 12, CYAN, bold=True); _set_letter_spacing(ra, 150)
pa2 = tfa.add_paragraph(); pa2.space_before = Pt(4)
ra2 = pa2.add_run(); set_run(ra2, "Python + FastAPI inspection microservice", 14, WHITE, bold=True)
pa3 = tfa.add_paragraph(); pa3.space_before = Pt(2)
ra3 = pa3.add_run(); set_run(ra3, "Threat detection, NLP analysis, and policy enforcement", 11.5, FAINT)

x1 = Inches(6.75)
rect(s, x1, y0, card_w, card_h, NAVY_2).line.color.rgb = GREEN
_, tfb = textbox(s, x1 + Inches(0.3), y0 + Inches(0.12), card_w - Inches(0.6), card_h - Inches(0.2))
pb = tfb.paragraphs[0]
rb = pb.add_run(); set_run(rb, "THE COCKPIT", 12, GREEN, bold=True); _set_letter_spacing(rb, 150)
pb2 = tfb.add_paragraph(); pb2.space_before = Pt(4)
rb2 = pb2.add_run(); set_run(rb2, "Next.js + TypeScript orchestration layer", 14, WHITE, bold=True)
pb3 = tfb.add_paragraph(); pb3.space_before = Pt(2)
rb3 = pb3.add_run(); set_run(rb3, "API routing, caching, and real-time visual observability", 11.5, FAINT)

_, tff = textbox(s, Inches(0.6), SLIDE_H - Inches(0.5), Inches(6), Inches(0.35))
pf = tff.paragraphs[0]
rf = pf.add_run(); set_run(rf, "Project: Aegis   |   Team: Future Bytes", 11, RGBColor(0x8A, 0x97, 0xAB))

# -----------------------------------------------------------------------------
# SLIDE 2 -- Objectives
# -----------------------------------------------------------------------------
s = blank_slide(prs)
rect(s, 0, 0, SLIDE_W, SLIDE_H, WHITE)
header_bar(s, "Why Aegis Exists", "Project Objectives")

objs = [
    ("Data Loss Prevention", "Guarantee that raw secrets (API keys) and sensitive PII never leave the enterprise boundary unredacted."),
    ("AI Attack Mitigation", "Identify and block known prompt-injection and jailbreak patterns before they reach the LLM."),
    ("Cost & Performance Optimization", "Reduce LLM API bills and response times through semantic caching and complexity-based routing."),
    ("Resilience & Availability", "Keep AI applications responsive through automated failover and circuit breakers across providers."),
    ("Total Transparency", "Give security teams a glass-box dashboard to audit every pipeline decision, in real time and after the fact."),
]

y = Inches(1.75)
for lead, body in objs:
    bullet_block(s, Inches(0.7), y, Inches(11.9), lead, body, lead_size=16, body_size=13.5)
    y += Inches(1.02)

footer(s, 2, TOTAL)

# -----------------------------------------------------------------------------
# Helper for feature slides (3-7): header + bullets + right-side pipeline strip
# -----------------------------------------------------------------------------

def feature_slide(idx, kicker, title, items, pipeline_labels=None, pipeline_caption=None):
    s = blank_slide(prs)
    rect(s, 0, 0, SLIDE_W, SLIDE_H, WHITE)
    header_bar(s, kicker, title)

    content_w = Inches(7.5) if pipeline_labels else Inches(11.9)
    y = Inches(1.8)
    for lead, body in items:
        bullet_block(s, Inches(0.7), y, content_w, lead, body, lead_size=15.5, body_size=13)
        y += Inches(1.12)

    if pipeline_labels:
        panel_x = Inches(8.55)
        rect(s, panel_x, Inches(1.75), Inches(4.15), Inches(4.9), NAVY)
        _, tfp = textbox(s, panel_x + Inches(0.3), Inches(1.95), Inches(3.6), Inches(0.4))
        pp = tfp.paragraphs[0]
        rp = pp.add_run(); set_run(rp, "PIPELINE FLOW", 11, CYAN, bold=True); _set_letter_spacing(rp, 150)

        cy = Inches(2.45)
        for i, label in enumerate(pipeline_labels):
            pipeline_chip(s, panel_x + Inches(0.3), cy, Inches(3.55), Inches(0.55), label,
                          accent=CYAN if i % 2 == 0 else GREEN)
            cy += Inches(0.7)
            if i < len(pipeline_labels) - 1:
                _, tfa = textbox(s, panel_x + Inches(1.6), cy - Inches(0.18), Inches(1.0), Inches(0.2))
                pa = tfa.paragraphs[0]; pa.alignment = PP_ALIGN.CENTER
                ra = pa.add_run(); set_run(ra, "↓", 14, CYAN, bold=True)

        if pipeline_caption:
            _, tfc = textbox(s, panel_x + Inches(0.3), cy + Inches(0.1), Inches(3.55), Inches(0.9))
            pc = tfc.paragraphs[0]
            pc.line_spacing = 1.15
            rc = pc.add_run(); set_run(rc, pipeline_caption, 10.5, FAINT, italic=True)

    footer(s, idx, TOTAL)
    return s


# -----------------------------------------------------------------------------
# SLIDE 3 -- Feature 1: Threat Detection & Redaction
# -----------------------------------------------------------------------------
feature_slide(
    3,
    "Feature 01",
    "Real-Time Threat Detection & Sanitization",
    [
        ("Multi-Vector Scanning", "Scans incoming prompts for PII (emails, phone numbers, IPs, card-like numbers) and pattern-matched secrets (AWS keys, GitHub tokens, database URIs)."),
        ("Dynamic Policy Engine", "Configurable rules resolve each finding to ALLOW, WARN, SANITIZE, or BLOCK -- detection and policy are kept as separate layers."),
        ("Tokenized Redaction", "Swaps sensitive data for safe placeholders (e.g. [AWS_KEY_1], [EMAIL_1]) before the prompt ever reaches the LLM provider."),
        ("Session-Scoped Vault", "Maps placeholders back to original values only for the request's lifetime, in memory/Redis with a short TTL -- secrets are never rehydrated."),
    ],
    pipeline_labels=["Prompt In", "PII Scanner", "Secret Scanner", "Policy Engine", "Sanitized Out"],
    pipeline_caption="Every stage reports a measured duration and a plain-language reason for its decision.",
)

# -----------------------------------------------------------------------------
# SLIDE 4 -- Feature 2: Prompt Injection Prevention
# -----------------------------------------------------------------------------
feature_slide(
    4,
    "Feature 02",
    "Prompt Injection & Jailbreak Defense",
    [
        ("Heuristic Pattern Detection", "Flags known attack vectors such as instruction-override phrasing, system-prompt extraction attempts, and DAN-style jailbreaks."),
        ("Pre-emptive Blocking", "Returns an immediate HTTP 403 on detection, stopping the attack at the gateway before it reaches the model."),
        ("Model Protection", "Reduces the chance of adversaries exfiltrating system instructions or steering the LLM into unsafe output."),
        ("Human-in-the-Loop Appeal", "A blocked user can request human review with a justification; approval mints a single-use override token -- automated blocks stay contestable."),
        ("Honestly Scoped", "Documented as heuristic defense against known OWASP LLM01 patterns -- not a claim of catching every jailbreak."),
    ],
    pipeline_labels=["Prompt In", "Injection Rules", "Score >= 0.75?", "BLOCK (403)", "Appeal Queue"],
    pipeline_caption="Credential leaks are never appealable. Injection blocks are -- a human can approve an override.",
)

# -----------------------------------------------------------------------------
# SLIDE 5 -- Feature 3: Semantic Caching
# -----------------------------------------------------------------------------
feature_slide(
    5,
    "Feature 03",
    "Semantic Redis Caching",
    [
        ("Vector Similarity Search", "Converts prompts into embeddings (sentence-transformers) and compares them against prior requests stored in Redis."),
        ("Smart Thresholds", "A prompt that is worded differently but semantically similar (cosine >= 0.92) to a prior query can be served from cache."),
        ("Negation-Safe Matching", "Guards on negation, numbers, and named entities before serving a hit -- 'is X safe' and 'is X unsafe' must never be confused."),
        ("Low-Latency Hits", "Bypasses the LLM entirely on a cache hit, cutting response time from hundreds of milliseconds to single digits."),
        ("Cost Reduction", "Avoids paying provider token fees for repeated or near-duplicate queries -- tenant-namespaced so no cache is shared across customers."),
    ],
    pipeline_labels=["Prompt In", "Embed Vector", "Cosine >= 0.92?", "Cache HIT", "Cache MISS -> LLM"],
    pipeline_caption="Estimated $ and cache-hit rate are shown with the assumption stated -- never presented as guarantees.",
)

# -----------------------------------------------------------------------------
# SLIDE 6 -- Feature 4: Smart Routing & Circuit Breaker
# -----------------------------------------------------------------------------
feature_slide(
    6,
    "Feature 04",
    "Smart Routing & Automated Failover",
    [
        ("Dynamic Model Routing", "Routes simple tasks to cost-effective models (e.g. a local Ollama model) and complex reasoning to a premium model -- no model name hardcoded in source."),
        ("Circuit Breaker Protocol", "Tracks provider health continuously across CLOSED / OPEN / HALF-OPEN states."),
        ("Automated Failover", "On a timeout (2.5s default), a 503, or a 429 from the primary provider, the breaker opens and traffic redirects to a configured secondary."),
        ("Continuity Under Outage", "The client application keeps functioning through a provider outage instead of surfacing an error to the end user."),
    ],
    pipeline_labels=["Request", "Primary Provider", "Timeout / 503?", "Circuit OPEN", "Secondary Provider"],
    pipeline_caption="Failover events are recorded and surfaced in provider metrics -- not hidden from the audit trail.",
)

# -----------------------------------------------------------------------------
# SLIDE 7 -- Feature 5: Live Inspector Dashboard
# -----------------------------------------------------------------------------
feature_slide(
    7,
    "Feature 05",
    "The “Cockpit” Dashboard & Live Inspector",
    [
        ("Real-Time Pipeline View", "Visualizes the exact journey of a request: Input -> PII Scan -> Secret Scan -> Cache -> Router -> LLM -> Response."),
        ("Sanitization Visualizer", "Shows what Aegis redacted from the original prompt, without ever rendering the raw secret to the screen."),
        ("Comprehensive Audit Logging", "Tracks latency, provider used, estimated token cost, estimated energy/CO2, and every policy action taken -- each figure labeled with its basis."),
        ("Role-Separated Access", "Viewer sees aggregates only; reviewer adds the appeal queue; admin adds per-request drill-down -- Aegis constrains its own visibility into every prompt."),
    ],
    pipeline_labels=["Input", "PII Scan", "Secret Scan", "Cache / Router", "LLM Response"],
    pipeline_caption="A redacting log filter also scrubs Aegis's own server logs -- the tool that blocks leaks cannot leak either.",
)

# -----------------------------------------------------------------------------
# SLIDE 8 -- Advantages in Real Life
# -----------------------------------------------------------------------------
s = blank_slide(prs)
rect(s, 0, 0, SLIDE_W, SLIDE_H, WHITE)
header_bar(s, "Impact", "Real-World Enterprise Advantages")

advs = [
    ("Regulatory Support", "Helps organizations in healthcare and finance adopt generative AI while supporting their own HIPAA, GDPR, and internal risk-management obligations."),
    ("Brand Protection", "Reduces the risk of a public-facing AI assistant being hijacked into revealing internal data or producing off-brand responses."),
    ("Predictable AI Budgets", "Semantic caching smooths sudden spikes in LLM spend caused by traffic surges or repetitive queries."),
    ("Vendor Agnosticism", "Reduces lock-in -- an application can move between OpenAI, Anthropic, and open-source models behind one stable API contract."),
]

y = Inches(1.85)
col_w = Inches(5.75)
positions = [(Inches(0.7), y), (Inches(6.85), y), (Inches(0.7), y + Inches(2.15)), (Inches(6.85), y + Inches(2.15))]
for (lead, body), (x, yy) in zip(advs, positions):
    card = rect(s, x, yy, col_w, Inches(1.85), RGBColor(0xF7, 0xF9, 0xFC))
    card.line.color.rgb = RGBColor(0xE1, 0xE7, 0xEF)
    rect(s, x, yy, Pt(4), Inches(1.85), CYAN)
    _, tf = textbox(s, x + Inches(0.32), yy + Inches(0.25), col_w - Inches(0.6), Inches(1.4))
    p = tf.paragraphs[0]
    r = p.add_run(); set_run(r, lead, 16, NAVY, bold=True, font=FONT_SEMIBOLD)
    p2 = tf.add_paragraph(); p2.space_before = Pt(8); p2.line_spacing = 1.2
    r2 = p2.add_run(); set_run(r2, body, 12.5, SLATE)

footer(s, 8, TOTAL)

# -----------------------------------------------------------------------------
# SLIDE 9 -- Conclusion
# -----------------------------------------------------------------------------
s = blank_slide(prs)
rect(s, 0, 0, SLIDE_W, SLIDE_H, NAVY)
rect(s, 0, 0, SLIDE_W, Inches(0.12), CYAN)

_, tf = textbox(s, Inches(0.7), Inches(0.7), Inches(11.9), Inches(0.8))
p = tf.paragraphs[0]
r = p.add_run(); set_run(r, "Conclusion", 34, WHITE, bold=True)

_, tf2 = textbox(s, Inches(0.7), Inches(1.7), Inches(11.9), Inches(1.5))
p2 = tf2.paragraphs[0]
p2.line_spacing = 1.3
r2 = p2.add_run(); set_run(
    r2,
    "Generative AI is powerful, but direct LLM integrations are exposed to data leaks, "
    "provider outages, and prompt manipulation.",
    16, FAINT,
)

rect(s, Inches(0.7), Inches(3.35), Inches(11.9), Inches(1.05), NAVY_2)
rect(s, Inches(0.7), Inches(3.35), Pt(4), Inches(1.05), AMBER)
_, tf3 = textbox(s, Inches(1.05), Inches(3.35), Inches(11.3), Inches(1.05), MSO_ANCHOR.MIDDLE)
p3 = tf3.paragraphs[0]
p3.line_spacing = 1.25
r3 = p3.add_run(); set_run(
    r3,
    "Aegis, built by Team Future Bytes, acts as a zero-trust checkpoint for enterprise AI "
    "traffic -- inspecting what goes out and what comes back, and holding its own decisions "
    "to the same standard of accountability it enforces.",
    15, WHITE,
)

chips = [
    ("Python Security Engine", "Detection, policy, governance"),
    ("Next.js API Gateway", "Routing, caching, observability"),
    ("Result", "Faster, safer, auditable AI in production"),
]
cx = Inches(0.7)
cw = Inches(3.83)
cy = Inches(4.85)
for title, sub in chips:
    stat_chip(s, cx, cy, cw, Inches(1.5), title, sub, accent=CYAN)
    cx += cw + Inches(0.2)

footer(s, 9, TOTAL, label="AEGIS  ·  Team Future Bytes")

# =============================================================================
prs.save(OUT)
print(f"wrote {OUT}  ({len(prs.slides.__iter__.__self__._sldIdLst)} slides)")
