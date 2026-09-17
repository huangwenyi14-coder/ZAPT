"""Generate EvidenceForge data-quality scoring overview PPTX.

Produces docs/reference/data-quality-scoring-overview.pptx with 8 slides
mirroring the markdown version, using python-pptx (ad-hoc dep via uv).
"""

from __future__ import annotations

from pathlib import Path

from pptx import Presentation
from pptx.dml.color import RGBColor
from pptx.enum.shapes import MSO_SHAPE
from pptx.enum.text import PP_ALIGN
from pptx.util import Cm, Pt

# ---------- Palette ----------
INK = RGBColor(0x1F, 0x29, 0x37)          # near-black for body
INK_SOFT = RGBColor(0x4B, 0x55, 0x63)     # softer ink for secondary
BRAND = RGBColor(0x0B, 0x5C, 0xAB)        # Cisco-ish blue
ACCENT = RGBColor(0xC9, 0x37, 0x4D)       # accent red for hard-gate
GOLD = RGBColor(0xB8, 0x86, 0x0B)         # aspirational gold
LIGHT_BG = RGBColor(0xF5, 0xF7, 0xFA)    # row background
LINE = RGBColor(0xD1, 0xD5, 0xDB)         # table border
GREEN = RGBColor(0x05, 0x96, 0x69)
ORANGE = RGBColor(0xD9, 0x73, 0x06)
WHITE = RGBColor(0xFF, 0xFF, 0xFF)

# ---------- Geometry (16:9) ----------
SLIDE_W = Cm(33.867)
SLIDE_H = Cm(19.05)
MARGIN_X = Cm(1.6)
TITLE_Y = Cm(0.8)
TITLE_H = Cm(1.4)
BODY_Y = Cm(2.5)
BODY_W = Cm(30.6)
FOOTER_Y = Cm(18.2)

# ---------- Presentation setup ----------
prs = Presentation()
prs.slide_width = SLIDE_W
prs.slide_height = SLIDE_H
BLANK = prs.slide_layouts[6]


# ---------- Helpers ----------
def add_rect(slide, x, y, w, h, fill, line=None):
    shape = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, x, y, w, h)
    shape.fill.solid()
    shape.fill.fore_color.rgb = fill
    if line is None:
        shape.line.fill.background()
    else:
        shape.line.color.rgb = line
        shape.line.width = Pt(0.5)
    shape.shadow.inherit = False
    return shape


def add_text(
    slide,
    x,
    y,
    w,
    h,
    text: str,
    *,
    size: int = 14,
    bold: bool = False,
    color: RGBColor = INK,
    align=PP_ALIGN.LEFT,
    anchor="top",
    font: str = "Microsoft YaHei",
):
    tb = slide.shapes.add_textbox(x, y, w, h)
    tf = tb.text_frame
    tf.word_wrap = True
    tf.margin_left = Cm(0.1)
    tf.margin_right = Cm(0.1)
    tf.margin_top = Cm(0.05)
    tf.margin_bottom = Cm(0.05)
    if anchor == "middle":
        from pptx.enum.text import MSO_ANCHOR

        tf.vertical_anchor = MSO_ANCHOR.MIDDLE
    elif anchor == "bottom":
        from pptx.enum.text import MSO_ANCHOR

        tf.vertical_anchor = MSO_ANCHOR.BOTTOM
    lines = text.split("\n")
    for i, line in enumerate(lines):
        p = tf.paragraphs[0] if i == 0 else tf.add_paragraph()
        p.alignment = align
        run = p.add_run()
        run.text = line
        run.font.size = Pt(size)
        run.font.bold = bold
        run.font.color.rgb = color
        run.font.name = font
    return tb


def add_runs(slide, x, y, w, h, runs, *, align=PP_ALIGN.LEFT, anchor="top"):
    """runs: list of (text, size, bold, color) tuples within a single line."""
    tb = slide.shapes.add_textbox(x, y, w, h)
    tf = tb.text_frame
    tf.word_wrap = True
    tf.margin_left = Cm(0.1)
    tf.margin_right = Cm(0.1)
    tf.margin_top = Cm(0.05)
    tf.margin_bottom = Cm(0.05)
    if anchor == "middle":
        from pptx.enum.text import MSO_ANCHOR

        tf.vertical_anchor = MSO_ANCHOR.MIDDLE
    p = tf.paragraphs[0]
    p.alignment = align
    for text, size, bold, color in runs:
        run = p.add_run()
        run.text = text
        run.font.size = Pt(size)
        run.font.bold = bold
        run.font.color.rgb = color
        run.font.name = "Microsoft YaHei"
    return tb


def add_title(slide, title: str, subtitle: str | None = None):
    add_rect(slide, 0, 0, SLIDE_W, Cm(0.5), BRAND)
    add_text(
        slide,
        MARGIN_X,
        TITLE_Y,
        BODY_W,
        TITLE_H,
        title,
        size=28,
        bold=True,
        color=INK,
    )
    if subtitle:
        add_text(
            slide,
            MARGIN_X,
            TITLE_Y + Cm(1.1),
            BODY_W,
            Cm(0.7),
            subtitle,
            size=14,
            color=INK_SOFT,
        )


def add_footer(slide, idx: int, total: int):
    add_text(
        slide,
        MARGIN_X,
        FOOTER_Y,
        BODY_W,
        Cm(0.5),
        f"EvidenceForge 数据质量判分  ·  维度与判分依据  ·  {idx} / {total}",
        size=9,
        color=INK_SOFT,
    )


def add_table(
    slide,
    x,
    y,
    col_widths: list[float],
    rows: list[list[tuple[str, dict] | str]],
    *,
    header_bg: RGBColor = BRAND,
    header_fg: RGBColor = WHITE,
    body_bg: RGBColor = WHITE,
    alt_bg: RGBColor = LIGHT_BG,
    row_h: float = 0.85,
    header_h: float = 0.9,
    cell_size: int = 12,
    header_size: int = 13,
):
    """rows: each cell is a (text, opts_dict) tuple or plain str.
    opts: {bold, color, size, align, bg}"""
    total_w = sum(col_widths)
    x0 = x
    n_rows = len(rows)
    n_cols = len(col_widths)

    cur_y = y
    for r_idx, row in enumerate(rows):
        is_header = r_idx == 0
        h = header_h if is_header else row_h
        cur_x = x0
        for c_idx, cell in enumerate(row):
            if isinstance(cell, tuple):
                text, opts = cell
            else:
                text, opts = cell, {}
            w = Cm(col_widths[c_idx])
            cell_y = cur_y
            cell_x = cur_x
            bg = opts.get("bg") or (header_bg if is_header else (alt_bg if r_idx % 2 == 0 else body_bg))
            color = opts.get("color") or (header_fg if is_header else INK)
            bold = opts.get("bold", is_header)
            size = opts.get("size", header_size if is_header else cell_size)
            align = opts.get("align", PP_ALIGN.LEFT)
            add_rect(slide, cell_x, cell_y, w, Cm(h), bg, line=LINE)
            add_text(
                slide,
                cell_x + Cm(0.15),
                cell_y,
                w - Cm(0.3),
                Cm(h),
                text,
                size=size,
                bold=bold,
                color=color,
                align=align,
                anchor="middle",
            )
            cur_x += w
        cur_y += Cm(h)
    return cur_y


# ---------- Slide builders ----------

TOTAL = 8


def slide_cover():
    s = prs.slides.add_slide(BLANK)
    # Background block
    add_rect(s, 0, 0, SLIDE_W, SLIDE_H, WHITE)
    add_rect(s, 0, 0, SLIDE_W, Cm(2.0), BRAND)
    add_rect(s, 0, Cm(18.0), SLIDE_W, Cm(1.05), LIGHT_BG)
    # Title block
    add_text(
        s,
        MARGIN_X,
        Cm(5.0),
        BODY_W,
        Cm(2.2),
        "EvidenceForge 数据质量判分体系",
        size=44,
        bold=True,
        color=INK,
    )
    add_text(
        s,
        MARGIN_X,
        Cm(7.6),
        BODY_W,
        Cm(1.5),
        "四个维度 · 二十项判分依据 · 双档阈值",
        size=22,
        color=INK_SOFT,
    )
    add_text(
        s,
        MARGIN_X,
        Cm(9.5),
        BODY_W,
        Cm(1.0),
        "聚焦两件事:打分的维度、每个维度按什么判分",
        size=16,
        color=BRAND,
        bold=True,
    )
    # Four pillar tags
    tags = [
        ("Parseability", "30%"),
        ("Plausibility", "25%"),
        ("Causality", "25%"),
        ("Timing", "20%"),
    ]
    tag_w = Cm(6.5)
    gap = Cm(0.6)
    start_x = (SLIDE_W - (tag_w * 4 + gap * 3)) / 2
    for i, (name, pct) in enumerate(tags):
        x = start_x + i * (tag_w + gap)
        add_rect(s, x, Cm(12.0), tag_w, Cm(2.4), LIGHT_BG, line=BRAND)
        add_text(
            s,
            x,
            Cm(12.15),
            tag_w,
            Cm(1.0),
            name,
            size=16,
            bold=True,
            color=BRAND,
            align=PP_ALIGN.CENTER,
        )
        add_text(
            s,
            x,
            Cm(13.15),
            tag_w,
            Cm(1.0),
            f"权重 {pct}",
            size=14,
            color=INK,
            align=PP_ALIGN.CENTER,
        )
    add_text(
        s,
        MARGIN_X,
        FOOTER_Y,
        BODY_W,
        Cm(0.5),
        f"EvidenceForge 数据质量判分  ·  1 / {TOTAL}",
        size=9,
        color=INK_SOFT,
    )


def slide_overview():
    s = prs.slides.add_slide(BLANK)
    add_title(s, "一页总览", "评估体系 = 4 维度(支柱)× 双档阈值(hard gate + aspirational)")

    rows = [
        [
            "#",
            ("维度", {"align": PP_ALIGN.CENTER}),
            ("权重", {"align": PP_ALIGN.CENTER}),
            "答的问题",
            ("硬门槛(必过)", {"align": PP_ALIGN.CENTER}),
        ],
        [
            "1",
            ("Parseability", {"bold": True, "color": BRAND}),
            ("30%", {"align": PP_ALIGN.CENTER, "bold": True}),
            "SIEM parser 吃不吃得下这行?",
            ("spec_conformance ≥ 95", {"align": PP_ALIGN.CENTER, "bold": True, "color": ACCENT}),
        ],
        [
            "2",
            ("Plausibility", {"bold": True, "color": BRAND}),
            ("25%", {"align": PP_ALIGN.CENTER, "bold": True}),
            "字段值 / 组合 / 分布像不像真东西?",
            ("value_plausibility ≥ 95", {"align": PP_ALIGN.CENTER, "bold": True, "color": ACCENT}),
        ],
        [
            "3",
            ("Causality", {"bold": True, "color": BRAND}),
            ("25%", {"align": PP_ALIGN.CENTER, "bold": True}),
            "攻击剧情在数据里顺序对、来源对、IOA 对吗?",
            ("causal_ordering ≥ 90", {"align": PP_ALIGN.CENTER, "bold": True, "color": ACCENT}),
        ],
        [
            "4",
            ("Timing", {"bold": True, "color": BRAND}),
            ("20%", {"align": PP_ALIGN.CENTER, "bold": True}),
            "人 / 系统 / 攻击链的节奏合理吗?",
            ("(无硬门,纯拉分)", {"align": PP_ALIGN.CENTER, "color": INK_SOFT}),
        ],
    ]
    add_table(
        s,
        MARGIN_X,
        BODY_Y,
        col_widths=[1.0, 4.0, 2.2, 12.6, 10.8],
        rows=rows,
        row_h=1.0,
        header_h=0.95,
        cell_size=13,
        header_size=13,
    )

    # Footer note
    add_runs(
        s,
        MARGIN_X,
        BODY_Y + Cm(5.6),
        BODY_W,
        Cm(2.0),
        [
            ("Overall = ", 14, True, INK),
            ("Σ(pillar_score × pillar_weight)", 14, False, BRAND),
            ("。", 14, False, INK),
        ],
    )
    add_runs(
        s,
        MARGIN_X,
        BODY_Y + Cm(6.3),
        BODY_W,
        Cm(2.0),
        [
            ("• Overall ≥ 70 视为可用,", 13, False, INK),
            ("≥ 85 为优秀。", 13, True, GREEN),
        ],
    )
    add_runs(
        s,
        MARGIN_X,
        BODY_Y + Cm(6.95),
        BODY_W,
        Cm(2.0),
        [
            ("• 任何 hard gate 不过 → ", 13, False, INK),
            ("acceptance_passed = False", 13, True, ACCENT),
            (",数据集拒收。", 13, False, INK),
        ],
    )

    add_footer(s, 2, TOTAL)


def slide_pillar(num: int, name: str, weight: int, what: str, rows: list, notes: list, idx: int):
    s = prs.slides.add_slide(BLANK)
    title = f"Pillar {num}: {name}  (权重 {weight}%)"
    add_title(s, title, f"判分依据:{what}")

    # Build table with header
    header = [
        ("Sub-score", {"align": PP_ALIGN.CENTER}),
        ("权重", {"align": PP_ALIGN.CENTER}),
        "判分依据",
        ("评分公式", {"align": PP_ALIGN.CENTER}),
    ]
    body_rows = [header]
    for sub_key, sub_w, basis, formula in rows:
        body_rows.append(
            [
                (sub_key, {"bold": True, "color": BRAND}),
                (sub_w, {"align": PP_ALIGN.CENTER, "bold": True}),
                basis,
                (formula, {"align": PP_ALIGN.CENTER, "color": INK_SOFT}),
            ]
        )
    add_table(
        s,
        MARGIN_X,
        BODY_Y,
        col_widths=[5.0, 1.8, 14.2, 9.6],
        rows=body_rows,
        row_h=0.78,
        header_h=0.85,
        cell_size=11,
        header_size=12,
    )

    # Notes block
    notes_y = BODY_Y + Cm(0.78 * len(rows) + 0.95)
    add_rect(s, MARGIN_X, notes_y, BODY_W, Cm(2.6), LIGHT_BG, line=LINE)
    add_text(
        s,
        MARGIN_X + Cm(0.2),
        notes_y + Cm(0.1),
        BODY_W - Cm(0.4),
        Cm(0.5),
        "关键判据",
        size=13,
        bold=True,
        color=BRAND,
    )
    for i, n in enumerate(notes):
        add_text(
            s,
            MARGIN_X + Cm(0.4),
            notes_y + Cm(0.7) + Cm(0.6) * i,
            BODY_W - Cm(0.6),
            Cm(0.6),
            f"• {n}",
            size=11,
            color=INK,
        )

    add_footer(s, idx, TOTAL)


def slide_total():
    s = prs.slides.add_slide(BLANK)
    add_title(s, "总分计算 & 两档阈值", "6.1 / 6.2 / 6.3 — 把 14 个 sub-score 收成 1 个 overall")

    # 6.1 Pillar score
    y = BODY_Y
    add_rect(s, MARGIN_X, y, BODY_W, Cm(1.2), LIGHT_BG, line=LINE)
    add_text(
        s,
        MARGIN_X + Cm(0.2),
        y + Cm(0.1),
        Cm(4.0),
        Cm(1.0),
        "6.1 Pillar 得分",
        size=14,
        bold=True,
        color=BRAND,
        anchor="middle",
    )
    add_text(
        s,
        MARGIN_X + Cm(5.0),
        y + Cm(0.1),
        BODY_W - Cm(5.0),
        Cm(1.0),
        "pillar_score = Σ(sub_score_i × sub_score_weight_i)",
        size=14,
        bold=True,
        color=INK,
        anchor="middle",
    )

    y2 = y + Cm(1.4)
    add_rect(s, MARGIN_X, y2, BODY_W, Cm(1.6), LIGHT_BG, line=LINE)
    add_text(
        s,
        MARGIN_X + Cm(0.2),
        y2 + Cm(0.1),
        Cm(4.0),
        Cm(1.4),
        "6.2 Overall 得分",
        size=14,
        bold=True,
        color=BRAND,
        anchor="middle",
    )
    add_text(
        s,
        MARGIN_X + Cm(5.0),
        y2 + Cm(0.1),
        BODY_W - Cm(5.0),
        Cm(0.6),
        "overall = Σ(pillar_score_i × pillar_weight_i)",
        size=13,
        bold=True,
        color=INK,
    )
    add_text(
        s,
        MARGIN_X + Cm(5.0),
        y2 + Cm(0.7),
        BODY_W - Cm(5.0),
        Cm(0.6),
        "可用 pillar 不足时按剩余 pillar 重归一化(防单 pillar 异常把总分压成零)",
        size=11,
        color=INK_SOFT,
    )

    y3 = y2 + Cm(1.8)
    add_rect(s, MARGIN_X, y3, BODY_W, Cm(1.0), LIGHT_BG, line=LINE)
    add_text(
        s,
        MARGIN_X + Cm(0.2),
        y3 + Cm(0.1),
        Cm(4.0),
        Cm(0.8),
        "6.3 两档阈值",
        size=14,
        bold=True,
        color=BRAND,
        anchor="middle",
    )
    add_runs(
        s,
        MARGIN_X + Cm(5.0),
        y3 + Cm(0.15),
        Cm(13.0),
        Cm(0.8),
        [
            ("minimum", 13, True, ACCENT),
            (" = hard gate — 不达 → 拒收   |   ", 12, False, INK),
            ("aspirational", 13, True, GOLD),
            (" = 努力目标 — 仅展示达成率", 12, False, INK),
        ],
        anchor="middle",
    )

    # Hard gates table
    y4 = y3 + Cm(1.2)
    add_text(
        s,
        MARGIN_X,
        y4,
        BODY_W,
        Cm(0.6),
        "目前 4 条 hard gate",
        size=14,
        bold=True,
        color=INK,
    )
    gates = [
        [
            ("维度", {"align": PP_ALIGN.CENTER}),
            ("Sub-score", {"align": PP_ALIGN.CENTER}),
            ("hard gate", {"align": PP_ALIGN.CENTER}),
        ],
        [
            ("Parseability", {"bold": True, "color": BRAND}),
            ("spec_conformance", {"align": PP_ALIGN.CENTER}),
            ("≥ 95", {"align": PP_ALIGN.CENTER, "bold": True, "color": ACCENT}),
        ],
        [
            ("Plausibility", {"bold": True, "color": BRAND}),
            ("value_plausibility", {"align": PP_ALIGN.CENTER}),
            ("≥ 95", {"align": PP_ALIGN.CENTER, "bold": True, "color": ACCENT}),
        ],
        [
            ("Causality", {"bold": True, "color": BRAND}),
            ("causal_ordering", {"align": PP_ALIGN.CENTER}),
            ("≥ 90", {"align": PP_ALIGN.CENTER, "bold": True, "color": ACCENT}),
        ],
        [
            ("Causality", {"bold": True, "color": BRAND}),
            ("event_presence", {"align": PP_ALIGN.CENTER}),
            ("≥ 85", {"align": PP_ALIGN.CENTER, "bold": True, "color": ACCENT}),
        ],
    ]
    add_table(
        s,
        MARGIN_X,
        y4 + Cm(0.7),
        col_widths=[7.0, 12.0, 11.6],
        rows=gates,
        row_h=0.62,
        header_h=0.65,
        cell_size=12,
        header_size=12,
    )

    add_footer(s, 7, TOTAL)


def slide_cheatsheet():
    s = prs.slides.add_slide(BLANK)
    add_title(s, "速查卡:4 维度 × 14 子分 × 判分依据", "整套判分规则就是这些")

    # Compact 2x2 grid of pillars with sub-scores
    pillars = [
        (
            "Pillar 1  Parseability (30%)",
            BRAND,
            [
                ("spec_conformance", "0.55", "strict parse + 必填 + 类型"),
                ("format_constraints", "0.45", "enum/range/regex/coerce"),
            ],
        ),
        (
            "Pillar 2  Plausibility (25%)",
            BRAND,
            [
                ("value_plausibility", "0.25", "OS 不窜台、host 存在"),
                ("co_occurrence", "0.20", "字段必现/互斥规则"),
                ("distribution_fit", "0.15", "JSD vs 参考分布"),
                ("field_agreement", "0.15", "跨源 pivot + 一致性"),
                ("user_diversity", "0.15", "两两余弦相似度低"),
                ("anomaly_rate", "0.10", "1–5% 异常良性"),
            ],
        ),
        (
            "Pillar 3  Causality (25%)",
            BRAND,
            [
                ("causal_ordering", "0.25", "前后对顺序"),
                ("event_presence", "0.20", "应见就有 trace"),
                ("indicator_accuracy", "0.15", "IOA(IP/host/user)对"),
                ("pivot_linkability", "0.15", "相邻步能 pivot"),
                ("temporal_integrity", "0.15", "时间窗内、有序"),
                ("storyline_trace_coverage", "0.10", "期望源都覆盖"),
            ],
        ),
        (
            "Pillar 4  Timing (20%)",
            BRAND,
            [
                ("attack_chain_timing", "0.15", "剧情间隔在窗口内"),
                ("burstiness", "0.20", "人 CV 1–3"),
                ("system_regularity", "0.15", "服务 CV 0.15–1.0"),
                ("diurnal_pattern", "0.20", "2D JSD vs persona"),
                ("volume_adequacy", "0.20", "noise:signal 达标"),
                ("rate_plausibility", "0.10", "物理速率合理"),
            ],
        ),
    ]

    # 2 columns x 2 rows layout
    col_w = Cm(15.0)
    row_h_title = Cm(0.9)
    cell_h = Cm(0.6)
    gap_x = Cm(0.6)
    gap_y = Cm(0.4)
    start_x = MARGIN_X
    start_y = BODY_Y

    for p_idx, (title, color, subs) in enumerate(pillars):
        col = p_idx % 2
        row = p_idx // 2
        x = start_x + col * (col_w + gap_x)
        y = start_y + row * (Cm(7.4))
        # title bar
        add_rect(s, x, y, col_w, row_h_title, color)
        add_text(
            s,
            x + Cm(0.2),
            y,
            col_w - Cm(0.4),
            row_h_title,
            title,
            size=15,
            bold=True,
            color=WHITE,
            anchor="middle",
        )
        # rows
        for i, (k, w, desc) in enumerate(subs):
            ry = y + row_h_title + i * cell_h
            bg = LIGHT_BG if i % 2 == 0 else WHITE
            add_rect(s, x, ry, col_w, cell_h, bg, line=LINE)
            add_text(
                s,
                x + Cm(0.2),
                ry,
                Cm(5.5),
                cell_h,
                k,
                size=11,
                bold=True,
                color=INK,
                anchor="middle",
            )
            add_text(
                s,
                x + Cm(5.7),
                ry,
                Cm(1.5),
                cell_h,
                w,
                size=11,
                bold=True,
                color=BRAND,
                align=PP_ALIGN.CENTER,
                anchor="middle",
            )
            add_text(
                s,
                x + Cm(7.2),
                ry,
                col_w - Cm(7.4),
                cell_h,
                desc,
                size=11,
                color=INK_SOFT,
                anchor="middle",
            )

    add_footer(s, 8, TOTAL)


# ---------- Build ----------
slide_cover()

slide_overview()

slide_pillar(
    num=1,
    name="Parseability",
    weight=30,
    what="用真实下游 parser 的口径跑 strict 模式验证",
    rows=[
        ("spec_conformance", "0.55", "记录能否被 strict parser 解析 + 必填字段齐备 + 字段类型正确", "100 × 通过 / 总数"),
        ("format_constraints", "0.45", "enum / 范围 / regex / coerce 约束是否被违反(可 parse 但破 schema)", "100 × 通过 / 总数"),
    ],
    notes=[
        "Windows 事件用 EventID → variant 映射选变体后再校验",
        "STRICT_FORMATS(syslog、zeek_*)再走一次字节级 validate_strict()",
        "错误归类为 parse_error / missing_field / strict_validation / constraint_violation",
    ],
    idx=3,
)

slide_pillar(
    num=2,
    name="Plausibility",
    weight=25,
    what="逐条看值、组合、分布、跨源是否合理",
    rows=[
        ("value_plausibility", "0.25", "OS 不窜台(Linux 上没 C:\\Windows)+ 主机名在 scenario 中", "100 × 通过 / 总数"),
        ("co_occurrence", "0.20", "字段必现/互斥/范围规则(co_occurrence.yaml)", "100 × 通过 / 适用条数"),
        ("distribution_fit", "0.15", "字段值分布 vs distributions.yaml 参考分布", "JSD→100 / 2×tolerance→0,中间线性"),
        ("field_agreement", "0.15", "跨源 pivot join 后字段值一致(cross_source_pairs.yaml)", "100 × 一致对 / 匹配对"),
        ("user_diversity", "0.15", "不同 user 事件类型分布两两余弦相似度低", "sim≤0.5→100;sim≥0.9→0;中间线性"),
        ("anomaly_rate", "0.10", "异常但良性的事件占 1–5% 是金标准", "0%→0;1–5%→100;>10%→0;中间带衰减"),
    ],
    notes=[
        "co_occurrence:checks 支持 present / not_equal / equals / min_length / min_value / max_value / in / matches",
        "field_agreement:支持 lower / path_basename_ci / cn_from_dn 归一化、tolerance 数值容差、time_window_seconds",
    ],
    idx=4,
)

slide_pillar(
    num=3,
    name="Causality",
    weight=25,
    what="验证攻击剧情在数据里该有的痕迹都到位、IOA 对得上、前后顺序不乱、相邻步骤能 pivot",
    rows=[
        ("causal_ordering", "0.25", "已知前后事件对顺序正确(causal_pairs.yaml)", "100 × 正确对 / 总对"),
        ("event_presence", "0.20", "每条剧情事件在 sensor 视野内留了至少 1 条 trace", "100 × 找到 / 应见"),
        ("indicator_accuracy", "0.15", "找到的 trace 中 actor/hostname/IP 与剧本一致(IPv4-mapped 兼容)", "100 × 正确项 / 检查项"),
        ("pivot_linkability", "0.15", "相邻剧情事件之间有可 pivot 的公共指示(actor、system、IP、trace 字段)", "100 × 可 pivot 对 / 邻接对"),
        ("temporal_integrity", "0.15", "trace 时间与剧情时间在 ±TIME_TOLERANCE 内", "100 × 合规 / 应见"),
        ("storyline_trace_coverage", "0.10", "剧情在所有期望 format-group 都落有 trace", "100 × 覆盖组 / 期望组"),
    ],
    notes=[
        "trace 搜索:(hostname 或 IP, 60s 时间桶) 建索引,FQDN 额外存 bare-hostname",
        "observation-profile 调整:非 complete 的源按 manifest 排除不可见事件,但不豁免 hard correctness 错误",
        "spillage / adversarial_payload:从 GROUND_TRUTH.json 读实际渲染字符串,在原文(支持 CRLF 切分)里搜",
    ],
    idx=5,
)

slide_pillar(
    num=4,
    name="Timing",
    weight=20,
    what="节奏对得上真实环境 — 人不是等距发指令、系统不是等距跑 cron、攻击链不会瞬间完成",
    rows=[
        ("attack_chain_timing", "0.15", "相邻剧情事件间隔在 timing_bounds.yaml 的 min/max 窗口内", "100 × 窗口内对 / 总对"),
        ("burstiness", "0.20", "人 inter-event 时间呈突发性(剔 system account,5s 去重,算 CV)", "CV∈[1,3]→100;CV<0.5→0"),
        ("system_regularity", "0.15", "同(host, service)的服务类事件呈周期性", "CV∈[0.15,1.0]→100;CV>2→0"),
        ("diurnal_pattern", "0.20", "用户活动按 persona work_hours 聚集、跨工作日(7×24 二维直方图)", "JSD<0.01→0;JSD≥0.4→0"),
        ("volume_adequacy", "0.20", "背景噪声与攻击信号比例达标", "ratio≥target→100;≤target/2→0"),
        ("rate_plausibility", "0.10", "物理上不可能的速率(5s 内 ≥ 21 条、>10Gbps 连接)", "100 × 合规 / 检查"),
    ],
    notes=[
        "目标 noise:signal 比:low=200:1 / medium=2000:1 / high=5000:1",
        "短场景保护:diurnal_pattern 需 ≥ 24h + ≥ 2 weekday;burstiness 单用户 < 30 条跳过;N/A 项自动从分母拿掉",
    ],
    idx=6,
)

slide_total()

slide_cheatsheet()

# ---------- Save ----------
out = Path(__file__).resolve().parents[1] / "docs" / "reference" / "data-quality-scoring-overview.pptx"
out.parent.mkdir(parents=True, exist_ok=True)
prs.save(out)
print(f"Wrote {out}  ({out.stat().st_size / 1024:.1f} KB, {len(prs.slides)} slides)")
