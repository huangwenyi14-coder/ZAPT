#!/usr/bin/env python3
"""生成「多源异构日志攻击链关联发现」赛题说明 Word 文档。

数据来源：output/ 下 14 个 APT 场景的 GROUND_TRUTH.json / OBSERVATION_MANIFEST.json
及各类日志样例。所有统计在生成时从真实数据汇总，保证准确。
"""

from __future__ import annotations

import glob
import json
import os
from collections import Counter
from pathlib import Path

from docx import Document
from docx.enum.table import WD_ALIGN_VERTICAL
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml.ns import qn
from docx.oxml import OxmlElement
from docx.shared import Cm, Pt, RGBColor

REPO = Path(__file__).resolve().parents[1]
OUT_DIR = REPO / "output"
OUT_DOCX = REPO / "docs" / "赛题说明_多源异构日志攻击链关联发现.docx"

LATIN = "Calibri"
MONO = "Consolas"
SONG = "宋体"
HEI = "黑体"

# ---- 字体 / 样式辅助 ----------------------------------------------------------


def _set_east_asia(run, eastasia: str) -> None:
    rpr = run._element.get_or_add_rPr()
    rfonts = rpr.find(qn("w:rFonts"))
    if rfonts is None:
        rfonts = OxmlElement("w:rFonts")
        rpr.append(rfonts)
    rfonts.set(qn("w:eastAsia"), eastasia)


def add_run(paragraph, text: str, *, bold=False, italic=False, size=None,
            latin=LATIN, eastasia=SONG, color=None, mono=False):
    run = paragraph.add_run(text)
    run.bold = bold
    run.italic = italic
    if size:
        run.font.size = Pt(size)
    run.font.name = MONO if mono else latin
    _set_east_asia(run, MONO if mono else eastasia)
    if color:
        run.font.color.rgb = RGBColor(*color)
    return run


def shade(paragraph, fill: str = "F2F2F2") -> None:
    pPr = paragraph._p.get_or_add_pPr()
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear")
    shd.set(qn("w:color"), "auto")
    shd.set(qn("w:fill"), fill)
    pPr.append(shd)


def border_box(paragraph) -> None:
    pPr = paragraph._p.get_or_add_pPr()
    pbdr = OxmlElement("w:pBdr")
    for edge in ("top", "left", "bottom", "right"):
        el = OxmlElement(f"w:{edge}")
        el.set(qn("w:val"), "single")
        el.set(qn("w:sz"), "6")
        el.set(qn("w:space"), "4")
        el.set(qn("w:color"), "BFBFBF")
        pbdr.append(el)
    pPr.append(pbdr)


def body(doc, text: str = "", *, size=10.5, bold=False, after=6) -> object:
    p = doc.add_paragraph()
    p.paragraph_format.space_after = Pt(after)
    p.paragraph_format.line_spacing = 1.25
    if text:
        add_run(p, text, size=size, bold=bold)
    return p


def bullet(doc, text: str, *, level=0, size=10.5) -> None:
    p = doc.add_paragraph(style="List Bullet")
    p.paragraph_format.left_indent = Cm(0.75 + level * 0.75)
    p.paragraph_format.space_after = Pt(2)
    add_run(p, text, size=size)


def numbered(doc, text: str, *, size=10.5) -> None:
    p = doc.add_paragraph(style="List Number")
    p.paragraph_format.space_after = Pt(2)
    add_run(p, text, size=size)


def heading(doc, text: str, level: int) -> None:
    h = doc.add_heading(level=level)
    h.paragraph_format.space_before = Pt(12 if level <= 2 else 8)
    h.paragraph_format.space_after = Pt(6)
    sizes = {0: 20, 1: 16, 2: 13.5, 3: 12, 4: 11}
    run = add_run(h, text, size=sizes.get(level, 11), bold=True, eastasia=HEI)
    if level == 0:
        run.font.color.rgb = RGBColor(0x1F, 0x38, 0x64)
    elif level == 1:
        run.font.color.rgb = RGBColor(0x1F, 0x4E, 0x79)
    elif level == 2:
        run.font.color.rgb = RGBColor(0x2E, 0x5C, 0x8A)


def formula(doc, text: str, *, caption: str | None = None) -> None:
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.paragraph_format.space_before = Pt(4)
    p.paragraph_format.space_after = Pt(4)
    add_run(p, text, size=11, bold=True, mono=True)
    shade(p, "F4F6F8")
    border_box(p)
    if caption:
        c = doc.add_paragraph()
        c.alignment = WD_ALIGN_PARAGRAPH.CENTER
        c.paragraph_format.space_after = Pt(8)
        add_run(c, caption, size=9, italic=True, color=(0x59, 0x59, 0x59))


def code_block(doc, text: str) -> None:
    p = doc.add_paragraph()
    p.paragraph_format.space_before = Pt(4)
    p.paragraph_format.space_after = Pt(8)
    p.paragraph_format.left_indent = Cm(0.3)
    for i, line in enumerate(text.splitlines()):
        if i:
            p.add_run().add_break()
        add_run(p, line if line else " ", size=9, mono=True)
    shade(p, "F4F6F8")
    border_box(p)


def make_table(doc, headers, rows, *, widths=None, font_size=9, header_fill="1F4E79"):
    table = doc.add_table(rows=1, cols=len(headers))
    table.style = "Table Grid"
    table.alignment = WD_ALIGN_VERTICAL.CENTER
    hdr = table.rows[0].cells
    for i, htext in enumerate(headers):
        hdr[i].text = ""
        para = hdr[i].paragraphs[0]
        para.alignment = WD_ALIGN_PARAGRAPH.CENTER
        add_run(para, htext, size=font_size, bold=True, color=(0xFF, 0xFF, 0xFF))
        tcPr = hdr[i]._tc.get_or_add_tcPr()
        shd = OxmlElement("w:shd")
        shd.set(qn("w:val"), "clear")
        shd.set(qn("w:color"), "auto")
        shd.set(qn("w:fill"), header_fill)
        tcPr.append(shd)
    for row in rows:
        cells = table.add_row().cells
        for i, val in enumerate(row):
            cells[i].text = ""
            para = cells[i].paragraphs[0]
            para.paragraph_format.space_after = Pt(1)
            add_run(para, str(val), size=font_size)
    if widths:
        for i, w in enumerate(widths):
            for row in table.rows:
                row.cells[i].width = Cm(w)
    return table


def page_break(doc) -> None:
    doc.add_page_break()


# ---- 数据采集 ----------------------------------------------------------------


def gather_stats() -> dict:
    scenarios = sorted(glob.glob(str(OUT_DIR / "*" / "GROUND_TRUTH.json")))
    rows = []
    et_counter = Counter()
    total_steps = total_events = multi_host = 0
    for p in scenarios:
        name = os.path.basename(os.path.dirname(p))
        d = json.loads(Path(p).read_text(encoding="utf-8"))
        steps = d.get("storyline_steps", [])
        events = d.get("events", [])
        systems = sorted({s.get("system", "?") for s in steps})
        et = Counter()
        for s in steps:
            for t in s.get("event_types", []):
                et[t] += 1
                et_counter[t] += 1
        rows.append({
            "name": name, "steps": len(steps), "events": len(events),
            "hosts": len(systems), "types": ", ".join(sorted(et)),
        })
        total_steps += len(steps)
        total_events += len(events)
        if len(systems) > 1:
            multi_host += 1
    return {
        "rows": rows, "n": len(rows), "total_steps": total_steps,
        "total_events": total_events, "multi_host": multi_host,
        "event_types": et_counter.most_common(),
    }


# ---- 文档构建 ----------------------------------------------------------------


def build() -> None:
    stats = gather_stats()
    doc = Document()

    # 全局正文样式：中文宋体
    normal = doc.styles["Normal"]
    normal.font.name = LATIN
    normal.font.size = Pt(10.5)
    normal.element.rPr.rFonts.set(qn("w:eastAsia"), SONG)

    sec = doc.sections[0]
    sec.top_margin = Cm(2.2)
    sec.bottom_margin = Cm(2.2)
    sec.left_margin = Cm(2.4)
    sec.right_margin = Cm(2.4)

    # ===== 封面标题 =====
    title = doc.add_paragraph()
    title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    title.paragraph_format.space_before = Pt(60)
    add_run(title, "多源异构安全日志中的多步攻击链关联发现",
            size=24, bold=True, eastasia=HEI, color=(0x1F, 0x38, 0x64))
    sub = doc.add_paragraph()
    sub.alignment = WD_ALIGN_PARAGRAPH.CENTER
    sub.paragraph_format.space_before = Pt(10)
    add_run(sub, "—— 赛题任务、数据集与评分方法说明 ——",
            size=13, eastasia=HEI, color=(0x59, 0x59, 0x59))

    tag = doc.add_paragraph()
    tag.alignment = WD_ALIGN_PARAGRAPH.CENTER
    tag.paragraph_format.space_before = Pt(6)
    add_run(tag, f"数据集规模：{stats['n']} 个 APT 场景  ·  "
            f"{stats['total_steps']} 个攻击步骤  ·  "
            f"{stats['total_events']} 个原子事件  ·  "
            f"5 大类 14 种日志格式",
            size=10.5, color=(0x59, 0x59, 0x59))

    doc.add_paragraph().paragraph_format.space_after = Pt(20)

    # 摘要框
    box = doc.add_paragraph()
    box.paragraph_format.space_before = Pt(30)
    box.paragraph_format.left_indent = Cm(0.5)
    box.paragraph_format.right_indent = Cm(0.5)
    add_run(box, "【一句话赛题】", size=11, bold=True, eastasia=HEI, color=(0xC0, 0x00, 0x00))
    box.add_run().add_break()
    add_run(box,
            "给定一份被正常业务流量与基线噪声高度淹没的企业级「多源异构日志集合」"
            "（端点 EDR、Windows 安全审计、Sysmon、Linux Syslog、Zeek 网络流量），"
            "参赛智能体需自主读取、解析、跨源关联，最终还原出一条（或多条）完整的"
            "「有序多步攻击链」，并以结构化形式输出，与攻击真值（Ground Truth）"
            "按攻击步骤比对评分。",
            size=10.5)
    shade(box, "FBF4E8")
    border_box(box)

    page_break(doc)

    # ===== 目录提示 =====
    heading(doc, "目录", 1)
    toc = [
        "一、赛题背景与目标",
        "二、数据集概览",
        "三、多源异构数据类型",
        "四、噪声、真实感与观测缺失",
        "五、攻击链（Storyline）标签体系",
        "六、任务定义：输入与输出",
        "七、智能体（Agent）解题方案",
        "八、评分方法（核心）",
        "九、基线建议与提交规范",
        "附录 A：数据字段速查表",
        "附录 B：场景清单与攻击组织",
        "附录 C：提交输出 JSON Schema 建议",
    ]
    for t in toc:
        p = doc.add_paragraph()
        p.paragraph_format.space_after = Pt(3)
        add_run(p, t, size=11)

    page_break(doc)

    # ===== 一、背景与目标 =====
    heading(doc, "一、赛题背景与目标", 1)

    heading(doc, "1.1 背景", 2)
    body(doc,
         "现代高级持续性威胁（APT）通常呈现「多阶段、多主机、多信道」特征：从初始钓鱼"
         "投递、恶意载荷执行，到命令与控制（C2）通信、横向移动、凭据窃取、权限提升，"
         "直至最终持久化与数据外传。每一阶段都会在不同安全设备上留下分散的证据碎片——"
         "一条进程创建、一次异常外联、一个被创建的计划任务、一段 DNS 查询。")
    body(doc,
         "真实威胁狩猎的核心难题在于：单源、单点的告警早已被海量正常业务流量淹没。"
         "安全运营人员面对的往往是数十万乃至上百万行异构日志，真正的攻击证据只占"
         "其中极小比例。能否把这些跨源、跨主机、跨时间的碎片「拼成一条完整的攻击故事」，"
         "是区分「告警噪音」与「威胁情报」的关键能力。")

    heading(doc, "1.2 赛题目标", 2)
    body(doc, "本赛题要求构建一个能够自主完成下列全流程的智能体（Agent）系统：")
    numbered(doc, "读取并解析 5 大类、14 种格式的多源异构日志；")
    numbered(doc, "在海量正常基线噪声中识别出可疑的「原子攻击动作」；")
    numbered(doc, "通过跨源 ID、时间因果与 IOC 锚点，把分散动作关联成有序的攻击链；")
    numbered(doc, "以结构化形式输出攻击链，使其可与攻击真值自动比对评分。")

    heading(doc, "1.3 核心挑战", 2)
    rows = [
        ("数据量大", "单场景日志可达近百万行（约 96 万行），端到端处理需兼顾吞吐与精度。"),
        ("数据异构", "JSON / JSONL / XML / 纯文本 4 种载体，5 大采集视角，字段语义各不相同。"),
        ("信噪比极低", "正常业务流量（登录、DNS、SMB、补丁、备份）远多于攻击流量，攻击证据被淹没。"),
        ("跨源跨主机", "同一攻击动作在多源留下不同形态证据，且常跨多台主机，需统一关联。"),
        ("观测缺失", "同一动作在不同数据源的可见性不同，存在天然采集缺口，需容忍不完整证据。"),
        ("链条语义", "不仅要「找出事件」，还要还原「先后顺序与因果关系」，形成可解释故事。"),
    ]
    make_table(doc, ["挑战", "说明"], rows, widths=[3.2, 13.5], font_size=9.5)

    page_break(doc)

    # ===== 二、数据集概览 =====
    heading(doc, "二、数据集概览", 1)

    heading(doc, "2.1 整体构成", 2)
    body(doc,
         f"数据集共包含 {stats['n']} 个独立 APT 攻击场景，覆盖 darkhotel、lazarus、"
         "oceanlotus、donot、sidewinder、apt36、bitter、retail-store-ftp-attack 等"
         "真实威胁组织的典型战术。攻击链长度从 6 步到 22 步不等；其中 "
         f"{stats['multi_host']} 个场景涉及跨主机横向移动。")
    body(doc,
         f"全数据集合计 {stats['total_steps']} 个攻击步骤、"
         f"{stats['total_events']} 个原子事件，事件类型分布如下表所示。")

    et_rows = [(t, c, f"{c/stats['total_steps']*100:.1f}%") for t, c in stats["event_types"]]
    make_table(doc, ["事件类型 (event_type)", "出现次数", "占比"], et_rows,
               widths=[6.5, 4.0, 4.0], font_size=9.5)
    body(doc,
         "（说明：事件类型在攻击叙事层面的语义——process=进程执行，connection=网络连接，"
         "beacon=C2 周期信标，logon=登录，scheduled_task_created=计划任务持久化，"
         "dns_query=DNS 查询，create_remote_thread=远程线程注入。）", size=9, after=10)

    heading(doc, "2.2 目录结构", 2)
    body(doc, "每个场景为一个独立目录，结构如下：")
    code_block(doc, """output/<scenario>/
├── data/                              # 多源异构日志（参赛者唯一输入）
│   ├── <Windows主机名>/               # 每台主机一个子目录
│   │   ├── ecar.json                  #   EDR 端点行为日志 (JSONL)
│   │   ├── windows_event_security.xml #   Windows 安全审计事件 (XML)
│   │   └── windows_event_sysmon.xml   #   Sysmon 细粒度事件 (XML)
│   ├── <Linux主机名>/
│   │   ├── ecar.json
│   │   └── syslog.log                 #   Linux 系统日志 (RFC5424)
│   └── ZEEK-<传感器>/                 # 网络侧 Zeek 全流量解析 (JSONL)
│       ├── conn.json   dns.json   http.json   ssl.json
│       ├── files.json  x509.json  dhcp.json   ntp.json
│       └── ocsp.json   pe.json
├── GROUND_TRUTH.json                  # 机器可读攻击真值（评分依据，比赛期间不下发）
├── GROUND_TRUTH.md                    # 人类可读真值（同上）
├── OBSERVATION_MANIFEST.json          # 每个攻击步骤在各数据源的可见事件计数
└── OUTPUT_TARGET.txt                  # 输出目标标记""")

    heading(doc, "2.3 体量示例", 2)
    body(doc, "以 apt-c48-cnc-sbie 场景为例，单场景各类日志的行数规模：")
    size_rows = [
        ("windows_event_security.xml", "781,242", "Windows 安全审计（登录/Kerberos/权限）"),
        ("windows_event_sysmon.xml", "116,569", "Sysmon 进程/网络/文件/注册表"),
        ("conn.json (Zeek)", "24,133", "网络连接元数据"),
        ("ecar.json (EDR)", "18,214", "端点行为细粒度记录"),
        ("dns.json (Zeek)", "4,425", "DNS 查询与应答"),
        ("files.json / ssl.json / x509.json", "合计 ~1.4 万", "文件哈希 / TLS / 证书"),
        ("合计", "≈ 960,000 行", "单场景日志总量"),
    ]
    make_table(doc, ["文件", "行数", "采集视角"], size_rows,
               widths=[6.2, 3.2, 7.3], font_size=9)

    page_break(doc)

    # ===== 三、数据类型 =====
    heading(doc, "三、多源异构数据类型", 1)
    body(doc,
         "数据集包含 5 大类、14 种日志格式。它们从「主机端点」「身份认证」「网络流量」"
         "三个视角，对同一时空内的活动进行互补观测。同一攻击动作往往在多源同时留下证据"
         "（例如一次 C2 外联，会同时出现在 Zeek conn/ssl/http、EDR FLOW、Sysmon 网络事件中），"
         "这正是跨源关联的基础；而这些正常业务流程同样会大量出现在各源中，构成噪声。")

    heading(doc, "3.1 主机端点视角", 2)
    body(doc, "(1) EDR 端点行为日志（eCAR）—— ecar.json（JSONL）", bold=True, after=2)
    body(doc,
         "最细粒度的端点行为记录。每条记录由 object + action + properties 构成，"
         "覆盖进程、网络流（FLOW/CONNECT）、文件、注册表、模块加载等。字段含主机名、"
         "PID/TID、命令行、映像路径、源/目的 IP 端口等。是还原进程树与行为链的核心。")
    code_block(doc, '{"timestamp_ms":1732582836252,"hostname":"DC-01","object":"FLOW",\n'
               ' "action":"CONNECT","pid":2416,\n'
               ' "properties":{"command_line":"dns.exe","image_path":"C:\\\\Windows\\\\System32\\\\dns.exe",\n'
               '   "src_ip":"10.20.30.10","src_port":"42477","dst_ip":"10.20.20.10","dst_port":"53",\n'
               '   "protocol":"udp","direction":"INBOUND"}}')

    body(doc, "(2) Windows 安全审计 —— windows_event_security.xml（XML）", bold=True, after=2)
    body(doc,
         "域控制器与主机的安全事件日志。关键 EventID 包括：4624/4625（登录成功/失败）、"
         "4634/4647（注销）、4672（特殊权限）、4720/472x（账户创建/变更）、"
         "4768/4769/4771（Kerberos TGT/TGS/预认证失败）、4698（计划任务创建）、"
         "1102（日志清除）。是身份与权限类攻击动作的主要证据来源。")
    code_block(doc, '<Event><System><Provider Name="Microsoft-Windows-Security-Auditing"/>\n'
               '  <EventID>4769</EventID><TimeCreated SystemTime="2024-11-26T01:00:07Z"/>\n'
               '  <Computer>DC-01.cnc-target.local</Computer></System>\n'
               '  <EventData><Data Name="TargetUserName">attacker@CNC-TARGET.LOCAL</Data> ...')

    body(doc, "(3) Sysmon —— windows_event_sysmon.xml（XML）", bold=True, after=2)
    body(doc,
         "Sysmon 细粒度系统监控。EventID 1（进程创建，含完整命令行与父进程）、"
         "3（网络连接）、7（映像加载/DLL）、8（远程线程创建）、10（进程访问）、"
         "11（文件创建）、13（注册表值设置）、22（DNS 查询）等。"
         "与 EDR 互补，是进程级攻击链的关键证据。")

    heading(doc, "3.2 Linux 主机视角", 2)
    body(doc, "(4) Linux Syslog —— syslog.log（RFC5424 纯文本）", bold=True, after=2)
    body(doc,
         "Linux 主机系统日志，覆盖 sshd/PAM（SSH 登录与密钥交换）、cron（计划任务）、"
         "systemd、polkitd、apt/dnf（软件安装）、logrotate、journald 等守护进程行为。"
         "是 Linux 跳板机横向移动与持久化行为的证据来源。")
    code_block(doc, '<86>1 2024-11-26T01:00:42Z LINUX-JUMP-01 sshd 497018 - - \\\n'
               '  pam_unix(sshd:session): session closed for user wang.fang\n'
               '<30>1 2024-11-26T01:03:00Z LINUX-JUMP-01 CRON 498062 - - \\\n'
               '  (sysstat) CMD (command -v debian-sa1 > /dev/null && debian-sa1 1 1)')

    heading(doc, "3.3 网络流量视角（Zeek）", 2)
    body(doc,
         "Zeek 传感器对全流量进行协议级解析，输出 10 类 JSONL 日志，是网络侧攻击行为"
         "（C2、外联下载、信标、DNS）的主要证据，也是跨主机关联的关键纽带：")
    zeek_rows = [
        ("conn.json", "TCP/UDP 连接元数据（五元组、时长、字节、连接状态、Zeek UID）"),
        ("dns.json", "DNS 查询与应答（域名、qtype、answers、TTL）"),
        ("http.json", "HTTP 事务（方法、URI、host、UA、状态码、响应体大小）"),
        ("ssl.json", "TLS 握手（SNI、版本、密码套件、服务器证书指纹）"),
        ("files.json", "传输文件元数据（文件类型、SHA、大小、来源 UID）"),
        ("x509.json", "X.509 证书详情（颁发者、主体、有效期、序列号）"),
        ("dhcp.json", "DHCP 租约（MAC、主机名、分配 IP、租期）"),
        ("ntp.json", "NTP 同步请求"),
        ("ocsp.json", "证书在线状态查询"),
        ("pe.json", "可执行文件（PE）头解析"),
    ]
    make_table(doc, ["Zeek 日志", "内容"], zeek_rows, widths=[3.8, 12.9], font_size=9)
    code_block(doc, '{"ts":1732583169.77,"uid":"CrVYdtEbDC37hqxU5M",\n'
               ' "id.orig_h":"10.20.20.10","id.resp_h":"23.45.126.51","id.resp_p":80,\n'
               ' "method":"GET","host":"downloads.cloud.com","uri":"/workspace/windows/03edc8c3/manifest.json",\n'
               ' "user_agent":"python-requests/2.31.0","status_code":304}')

    page_break(doc)

    # ===== 四、噪声与真实感 =====
    heading(doc, "四、噪声、真实感与观测缺失", 1)

    heading(doc, "4.1 为什么不能「按日志条数」评分", 2)
    body(doc,
         "本数据集最关键的设计特征：不同攻击动作产生的日志条数差异极大。下表取自 "
         "OBSERVATION_MANIFEST.json，展示 apt-c48-cnc-sbie 场景中 10 个攻击步骤各自"
         "在各数据源产生的可见事件条数：")
    noise_rows = [
        ("evt-cnc-00 登录工作站", "1", "—", "1", "—"),
        ("evt-cnc-01 执行恶意 EXE", "2", "2", "2", "—"),
        ("evt-cnc-02 下载诱饵 PDF", "3", "3", "4", "10"),
        ("evt-cnc-04 上线 C2 握手", "2", "2", "3", "4"),
        ("evt-cnc-07 创建计划任务", "4", "4", "4", "—"),
        ("evt-cnc-09 周期 C2 信标", "220", "220", "242", "666"),
    ]
    make_table(doc, ["攻击步骤 (storyline)", "EDR", "Sysmon", "Win安全", "Zeek"],
               noise_rows, widths=[6.0, 2.4, 2.4, 2.6, 2.4], font_size=9)
    body(doc,
         "可以看到：「登录」一步只在端点产生 1 条记录，而「周期信标」一步在网络侧"
         "产生 666 条、在 Windows 安全日志产生 242 条。若按日志条数评分，分数会被"
         "「日志多的动作」（如 beacon）严重主导，根本无法反映智能体是否「还原了完整的"
         "攻击故事」。因此，本赛题明确规定：评分单元是「攻击步骤（storyline step）」，"
         "而非单条日志。", bold=False)

    heading(doc, "4.2 噪声来源", 2)
    bullet(doc, "基线正常活动：周一登录风暴、DNS 递归解析、SMB 文件共享、Windows 补丁"
                "（CBS）、AD 复制、备份与监控巡检、Kerberos 票据刷新等，构成海量背景噪声。")
    bullet(doc, "红鲱鱼（Red Herring）：刻意植入的「可疑但无害」行为（如非常规外联、扫描式"
                "连接、可疑 DNS），用于考验智能体的甄别能力，避免「见可疑即报警」。")
    bullet(doc, "信噪比：真实场景中攻击证据占比通常 < 1%，端到端检索与关联能力是核心考点。")

    heading(doc, "4.3 观测缺失（observation profile）", 2)
    body(doc,
         "数据集通过 observation_profile 字段模拟真实采集缺口：同一攻击动作在不同数据源"
         "的可见性不同（如某步在 Zeek 可见、在 Sysmon 不可见）。智能体必须容忍证据不完整，"
         "不能假设「每个动作在每源都有记录」。OBSERVATION_MANIFEST.json 记录了每步在每源"
         "的可见事件数，供研究与分析使用（比赛评分阶段不下发真值文件）。")

    page_break(doc)

    # ===== 五、标签体系 =====
    heading(doc, "五、攻击链（Storyline）标签体系", 1)

    heading(doc, "5.1 GROUND_TRUTH.json 结构", 2)
    body(doc, "攻击真值由 GROUND_TRUTH.json 给出，核心字段如下：")
    code_block(doc, """{
  "schema_version": 1,
  "scenario_name": "apt-c48-cnc-sbie",
  "scenario_description": "APT-C-48 (CNC) 钓鱼攻击场景 ……",
  "collection_window": { "start": "...", "end": "..." },
  "storyline_steps": [ ... ],     // ★ 有序攻击步骤（评分锚点）
  "red_herring_steps": [ ... ],   // 干扰项（可疑但无害）
  "events": [ ... ],              // 原子事件，含 IOC / attributes
  "source_evidence_status": { ... } // 每步在各源的可见事件数
}""")

    heading(doc, "5.2 storyline_steps —— 评分锚点", 2)
    body(doc,
         "storyline_steps 是一个有序数组，每个元素代表攻击链中的一个原子步骤，字段包括："
         "storyline_id（唯一标识）、index（顺序）、actor（执行主体，如受害者/攻击者/账户）、"
         "system（所在主机）、activity（人类可读动作描述）、event_types（动作类型）、"
         "attributes（关键 IOC：进程路径/PID/目的 IP/端口/Zeek UID/计划任务名/LogonID 等）。")
    body(doc, "以 apt-c48-cnc-sbie 场景为例，完整攻击链共 10 步：")
    chain_rows = [
        ("0", "evt-cnc-00", "logon", "受害者早晨登录工作站"),
        ("1", "evt-cnc-01", "process", "打开伪装 PDF 的 EXE，触发恶意执行"),
        ("2", "evt-cnc-02", "connection", "从 C2 下载诱饵 PDF 文档"),
        ("3", "evt-cnc-03", "process", "cmd.exe 打开诱饵 PDF 迷惑受害者"),
        ("4", "evt-cnc-04", "connection", "WinHTTP 上线 C2，POST 主机信息握手"),
        ("5", "evt-cnc-05", "connection", "下载后续攻击组件 scs64.exe"),
        ("6", "evt-cnc-06", "connection", "下载第二个组件 msfeedsync.exe"),
        ("7", "evt-cnc-07", "scheduled_task_created", "创建计划任务 SCS-Update 持久化"),
        ("8", "evt-cnc-08", "scheduled_task_created", "创建计划任务 User_Feed_Synchronization"),
        ("9", "evt-cnc-09", "beacon", "持久化后周期性 C2 信标通信"),
    ]
    make_table(doc, ["序号", "storyline_id", "类型", "动作描述"], chain_rows,
               widths=[1.4, 3.6, 3.4, 8.3], font_size=9)
    body(doc,
         "events 数组则是 storyline 步骤的展开：一个步骤可能对应多条原子事件"
         "（如 evt-cnc-07 同时有 process 与 scheduled_task_created 两条记录），每条带"
         "精确时间戳与 IOC 属性。storyline_id 是把日志证据回挂到攻击步骤的「主键」。", size=9.5)

    page_break(doc)

    # ===== 六、任务定义 =====
    heading(doc, "六、任务定义：输入与输出", 1)

    heading(doc, "6.1 输入", 2)
    body(doc,
         "参赛者获得：某场景 data/ 目录下的全部多源异构日志（5 大类、14 种格式）。"
         "比赛评测阶段不下发 GROUND_TRUTH.json / GROUND_TRUTH.md / OBSERVATION_MANIFEST.json。"
         "允许参赛者离线读取全部日志（端到端，不限制轮次，但计总耗时）。")

    heading(doc, "6.2 输出", 2)
    body(doc,
         "智能体须输出一条或多条结构化攻击链。每条攻击链为一个有序步骤数组，"
         "每个预测步骤应至少包含：时间戳、主机、动作类型、动作描述，以及支撑该步"
         "判断的关键 IOC 与证据引用（指向具体日志文件的记录标识）。建议的输出 JSON "
         "结构见附录 C。")

    heading(doc, "6.3 允许与禁止", 2)
    bullet(doc, "允许：读取全部日志、建立索引、调用规则/模型/大模型推理、多轮迭代。")
    bullet(doc, "允许：输出多条候选攻击链（如怀疑存在多个攻击者/多个阶段）。")
    bullet(doc, "禁止：直接访问或推断 GROUND_TRUTH；禁止输出「全部可疑事件」而交代链条"
                "结构（会被高 FP 惩罚，见第八节）。")

    # ===== 七、智能体方案 =====
    heading(doc, "七、智能体（Agent）解题方案", 1)
    body(doc,
         "推荐采用「多智能体分工协作」架构。每个 Agent 负责一个清晰阶段，"
         "通过共享的统一中间表示（IR）传递结果，最终由编排 Agent 串联工作流。")

    heading(doc, "7.1 推荐 Agent 角色", 2)
    agent_rows = [
        ("采集/解析 Agent", "读取 14 种格式日志，逐源解析为统一 IR："
         "{ts, host, actor, object, action, ioc_set, raw_ref}。处理 XML/JSONL/Syslog 差异。"),
        ("索引 Agent", "按 host / actor / IP / PID / 进程名 / Zeek UID 建倒排索引，"
         "并构建全局时间轴，支持快速邻域检索。"),
        ("检测 Agent", "在 IR 上识别可疑原子动作：可疑进程名/命令行、异常外联 IP、"
         "计划任务创建、C2 信标节奏、凭据相关 EventID 等。可用规则 + 大模型语义判断。"),
        ("关联 Agent", "跨源跨主机拼链：用 LogonID↔会话、Zeek UID↔EDR FLOW、"
         "PID↔进程树、时间因果窗、共享 IOC 把分散动作连成一条链。"),
        ("去噪/排序 Agent", "剔除基线噪声与红鲱鱼，按时间与 kill-chain 阶段对链内步骤排序，"
         "输出有序攻击故事。"),
        ("报告/自评 Agent", "生成结构化 JSON 输出，附证据引用；可对自身输出做一致性自检。"),
        ("编排 Agent", "调度上述 Agent，处理迭代与冲突（如多个候选链的合并/取舍）。"),
    ]
    make_table(doc, ["Agent", "职责"], agent_rows, widths=[3.6, 13.1], font_size=9)

    heading(doc, "7.2 跨源关联的关键纽带", 2)
    bullet(doc, "身份纽带：Windows LogonID / 用户名 ↔ Linux PAM 会话 ↔ 进程属主。")
    bullet(doc, "进程纽带：PID + 主机 ↔ 进程树父子关系 ↔ Sysmon/EDR 进程创建链。")
    bullet(doc, "网络纽带：Zeek UID 同时出现在 conn/dns/http/ssl/files，是把一次网络行为"
                "「钉死」的主键；EDR FLOW 的五元组与 Zeek conn 可按 (时间窗, 五元组) 对齐。")
    bullet(doc, "时间因果：DNS 查询 → TCP 连接 → TLS 握手 → HTTP 请求 → 文件落地 → 进程执行，"
                "形成可验证的因果时序。")
    bullet(doc, "IOC 锚点：恶意 IP/域名/进程路径/计划任务名/HASH 是高置信关联点。")

    heading(doc, "7.3 推荐工作流", 2)
    code_block(doc, """┌─────────────┐   统一IR   ┌──────────┐  倒排索引  ┌─────────────┐
│ 采集/解析   │ ─────────▶ │  索引     │ ─────────▶ │   检测       │
└─────────────┘            └──────────┘            └──────┬──────┘
                                                          │ 可疑原子动作
                                                          ▼
┌─────────────┐  有序链   ┌──────────────┐  候选链  ┌──────────────┐
│ 报告/自评   │ ◀──────── │ 去噪/排序    │ ◀────────│   关联        │
└─────────────┘           └──────────────┘          └──────────────┘
        ▲                                                    ▲
        └────────────── 编排 Agent（迭代/冲突仲裁）──────────┘""")

    page_break(doc)

    # ===== 八、评分方法（核心） =====
    heading(doc, "八、评分方法（核心）", 1)

    heading(doc, "8.1 评分原则", 2)
    body(doc,
         "本赛题评分严格遵循一条原则：评分单元是「攻击步骤（storyline step）」，"
         "不是「日志条数」。一个攻击步骤无论在原始日志中产生 1 条还是 666 条记录，"
         "在评分中权重相等。这样评分才能真实反映「智能体是否还原了完整的攻击故事」，"
         "而非「是否抓住了日志量最大的动作」。")

    heading(doc, "8.2 记号与集合定义", 2)
    bullet(doc, "G = 真实攻击步骤集合，即 GROUND_TRUTH.storyline_steps，|G| = N。")
    bullet(doc, "P̂ = 智能体预测的攻击步骤集合，|P̂| = M。")
    bullet(doc, "M(p, g) = 匹配谓词：预测步骤 p 是否命中真实步骤 g（见 8.3）。")

    heading(doc, "8.3 匹配判定规则 M(p, g)", 2)
    body(doc,
         "预测步骤 p 命中真实步骤 g，当且仅当同时满足下列条件（建议裁判规则，"
         "评测方可按数据特点微调阈值）：")
    numbered(doc, "主机一致：p.host == g.system；")
    numbered(doc, "时间落在容差窗内：|p.ts − g.first_evidence_ts| ≤ Δ（建议 Δ = 60 秒，"
                  "beacon 类长跨度动作可放宽到覆盖其首个信标时刻）；")
    numbered(doc, "语义命中（满足其一即可）：(a) 动作类型匹配 p.action_type ∈ g.event_types；"
                  "或 (b) 命中 g 的至少一个关键 IOC（dst_ip / 进程路径 / PID / 计划任务名 / "
                  "Zeek UID / LogonID 等）。")
    body(doc,
         "为避免「一个真实步骤被多个预测步骤重复消费」或「一个预测步骤命中多个真值」"
         "导致计数失真，采用一对一最优配对（如贪心或匈牙利算法）：在所有满足 M(p, g) "
         "的 (p, g) 对中，选出一组互不冲突（每个 p 与每个 g 至多出现一次）且匹配数最大的"
         "配对作为 TP。", size=10)

    heading(doc, "8.4 主公式：步骤级 Precision / Recall / F1", 2)
    body(doc, "在一对一配对完成后，定义：")
    formula(doc, "TP  =  |{ g ∈ G  :  ∃ p ∈ P̂ ,  M(p, g) 已配对 }|")
    formula(doc, "FP  =  |P̂| − TP          （预测但未命中任何真值的步骤数）")
    formula(doc, "FN  =  |G| − TP          （真实但未被任何预测命中的步骤数）")
    formula(doc, "Precision  =  TP ÷ ( TP + FP )")
    formula(doc, "Recall     =  TP ÷ ( TP + FN )")
    formula(doc, "F1  =  2 × Precision × Recall ÷ ( Precision + Recall )",
            caption="核心评分：步骤级精确率、召回率与 F1")

    body(doc, "符号对照：", bold=True, after=2)
    sym_rows = [
        ("G", "真实攻击步骤集合（Ground Truth 的 storyline_steps）"),
        ("P̂", "智能体预测的攻击步骤集合"),
        ("TP", "正确命中的真实步骤数（True Positive，一对一配对后）"),
        ("FP", "误报步骤数（预测了但不在真实攻击链中）—— 惩罚「见可疑即报」"),
        ("FN", "漏报步骤数（真实存在但未被预测）—— 惩罚「链条不完整」"),
        ("Δ", "时间容差窗（建议 60 秒；长跨度动作按首证时刻）"),
    ]
    make_table(doc, ["符号", "含义"], sym_rows, widths=[2.2, 14.5], font_size=9.5)

    heading(doc, "8.5 顺序加权（可选进阶）", 2)
    body(doc,
         "攻击链的「先后顺序」本身携带信息。在步骤级 F1 之外，可引入一个顺序得分 "
         "OrderScore，奖励预测链中步骤的相对顺序与真值一致：")
    formula(doc,
            "OrderScore  =  |{ 保持顺序的相邻对 }|  ÷  |TP 步骤构成的全部相邻对|")
    body(doc,
         "即：在已命中的 TP 步骤中，考察预测序列里任意两个步骤 (g_i, g_j)，若它们在"
         "预测序列中的相对先后与在真值序列（index）中的相对先后一致，则计为「保持顺序」。"
         "最终综合得分可取加权：")
    formula(doc, "Score  =  α × F1  +  ( 1 − α ) × OrderScore     ,     建议 α = 0.8",
            caption="综合得分：F1 为主，顺序一致性为辅")

    heading(doc, "8.6 多攻击链与多主体的处理", 2)
    body(doc,
         "若场景含多个攻击者或多条独立链，先按 (actor, host) 把真值与预测各自分组，"
         "组内分别计算 P/R/F1，再做宏平均（macro-average）得到场景级分数；"
         "数据集级分数 = 各场景分数的宏平均。")

    heading(doc, "8.7 计算示例", 2)
    body(doc,
         "以 apt-c48-cnc-sbie 场景（|G| = 10 步）为例，假设智能体预测了 11 个步骤，"
         "其中 8 个命中真值、3 个为误报：")
    ex_rows = [
        ("|G|（真实步骤数）", "10"),
        ("|P̂|（预测步骤数）", "11"),
        ("TP（命中且配对）", "8"),
        ("FP（误报）", "11 − 8 = 3"),
        ("FN（漏报）", "10 − 8 = 2"),
        ("Precision", "8 ÷ 11 ≈ 0.727"),
        ("Recall", "8 ÷ 10 = 0.800"),
        ("F1", "2 × 0.727 × 0.800 ÷ (0.727 + 0.800) ≈ 0.762"),
    ]
    make_table(doc, ["量", "值"], ex_rows, widths=[6.5, 7.5], font_size=9.5)

    page_break(doc)

    # ===== 九、基线与提交 =====
    heading(doc, "九、基线建议与提交规范", 1)
    heading(doc, "9.1 建议的渐进式基线", 2)
    numbered(doc, "基线 A（IOC 检索）：直接对已知 IOC（IP/域名/进程名）做全文检索，"
                  "召回相关步骤——简单但泛化差，作为下界参考。")
    numbered(doc, "基线 B（单源规则）：在某单一源（如 Sysmon 进程创建 + Zeek 外联）上跑规则，"
                  "检测原子动作但不做深度跨源关联。")
    numbered(doc, "基线 C（多 Agent 关联）：完整第七节方案，跨源关联 + 去噪 + 排序，作为主方案。")
    body(doc,
         "建议评测方随赛题发布评分脚本与少量示例（含真值），便于参赛者本地自测 P/R/F1。",
         size=10)

    heading(doc, "9.2 提交规范", 2)
    bullet(doc, "提交一个 JSON 文件 / 场景，结构见附录 C。")
    bullet(doc, "每个预测步骤须含 timestamp、host、action_type、description，"
                "并尽量附 iocs 与 evidence_refs（证据回链）。")
    bullet(doc, "评分以 storyline step 为单元，证据引用用于人工复核，不直接计入 P/R/F1。")

    # ===== 附录 =====
    heading(doc, "附录 A：数据字段速查表", 1)
    appA = [
        ("ecar.json", "timestamp_ms, hostname, object, action, pid, tid, properties{...}",
         "object∈{PROCESS,FLOW,MODULE,FILE,REGISTRY}; action∈{START,CONNECT,LOAD,…}"),
        ("windows_event_security.xml", "EventID, TimeCreated, Computer, EventData/Data",
         "4624/4625/4634/4672/4720/4768/4769/4771/4698/1102"),
        ("windows_event_sysmon.xml", "EventID, Execution, EventData",
         "1/3/7/8/10/11/13/22 对应进程/网络/DLL/远程线程/文件/注册表/DNS"),
        ("syslog.log", "RFC5424: pri, timestamp, host, proc, pid, msg",
         "sshd/PAM, CRON, systemd, polkitd, apt, logrotate"),
        ("zeek/*.json", "ts, uid, id.orig_h/p, id.resp_h/p",
         "uid 是跨 conn/dns/http/ssl/files 的关联主键"),
    ]
    make_table(doc, ["日志", "关键字段", "要点"], appA,
               widths=[4.2, 6.8, 5.7], font_size=8.5)

    heading(doc, "附录 B：场景清单与攻击组织", 1)
    sc_rows = [(r["name"], r["steps"], r["hosts"], r["types"]) for r in stats["rows"]]
    make_table(doc, ["场景", "步骤数", "主机数", "事件类型"], sc_rows,
               widths=[5.0, 1.8, 1.8, 8.1], font_size=8.5)
    body(doc,
         f"合计 {stats['n']} 个场景，{stats['total_steps']} 个攻击步骤，"
         f"{stats['multi_host']} 个场景涉及跨主机横向移动。", size=9)

    heading(doc, "附录 C：提交输出 JSON Schema 建议", 1)
    code_block(doc, """{
  "scenario": "apt-c48-cnc-sbie",
  "attack_chains": [
    {
      "chain_id": "chain-1",
      "actor": "zhang.wei",
      "steps": [
        {
          "step_index": 0,
          "timestamp": "2024-11-26T01:29:45Z",
          "host": "WS-ZWEI-01",
          "action_type": "logon",
          "description": "受害者交互登录工作站",
          "iocs": { "source_ip": "23.129.64.210", "logon_id": "0x6b878de" },
          "evidence_refs": [
            "data/WS-ZWEI-01.cnc-target.local/ecar.json#<record_id>",
            "data/ZEEK-CNC-CORE/conn.json#<uid>"
          ]
        }
        // ... 其余步骤
      ]
    }
  ],
  "confidence": 0.86
}""")

    body(doc, "", after=4)
    end = doc.add_paragraph()
    end.alignment = WD_ALIGN_PARAGRAPH.CENTER
    add_run(end, "— 本说明基于 output/ 下 14 个真实场景的 GROUND_TRUTH 与日志样例自动生成 —",
            size=9, italic=True, color=(0x80, 0x80, 0x80))

    OUT_DOCX.parent.mkdir(parents=True, exist_ok=True)
    doc.save(OUT_DOCX)
    print(f"✓ 已生成: {OUT_DOCX}")
    print(f"  场景: {stats['n']}  步骤: {stats['total_steps']}  "
          f"事件: {stats['total_events']}  跨主机场景: {stats['multi_host']}")


if __name__ == "__main__":
    build()
