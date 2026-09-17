"""RATIONALE: Generic MITRE ATT&CK patterns for process / command-line indicators.

Rules here are derived from publicly documented attacker tradecraft and Microsoft
DFIR / MITRE ATT&CK technique descriptions — NOT from the EvidenceForge ground
truth files. They target behavior classes (encoded scripts, LOLbin abuse, suspicious
network tooling) rather than scenario-specific paths.

References:
- T1059.001 (PowerShell), T1059.003 (cmd), T1218.005 (mshta),
  T1140 (encoded payloads), T1027 (obfuscation), T1105 (ingress tool transfer),
  T1053.005 (Scheduled Task), T1543 (Service), T1003 (OS Credential Dumping),
  T1564 (Hide Artifacts).
"""

from __future__ import annotations

import re
from typing import List

from ...parsers.base import CanonicalEvent


# Lowercase patterns matched against process_name or command_line
SUSPICIOUS_PROCESS_PATTERNS: list[tuple[str, str, str]] = [
    # (regex, technique, reason)
    (r"(?i)powershell[^\s]*\.exe", "T1059.001", "PowerShell host process — review encoded/remote activity"),
    (r"(?i)pwsh[^\s]*\.exe", "T1059.001", "PowerShell Core host process"),
    (r"(?i)cmd\.exe", "T1059.003", "cmd.exe invocation"),
    (r"(?i)mshta\.exe", "T1218.005", "mshta.exe is a LOLBin abused for HTA / remote script"),
    (r"(?i)rundll32\.exe", "T1218.011", "rundll32.exe is a LOLBin"),
    (r"(?i)regsvr32\.exe", "T1218.010", "regsvr32.exe is a LOLBin"),
    (r"(?i)wmic\.exe", "T1047", "WMIC — often abused for discovery or remote exec"),
    (r"(?i)certutil\.exe", "T1140", "certutil.exe abused for download/decode"),
    (r"(?i)bitsadmin\.exe", "T1197", "BITSAdmin abused for download"),
    (r"(?i)csc\.exe", "T1027.004", "C# compiler abuse"),
    (r"(?i)installutil\.exe", "T1218.004", "InstallUtil abuse"),
    (r"(?i)msbuild\.exe", "T1127.001", "MSBuild abuse"),
    (r"(?i)wscript\.exe", "T1059.005", "Windows Script Host"),
    (r"(?i)cscript\.exe", "T1059.005", "Console script host"),
    (r"(?i)regasm\.exe", "T1218.009", "RegAsm abuse"),
    (r"(?i)regsvcs\.exe", "T1218.009", "RegSvcs abuse"),
    (r"(?i)forfiles\.exe", "T1218", "forfiles LOLBin"),
    (r"(?i)cmstp\.exe", "T1218.003", "CMSTP abuse"),
    (r"(?i)odbcconf\.exe", "T1218.008", "ODBCConf abuse"),
    (r"(?i)msiexec\.exe", "T1218.007", "msiexec abuse"),
    (r"(?i)winword\.exe", "T1566.001", "Word spawned a child — common macro/phishing pattern"),
    (r"(?i)excel\.exe", "T1566.001", "Excel spawned a child"),
    (r"(?i)powerpnt\.exe", "T1566.001", "PowerPoint spawned a child"),
    (r"(?i)outlook\.exe", "T1566.001", "Outlook spawned a child"),
    # Linux recon / tooling
    (r"(?i)/usr/bin/(whoami|id|uname|hostname|ifconfig|ipaddr)\b", "T1059.004", "Recon utility execution"),
    (r"(?i)/usr/bin/(netstat|ss|lsof|arp)\b", "T1049", "Network/system discovery"),
    (r"(?i)/usr/bin/(find|locate|ls)\b", "T1083", "File discovery"),
    (r"(?i)/usr/bin/(nc|ncat|netcat)\b", "T1059", "Netcat-style tool"),
    (r"(?i)/usr/bin/(wget|curl)\b", "T1105", "Download tool"),
    (r"(?i)/usr/bin/(nmap|masscan|nikto|sqlmap)\b", "T1046", "Network scanner"),
    (r"(?i)/usr/bin/(base64|openssl|xxd)\b", "T1140", "Encoding/encryption tool"),
    (r"(?i)/usr/sbin/(sshd|sshd-|dropbear)\b", "T1078", "SSH daemon"),
    (r"(?i)/usr/bin/(ssh|ssh-keygen|ssh-copy-id|scp|sftp)\b", "T1021.002", "SSH client tooling"),
    (r"(?i)/usr/bin/(sudo|su)\b", "T1548.003", "Privilege escalation tool"),
    (r"(?i)/usr/bin/(systemctl|journalctl|service)\b", "T1007", "Service / log discovery"),
    (r"(?i)/usr/bin/python[23]?\b", "T1059.006", "Python interpreter — common reverse shell / post-exploit"),
    (r"(?i)/usr/bin/(perl|ruby|php)\b", "T1059", "Scripting interpreter"),
]

SUSPICIOUS_COMMANDLINE_PATTERNS: list[tuple[str, str, str]] = [
    # (regex, technique, reason)
    (r"(?i)-enc(?:odedcommand)?\s", "T1059.001", "Encoded PowerShell command"),
    (r"(?i)-e(?:nc)?\s+[A-Za-z0-9+/=]{40,}", "T1059.001", "Encoded PowerShell payload (long base64)"),
    (r"(?i)-windowstyle\s+hidden", "T1059.001", "PowerShell window hidden"),
    (r"(?i)-w(?:indowstyle)?\s+hidden", "T1059.001", "PowerShell window hidden"),
    (r"(?i)invoke-expression", "T1059.001", "Invoke-Expression (iex)"),
    (r"(?i)\biex\b", "T1059.001", "iex alias used"),
    (r"(?i)downloadstring", "T1105", "DownloadString — pull remote payload"),
    (r"(?i)downloadfile", "T1105", "DownloadFile — pull remote payload"),
    (r"(?i)WebClient\)\.Download", "T1105", "WebClient.Download — pull remote payload"),
    (r"(?i)new-object\s+net\.webclient", "T1105", "Net.WebClient instantiation"),
    (r"(?i)start-bitstransfer", "T1197", "BITS transfer"),
    (r"(?i)FromBase64String", "T1140", "Base64 decode"),
    (r"(?i)\\\[A-Za-z0-9_]+\$\\[A-Za-z0-9_$ .]+\.(exe|dll|bat|ps1|vbs|hta|js)", "T1021.002", "UNC path to executable share"),
    (r"(?i)\.ru\.com|\.cn:8080|server\.dynamic-dns|publicip|duckdns|hopto|ddns|servegame|serveftp|bounceme|redirectme|hopto\.org|myvnc|myftp|myhttp|myapi|gotdns|zapto|co\.cc", "T1071.001", "Dynamic DNS provider often abused by C2"),
    (r"(?i)nircmd|ncat|nc\.exe|netcat", "T1059", "netcat-style tooling"),
    (r"(?i)mimikatz|procdump|sekurlsa|wdigest", "T1003", "Credential dumping tooling"),
    (r"(?i)atexec|smbexec|wmiexec|psexec", "T1021.002", "Remote execution tool"),
    (r"(?i)wmic\s+.*\s+call\s+create", "T1047", "WMIC remote create"),
    (r"(?i)\bschtasks\b.*\/create", "T1053.005", "schtasks /create — persistence"),
    (r"(?i)\bcertutil\b.*-urlcache", "T1140", "certutil download"),
    (r"(?i)reg\s+add\s+.*\\run", "T1547.001", "Run key persistence"),
    (r"(?i)reg\s+add\s+.*\\currentversion", "T1547.001", "CurrentVersion key modification"),
    (r"(?i)vssadmin\s+delete\s+shadows", "T1490", "Shadow copy deletion"),
    (r"(?i)wbadmin\s+delete", "T1490", "Backup deletion"),
    (r"(?i)wevtutil\s+cl", "T1070.001", "Event log clearing"),
    (r"(?i)net\s+user\s+.*\s+/add", "T1136.001", "Local account creation"),
    (r"(?i)net\s+localgroup\s+.*\/add", "T1098", "Local group modification"),
    (r"(?i)\bping\s+-n\s+1\s+127\.0\.0\.1\s+>\s*nul", "T1059.003", "cmd sleep trick"),
    (r"(?i)timeout\s+>\s*nul\s+\d+", "T1059.003", "cmd sleep trick"),
    (r"(?i)set\s+\w+=.*&&.*&&", "T1059.003", "chained cmd.exe commands"),
    (r"(?i)\bpowershell.*-nop\b", "T1059.001", "PowerShell NoProfile"),
    (r"(?i)powershell.*-noni\b", "T1059.001", "PowerShell NonInteractive"),
    (r"(?i)officeupdate\.exe", "T1036", "Suspicious filename mimicking update"),
    (r"(?i)\.scr\b", "T1036", "Screensaver executable (often smuggled)"),
    (r"(?i)RLO|right-to-left", "T1036.002", "Right-to-left override filename spoofing"),
    # Linux discovery / recon
    (r"(?i)^\s*(cat|less|more|head|tail)\s+/etc/(passwd|shadow|hosts|hostname|sudoers|ssh/)", "T1087", "Sensitive Linux config read"),
    (r"(?i)^\s*(cat|less|more)\s+/proc/self/environ", "T1083", "Process environment read"),
    (r"(?i)^\s*find\s+/\s+-perm\s+-[24]000\b", "T1083", "find / -perm SUID/SGID — privilege escalation recon"),
    (r"(?i)^\s*find\s+/\s+-name\s+[^\n]*\.ssh", "T1083", "find / -name *.ssh — key discovery"),
    (r"(?i)^\s*(cat|head)\s+/root/", "T1083", "Read /root"),
    (r"(?i)^\s*/usr/bin/(whoami|id|hostname|uname)\b", "T1059.004", "Recon command"),
    (r"(?i)^\s*(ls|dir)\s+(-la\s+)?/(etc|root|home|var)/", "T1083", "Directory listing of sensitive paths"),
    (r"(?i)^\s*(netstat|ss)\s+(-tulpn|antp)", "T1049", "Network connection discovery"),
    (r"(?i)^\s*(arp|ip)\s+(a|route|addr)", "T1049", "Network interface discovery"),
    (r"(?i)^\s*(crontab|at)\s+-l", "T1053.003", "Cron listing"),
    (r"(?i)^\s*systemctl\s+(list-units|status|show)", "T1007", "systemd service recon"),
    (r"(?i)^\s*journalctl\b", "T1007", "Journal read"),
    (r"(?i)^\s*history\b", "T1059.004", "Bash history read"),
    (r"(?i)^\s*sudo\s+-l\b", "T1068", "sudo -l — privilege escalation recon"),
    (r"(?i)\bwget\b|\bcurl\b", "T1105", "wget/curl download"),
    (r"(?i)^\s*base64\b", "T1140", "base64 encode/decode"),
    (r"(?i)^\s*xz\b|\bgzip\b.*-d\b|\bgunzip\b", "T1140", "Decompression"),
    (r"(?i)\bnmap\b", "T1046", "nmap port scan"),
    (r"(?i)\bnc\b|\bncat\b", "T1059", "netcat"),
    (r"(?i)\bchmod\s+(\+s|[47]00[0-9])\b", "T1548.001", "Setuid bit"),
    (r"(?i)\b(rm|mv)\s+-rf?\s+/etc", "T1485", "Destructive /etc operation"),
    (r"(?i)\bdd\s+if=.*\s+of=/dev/(sd|nvme|hd)", "T1561.001", "dd to disk device"),
    (r"(?i)\bssh-keygen\b|\bssh-copy-id\b", "T1078", "SSH key generation/install"),
    (r"(?i)\bscp\s+", "T1021.002", "scp transfer"),
    (r"(?i)\brsync\s+", "T1021.002", "rsync transfer"),
    (r"(?i)\bldapsearch\b", "T1018", "ldapsearch — AD recon"),
    (r"(?i)\bcat\s+/etc/shadow\b", "T1003.008", "/etc/shadow read"),
]


def evaluate_ioc_patterns(event: CanonicalEvent) -> List[dict]:
    """Return list of {rule, technique, reason} hits for an event."""
    hits: list[dict] = []
    pn = (event.process_name or "").lower()
    cl = (event.command_line or "")

    for pattern, technique, reason in SUSPICIOUS_PROCESS_PATTERNS:
        if re.search(pattern, pn):
            hits.append({"rule": pattern, "technique": technique, "reason": reason})

    if pn and not any(h for h in hits):
        # Already matched a process pattern; skip command-line noise for low-value matches
        pass

    for pattern, technique, reason in SUSPICIOUS_COMMANDLINE_PATTERNS:
        if cl and re.search(pattern, cl):
            hits.append({"rule": pattern, "technique": technique, "reason": reason})

    # Deduplicate by technique
    seen: set[str] = set()
    unique: list[dict] = []
    for h in hits:
        if h["technique"] in seen:
            continue
        seen.add(h["technique"])
        unique.append(h)
    return unique