# =============================================================================
# DETECTIONS DICTIONARY
# Generated from: 19 EVTX files across 3 categories
#   - Malware TTPs (DLL sideloading, timestomping, rundll32, persistence)
#   - EDR/Sysmon testing (AtomicRedTeam, EDR Testing Script, WinDefender)
#   - Network tunneling (RDP/SSH, BITS, Tunna webshell)
#   - Credential Access (Mimikatz, DCSync, hashdump, KeePass, PetitPotam)
#   - Active Directory attacks (Zerologon, Kerberoasting, DSRM, ACL abuse)
#   - Discovery & Lateral Movement (ntdsutil, IIS config, RPC)
#
# Sources: Sysmon, Security, BITS-Client, TerminalServices,
#          Windows Defender, ESENT/Application, RPC (ETW)
#
# MITRE ATT&CK techniques mapped from RuleName fields and file context.
# =============================================================================

# ---------------------------------------------------------------------------
# CHANNEL CONSTANTS — used to disambiguate duplicate Event IDs
# (e.g. EID 6 = Sysmon "Driver Loaded" vs RPC "Server Listening")
# ---------------------------------------------------------------------------
CHANNEL_SYSMON   = "Microsoft-Windows-Sysmon/Operational"
CHANNEL_SECURITY = "Security"
CHANNEL_BITS     = "Microsoft-Windows-Bits-Client/Operational"
CHANNEL_RDP_TS   = "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational"
CHANNEL_DEFENDER = "Microsoft-Windows-Windows Defender/Operational"
CHANNEL_APP      = "Application"


# ---------------------------------------------------------------------------
# SYSMON EVENT IDs  (Provider: Microsoft-Windows-Sysmon)
# ---------------------------------------------------------------------------
SYSMON_DETECTIONS = {
    1: {
        "name": "Process Creation",
        "severity": "MEDIUM",
        "technique": "Execution",
        "mitre_id": "T1059",
        "description": "New process spawned. Observed with masquerading binaries "
                       "(Flash_update.exe, WINWORD.exe) and post-exploitation tools.",
        "channel": CHANNEL_SYSMON,
    },
    2: {
        "name": "File Creation Time Changed (Timestomp)",
        "severity": "HIGH",
        "technique": "Defense Evasion",
        "mitre_id": "T1070.006",
        "description": "A process modified a file's creation timestamp. "
                       "Observed with T1099/Timestomp rule — Flash_update.exe altering NvSmart.exe timestamps.",
        "channel": CHANNEL_SYSMON,
    },
    3: {
        "name": "Network Connection",
        "severity": "MEDIUM",
        "technique": "Command and Control",
        "mitre_id": "T1071",
        "description": "Outbound network connection. Observed with mshta.exe C2 callbacks, "
                       "plink.exe RDP tunneling, and meterpreter sessions.",
        "channel": CHANNEL_SYSMON,
    },
    4: {
        "name": "Sysmon Service State Changed",
        "severity": "INFO",
        "technique": "Defense Evasion",
        "mitre_id": "T1562.001",
        "description": "Sysmon driver started or stopped. Useful for detecting "
                       "tampering with the monitoring agent itself.",
        "channel": CHANNEL_SYSMON,
    },
    5: {
        "name": "Process Terminated",
        "severity": "LOW",
        "technique": "Execution",
        "mitre_id": "T1059",
        "description": "A monitored process exited. Correlate with EID 1 for "
                       "short-lived/injected process detection.",
        "channel": CHANNEL_SYSMON,
    },
    6: {
        "name": "Driver Loaded",
        "severity": "CRITICAL",
        "technique": "Persistence / Defense Evasion",
        "mitre_id": "T1547.006",
        "description": "A driver was loaded into the kernel. "
                       "Observed with rdpdd.dll in RDP tunneling scenarios.",
        "channel": CHANNEL_SYSMON,
    },
    7: {
        "name": "Image / DLL Loaded",
        "severity": "HIGH",
        "technique": "Defense Evasion",
        "mitre_id": "T1574.002",
        "description": "DLL loaded by a process. Observed with 'dll side loading' rule — "
                       "malicious EXE loading system DLLs (winmm.dll) from wrong path. "
                       "Also flags cryptdll.dll loaded by PowerShell (Mimikatz indicator).",
        "channel": CHANNEL_SYSMON,
    },
    8: {
        "name": "CreateRemoteThread",
        "severity": "CRITICAL",
        "technique": "Defense Evasion / Privilege Escalation",
        "mitre_id": "T1055",
        "description": "A thread was injected into a remote process. "
                       "Observed with KeeFarce injecting into KeePass, "
                       "and UAC bypass / rundll32 hollowing scenarios.",
        "channel": CHANNEL_SYSMON,
    },
    10: {
        "name": "Process Access (LSASS / Credential Dumping)",
        "severity": "CRITICAL",
        "technique": "Credential Access",
        "mitre_id": "T1003.001",
        "description": "A process opened a handle to another process (e.g. LSASS). "
                       "Observed with Mimikatz, meterpreter hashdump, and TeamViewer-dumper "
                       "accessing lsass.exe.",
        "channel": CHANNEL_SYSMON,
    },
    11: {
        "name": "File Created",
        "severity": "MEDIUM",
        "technique": "Defense Evasion / Persistence",
        "mitre_id": "T1027",
        "description": "A new file was written to disk. Observed with Mimikatz memssp "
                       "writing to mimilsa.log, and malware dropping payloads.",
        "channel": CHANNEL_SYSMON,
    },
    12: {
        "name": "Registry Object Added or Deleted",
        "severity": "HIGH",
        "technique": "Defense Evasion / Persistence",
        "mitre_id": "T1112",
        "description": "Registry key created or deleted. Observed with rundll32 creating "
                       "Explorer Desktop keys, and Sysmon Install Root Certificate (T1130).",
        "channel": CHANNEL_SYSMON,
    },
    13: {
        "name": "Registry Value Set",
        "severity": "HIGH",
        "technique": "Persistence",
        "mitre_id": "T1547.001",
        "description": "Registry value modified. Observed with T1060 / Run Key persistence — "
                       "NvSmart.exe writing svchost.exe path to HKCU Run key.",
        "channel": CHANNEL_SYSMON,
    },
    16: {
        "name": "Sysmon Configuration Changed",
        "severity": "HIGH",
        "technique": "Defense Evasion",
        "mitre_id": "T1562.001",
        "description": "Sysmon configuration was reloaded or altered. "
                       "Could indicate an attacker disabling or weakening monitoring.",
        "channel": CHANNEL_SYSMON,
    },
    19: {
        "name": "WMI Event Filter Registered",
        "severity": "CRITICAL",
        "technique": "Persistence",
        "mitre_id": "T1546.003",
        "description": "A WMI event filter was created. Observed with AtomicRedTeam "
                       "WMIPersistence — polling __InstanceModificationEvent every 60s.",
        "channel": CHANNEL_SYSMON,
    },
    20: {
        "name": "WMI Event Consumer Registered",
        "severity": "CRITICAL",
        "technique": "Persistence",
        "mitre_id": "T1546.003",
        "description": "A WMI CommandLine consumer was registered. "
                       "Observed paired with EID 19 for full WMI persistence chain.",
        "channel": CHANNEL_SYSMON,
    },
    21: {
        "name": "WMI Event Consumer Bound to Filter",
        "severity": "CRITICAL",
        "technique": "Persistence",
        "mitre_id": "T1546.003",
        "description": "WMI filter-to-consumer binding completed, finalising "
                       "the WMI persistence subscription.",
        "channel": CHANNEL_SYSMON,
    },
}


# ---------------------------------------------------------------------------
# WINDOWS SECURITY EVENT IDs  (Provider: Microsoft-Windows-Security-Auditing)
# ---------------------------------------------------------------------------
SECURITY_DETECTIONS = {
    4624: {
        "name": "Successful Logon",
        "severity": "INFO",
        "technique": "Lateral Movement / Initial Access",
        "mitre_id": "T1078",
        "description": "Account successfully logged on. Logon Type 10 (RemoteInteractive) "
                       "with source IP = 127.0.0.1 / ::1 indicates RDP tunneled over SSH.",
        "channel": CHANNEL_SECURITY,
    },
    4625: {
        "name": "Failed Logon",
        "severity": "MEDIUM",
        "technique": "Credential Access",
        "mitre_id": "T1110",
        "description": "Account failed to log on. Repeated failures across accounts "
                       "indicate password spraying or brute force.",
        "channel": CHANNEL_SECURITY,
    },
    4648: {
        "name": "Explicit Credential Logon (RunAs)",
        "severity": "HIGH",
        "technique": "Privilege Escalation / Lateral Movement",
        "mitre_id": "T1134.002",
        "description": "Logon using explicit credentials (RunAs / pass-the-hash). "
                       "Observed in RDP tunnel setup and lateral movement chains.",
        "channel": CHANNEL_SECURITY,
    },
    4656: {
        "name": "Handle to Object Requested",
        "severity": "HIGH",
        "technique": "Credential Access",
        "mitre_id": "T1003.001",
        "description": "A handle was requested to a sensitive object (Process/File). "
                       "ObjectType=Process targeting lsass.exe is a precursor to credential dumping.",
        "channel": CHANNEL_SECURITY,
    },
    4662: {
        "name": "Operation Performed on Directory Object (DCSync)",
        "severity": "CRITICAL",
        "technique": "Credential Access",
        "mitre_id": "T1003.006",
        "description": "An operation was performed on an AD object. "
                       "Replication GUIDs (1131f6aa / 1131f6ad) from non-DC accounts = DCSync attack.",
        "channel": CHANNEL_SECURITY,
    },
    4663: {
        "name": "Object Access Attempt",
        "severity": "HIGH",
        "technique": "Credential Access / Collection",
        "mitre_id": "T1555",
        "description": "An attempt to access an object (File/Process). "
                       "Observed accessing browser credential stores (Chrome, Firefox, Opera) "
                       "and lsass.exe for hashdump.",
        "channel": CHANNEL_SECURITY,
    },
    4672: {
        "name": "Special Privileges Assigned to Logon",
        "severity": "HIGH",
        "technique": "Privilege Escalation",
        "mitre_id": "T1078.002",
        "description": "Sensitive privileges (SeDebugPrivilege, SeBackupPrivilege, etc.) "
                       "assigned at logon. Indicates admin or SYSTEM-level session.",
        "channel": CHANNEL_SECURITY,
    },
    4688: {
        "name": "Process Created (Security Log)",
        "severity": "MEDIUM",
        "technique": "Execution",
        "mitre_id": "T1059",
        "description": "New process created recorded in Security log. "
                       "Observed with TSTheme.exe during RDP tunnel sessions.",
        "channel": CHANNEL_SECURITY,
    },
    4702: {
        "name": "Scheduled Task Updated",
        "severity": "HIGH",
        "technique": "Persistence",
        "mitre_id": "T1053.005",
        "description": "A scheduled task was modified. Observed in ACL abuse chains "
                       "alongside SPN and password force-reset operations.",
        "channel": CHANNEL_SECURITY,
    },
    4719: {
        "name": "Audit Policy Changed",
        "severity": "CRITICAL",
        "technique": "Defense Evasion",
        "mitre_id": "T1562.002",
        "description": "System audit policy was changed. Attackers modify audit policy "
                       "to reduce logging of their activities.",
        "channel": CHANNEL_SECURITY,
    },
    4738: {
        "name": "User Account Changed",
        "severity": "HIGH",
        "technique": "Persistence / Privilege Escalation",
        "mitre_id": "T1098",
        "description": "A user account was modified. Observed in ACL abuse — "
                       "attacker (bob) forcing password or SPN change on victim (alice).",
        "channel": CHANNEL_SECURITY,
    },
    4742: {
        "name": "Computer Account Changed",
        "severity": "HIGH",
        "technique": "Persistence / Credential Access",
        "mitre_id": "T1098",
        "description": "A computer account was modified. Observed in ACL/SPN abuse — "
                       "attacker modifying machine account attributes (e.g. SPN for Kerberoasting).",
        "channel": CHANNEL_SECURITY,
    },
    4768: {
        "name": "Kerberos TGT Request",
        "severity": "MEDIUM",
        "technique": "Credential Access",
        "mitre_id": "T1558.003",
        "description": "A Kerberos TGT was requested. Status 0x12 (account disabled) "
                       "or 0x18 (wrong password) in bulk = Kerberoasting or password spray.",
        "channel": CHANNEL_SECURITY,
    },
    4771: {
        "name": "Kerberos Pre-Authentication Failed",
        "severity": "HIGH",
        "technique": "Credential Access",
        "mitre_id": "T1110.003",
        "description": "Kerberos pre-auth failed. Multiple failures across many accounts "
                       "in short time = Kerberos password spraying (observed in kerberos_pwd_spray_4771.evtx).",
        "channel": CHANNEL_SECURITY,
    },
    4794: {
        "name": "DSRM Account Password Set",
        "severity": "CRITICAL",
        "technique": "Persistence",
        "mitre_id": "T1098",
        "description": "An attempt was made to set the DSRM (Directory Services Restore Mode) "
                       "administrator password. Enables offline DC access — high-value persistence technique.",
        "channel": CHANNEL_SECURITY,
    },
    5136: {
        "name": "Directory Service Object Modified",
        "severity": "CRITICAL",
        "technique": "Privilege Escalation / Persistence",
        "mitre_id": "T1222.001",
        "description": "An AD directory object was modified. Observed with ACL abuse — "
                       "bob modifying DACL/attributes on alice's account or computer objects.",
        "channel": CHANNEL_SECURITY,
    },
    5145: {
        "name": "Network Share Object Access Check",
        "severity": "HIGH",
        "technique": "Lateral Movement / Credential Access",
        "mitre_id": "T1021.002",
        "description": "A network share was accessed. Observed in PetitPotam / "
                       "protected storage / master key theft — backdoor user accessing IPC$ and named pipes.",
        "channel": CHANNEL_SECURITY,
    },
    5156: {
        "name": "Windows Filtering Platform Connection Permitted",
        "severity": "HIGH",
        "technique": "Command and Control",
        "mitre_id": "T1572",
        "description": "WFP allowed a network connection. "
                       "DestPort=3389 with SourceIP/DestIP=loopback = RDP tunneled via SSH (plink/svchost).",
        "channel": CHANNEL_SECURITY,
    },
    5158: {
        "name": "Windows Filtering Platform Port Bind Permitted",
        "severity": "MEDIUM",
        "technique": "Command and Control",
        "mitre_id": "T1572",
        "description": "WFP permitted a local port bind. "
                       "Supports detection of local port-forward listeners set up for tunneling.",
        "channel": CHANNEL_SECURITY,
    },
    1102: {
        "name": "Audit Log Cleared",
        "severity": "CRITICAL",
        "technique": "Defense Evasion",
        "mitre_id": "T1070.001",
        "description": "The Security event log was cleared. "
                       "Strong indicator of active anti-forensics.",
        "channel": CHANNEL_SECURITY,
    },
}


# ---------------------------------------------------------------------------
# BITS CLIENT EVENT IDs  (Provider: Microsoft-Windows-Bits-Client)
# ---------------------------------------------------------------------------
BITS_DETECTIONS = {
    4: {
        "name": "BITS Job Created",
        "severity": "MEDIUM",
        "technique": "Defense Evasion / Persistence",
        "mitre_id": "T1197",
        "description": "A new BITS transfer job was created. "
                       "Abused for stealthy download/upload of payloads or C2 data.",
        "channel": CHANNEL_BITS,
    },
    59: {
        "name": "BITS Job Transfer Completed",
        "severity": "MEDIUM",
        "technique": "Defense Evasion",
        "mitre_id": "T1197",
        "description": "A BITS transfer completed. Check URL and destination path "
                       "for suspicious domains or non-standard file locations.",
        "channel": CHANNEL_BITS,
    },
    60: {
        "name": "BITS Job Completed",
        "severity": "LOW",
        "technique": "Defense Evasion",
        "mitre_id": "T1197",
        "description": "BITS job closed after successful transfer. "
                       "Correlate with EID 59 for full transfer metadata.",
        "channel": CHANNEL_BITS,
    },
    61: {
        "name": "BITS Job Error",
        "severity": "LOW",
        "technique": "Defense Evasion",
        "mitre_id": "T1197",
        "description": "A BITS transfer failed. Repeated errors to the same URL "
                       "may indicate C2 beaconing or payload staging issues.",
        "channel": CHANNEL_BITS,
    },
    209: {
        "name": "BITS Job Notification Fired",
        "severity": "LOW",
        "technique": "Defense Evasion",
        "mitre_id": "T1197",
        "description": "BITS issued a job-complete notification (isRoaming flag present). "
                       "Part of BITS abuse for execution after transfer.",
        "channel": CHANNEL_BITS,
    },
    306: {
        "name": "BITS Transfer Policy Change",
        "severity": "LOW",
        "technique": "Defense Evasion",
        "mitre_id": "T1197",
        "description": "BITS transfer policy was modified. "
                       "May indicate reconfiguration to allow unrestricted transfers.",
        "channel": CHANNEL_BITS,
    },
    310: {
        "name": "BITS Transfer Failed (Fatal Error)",
        "severity": "LOW",
        "technique": "Defense Evasion",
        "mitre_id": "T1197",
        "description": "BITS transfer failed with a fatal error code "
                       "(e.g. 0x80070052 = file exists). Useful for reconstructing failed staging attempts.",
        "channel": CHANNEL_BITS,
    },
}


# ---------------------------------------------------------------------------
# TERMINAL SERVICES / RDP EVENT IDs
# (Provider: Microsoft-Windows-TerminalServices-RemoteConnectionManager)
# ---------------------------------------------------------------------------
RDP_DETECTIONS = {
    258: {
        "name": "RDP Session Auth Failed (TS)",
        "severity": "MEDIUM",
        "technique": "Credential Access",
        "mitre_id": "T1110",
        "description": "Terminal Services authentication failure. "
                       "Bulk occurrences = RDP brute force.",
        "channel": CHANNEL_RDP_TS,
    },
    261: {
        "name": "RDP Session Disconnect",
        "severity": "LOW",
        "technique": "Lateral Movement",
        "mitre_id": "T1021.001",
        "description": "An RDP session was disconnected.",
        "channel": CHANNEL_RDP_TS,
    },
    1136: {
        "name": "RDP Session Setup Failed",
        "severity": "MEDIUM",
        "technique": "Lateral Movement",
        "mitre_id": "T1021.001",
        "description": "Terminal Services could not complete a session setup.",
        "channel": CHANNEL_RDP_TS,
    },
    1149: {
        "name": "RDP User Authentication Succeeded (TS Operational)",
        "severity": "HIGH",
        "technique": "Lateral Movement",
        "mitre_id": "T1021.001",
        "description": "User authenticated to Remote Desktop. "
                       "Source IP = loopback (127.0.0.1 or ::1) = RDP tunneled over SSH/plink "
                       "(observed in DE_RDP_Tunneling_TerminalServices file).",
        "channel": CHANNEL_RDP_TS,
    },
    1155: {
        "name": "RDP Session License Check",
        "severity": "INFO",
        "technique": "Lateral Movement",
        "mitre_id": "T1021.001",
        "description": "Terminal Services performed a license check during session setup.",
        "channel": CHANNEL_RDP_TS,
    },
}


# ---------------------------------------------------------------------------
# WINDOWS DEFENDER EVENT IDs
# (Provider: Microsoft-Windows-Windows Defender)
# ---------------------------------------------------------------------------
DEFENDER_DETECTIONS = {
    1116: {
        "name": "Malware Detected",
        "severity": "CRITICAL",
        "technique": "Execution / Credential Access",
        "mitre_id": "T1059.001",
        "description": "Windows Defender detected malware but did NOT take action. "
                       "Observed detecting Trojan:PowerShell/Powersploit.M (Mimikatz/Invoke-Mimikatz).",
        "channel": CHANNEL_DEFENDER,
    },
    1117: {
        "name": "Malware Action Taken",
        "severity": "CRITICAL",
        "technique": "Execution / Credential Access",
        "mitre_id": "T1059.001",
        "description": "Windows Defender took action (quarantine/remove) on detected malware. "
                       "Same threat as EID 1116 — confirms active remediation attempt.",
        "channel": CHANNEL_DEFENDER,
    },
}


# ---------------------------------------------------------------------------
# ESENT / APPLICATION EVENT IDs
# (Provider: ESENT — ntdsutil / ntds.dit database operations)
# ---------------------------------------------------------------------------
ESENT_DETECTIONS = {
    325: {
        "name": "ESENT Database Created",
        "severity": "CRITICAL",
        "technique": "Credential Access",
        "mitre_id": "T1003.003",
        "description": "ESENT created a new database file. In the context of ntdsutil, "
                       "this marks the start of ntds.dit / Active Directory database dumping.",
        "channel": CHANNEL_APP,
    },
    326: {
        "name": "ESENT Database Attached",
        "severity": "CRITICAL",
        "technique": "Credential Access",
        "mitre_id": "T1003.003",
        "description": "ESENT attached an existing database. "
                       "Part of the ntdsutil IFM (Install From Media) / ntds.dit extraction sequence.",
        "channel": CHANNEL_APP,
    },
    327: {
        "name": "ESENT Database Detached",
        "severity": "CRITICAL",
        "technique": "Credential Access",
        "mitre_id": "T1003.003",
        "description": "ESENT detached a database after access. "
                       "Completes the ntdsutil ntds.dit dump — "
                       "325→326→327 sequence = full NTDS credential theft.",
        "channel": CHANNEL_APP,
    },
}


# ---------------------------------------------------------------------------
# RPC ETW EVENT IDs
# (Provider: Microsoft-Windows-RPC — from etw_rpc_zerologon.evtx /
#  CA_PetiPotam_etw_rpc_efsr_5_6.evtx)
# ---------------------------------------------------------------------------
RPC_DETECTIONS = {
    6: {
        "name": "RPC Server Listening (ETW)",
        "severity": "MEDIUM",
        "technique": "Lateral Movement / Command and Control",
        "mitre_id": "T1021",
        "description": "An RPC server registered an endpoint and began listening. "
                       "Observed with Zerologon (netlogon RPC) and PetitPotam (EFSR/MS-EFSRPC interface).",
        "channel": "RPC-ETW",
    },
    9: {
        "name": "RPC Call Failed",
        "severity": "HIGH",
        "technique": "Lateral Movement",
        "mitre_id": "T1210",
        "description": "An RPC call returned an error (Status 1722 = RPC_S_SERVER_UNAVAILABLE). "
                       "Observed during PetitPotam coercion attempts — "
                       "failed coercion still leaves forensic trail.",
        "channel": "RPC-ETW",
    },
    14: {
        "name": "RPC Interface Registered (ETW)",
        "severity": "HIGH",
        "technique": "Lateral Movement / Credential Access",
        "mitre_id": "T1557",
        "description": "An RPC interface UUID was registered. "
                       "EFSR interface (35bd3360-...) = EfsRpcOpenFileRaw / PetitPotam coercion vector "
                       "for NTLM relay or credential capture.",
        "channel": "RPC-ETW",
    },
    16: {
        "name": "RPC Client Call (ETW)",
        "severity": "MEDIUM",
        "technique": "Lateral Movement",
        "mitre_id": "T1021",
        "description": "An RPC client initiated a call. "
                       "Observed in Zerologon and PetitPotam attack traces.",
        "channel": "RPC-ETW",
    },
}


# ---------------------------------------------------------------------------
# FLAT COMBINED DICTIONARY (primary lookup — channel-agnostic)
# ---------------------------------------------------------------------------
# NOTE: Where the same EID exists in multiple providers (e.g. EID 6 = Sysmon
# "Driver Loaded" AND RPC "Server Listening"), the Sysmon variant is stored
# here (most common lookup path). Use SYSMON_DETECTIONS / RPC_DETECTIONS for
# precise per-channel lookups.

DETECTIONS = {
    # ── Sysmon ──────────────────────────────────────────────────────────────
    1:    {"name": "Process Creation",                           "severity": "MEDIUM",   "technique": "Execution",                          "mitre_id": "T1059"},
    2:    {"name": "File Creation Time Changed (Timestomp)",     "severity": "HIGH",     "technique": "Defense Evasion",                    "mitre_id": "T1070.006"},
    3:    {"name": "Network Connection",                         "severity": "MEDIUM",   "technique": "Command and Control",                "mitre_id": "T1071"},
    4:    {"name": "Sysmon / BITS Job Created",                  "severity": "MEDIUM",   "technique": "Defense Evasion / Persistence",      "mitre_id": "T1197"},
    5:    {"name": "Process Terminated",                         "severity": "LOW",      "technique": "Execution",                          "mitre_id": "T1059"},
    6:    {"name": "Driver Loaded",                              "severity": "CRITICAL", "technique": "Persistence / Defense Evasion",      "mitre_id": "T1547.006"},
    7:    {"name": "Image / DLL Loaded (Side-Loading)",          "severity": "HIGH",     "technique": "Defense Evasion",                    "mitre_id": "T1574.002"},
    8:    {"name": "CreateRemoteThread (Injection)",             "severity": "CRITICAL", "technique": "Defense Evasion / Privilege Escalation", "mitre_id": "T1055"},
    9:    {"name": "RawAccessRead / RPC Call Failed",            "severity": "HIGH",     "technique": "Credential Access / Lateral Movement","mitre_id": "T1006"},
    10:   {"name": "Process Access (Credential Dumping)",        "severity": "CRITICAL", "technique": "Credential Access",                  "mitre_id": "T1003.001"},
    11:   {"name": "File Created",                               "severity": "MEDIUM",   "technique": "Defense Evasion / Persistence",      "mitre_id": "T1027"},
    12:   {"name": "Registry Object Added or Deleted",           "severity": "HIGH",     "technique": "Defense Evasion / Persistence",      "mitre_id": "T1112"},
    13:   {"name": "Registry Value Set (Run Key Persistence)",   "severity": "HIGH",     "technique": "Persistence",                        "mitre_id": "T1547.001"},
    14:   {"name": "RPC Interface Registered / Named Pipe Created","severity": "HIGH",   "technique": "Lateral Movement / Credential Access","mitre_id": "T1557"},
    16:   {"name": "Sysmon Config Changed / RPC Client Call",    "severity": "HIGH",     "technique": "Defense Evasion",                    "mitre_id": "T1562.001"},
    19:   {"name": "WMI Event Filter Registered",                "severity": "CRITICAL", "technique": "Persistence",                        "mitre_id": "T1546.003"},
    20:   {"name": "WMI Event Consumer Registered",              "severity": "CRITICAL", "technique": "Persistence",                        "mitre_id": "T1546.003"},
    21:   {"name": "WMI Consumer-Filter Binding",                "severity": "CRITICAL", "technique": "Persistence",                        "mitre_id": "T1546.003"},

    # ── BITS ─────────────────────────────────────────────────────────────────
    59:   {"name": "BITS Transfer Completed",                    "severity": "MEDIUM",   "technique": "Defense Evasion",                    "mitre_id": "T1197"},
    60:   {"name": "BITS Job Completed",                         "severity": "LOW",      "technique": "Defense Evasion",                    "mitre_id": "T1197"},
    61:   {"name": "BITS Job Error",                             "severity": "LOW",      "technique": "Defense Evasion",                    "mitre_id": "T1197"},
    209:  {"name": "BITS Notification Fired",                    "severity": "LOW",      "technique": "Defense Evasion",                    "mitre_id": "T1197"},
    306:  {"name": "BITS Policy Changed",                        "severity": "LOW",      "technique": "Defense Evasion",                    "mitre_id": "T1197"},
    310:  {"name": "BITS Transfer Fatal Error",                  "severity": "LOW",      "technique": "Defense Evasion",                    "mitre_id": "T1197"},

    # ── Terminal Services / RDP ──────────────────────────────────────────────
    258:  {"name": "RDP Auth Failed (TS)",                       "severity": "MEDIUM",   "technique": "Credential Access",                  "mitre_id": "T1110"},
    261:  {"name": "RDP Session Disconnect",                     "severity": "LOW",      "technique": "Lateral Movement",                   "mitre_id": "T1021.001"},
    1136: {"name": "RDP Session Setup Failed",                   "severity": "MEDIUM",   "technique": "Lateral Movement",                   "mitre_id": "T1021.001"},
    1149: {"name": "RDP Auth Succeeded — Loopback = SSH Tunnel", "severity": "HIGH",     "technique": "Lateral Movement",                   "mitre_id": "T1021.001"},
    1155: {"name": "RDP License Check",                          "severity": "INFO",     "technique": "Lateral Movement",                   "mitre_id": "T1021.001"},

    # ── Security Log ─────────────────────────────────────────────────────────
    1102: {"name": "Audit Log Cleared",                          "severity": "CRITICAL", "technique": "Defense Evasion",                    "mitre_id": "T1070.001"},
    4624: {"name": "Successful Logon",                           "severity": "INFO",     "technique": "Lateral Movement / Initial Access",  "mitre_id": "T1078"},
    4625: {"name": "Failed Logon",                               "severity": "MEDIUM",   "technique": "Credential Access",                  "mitre_id": "T1110"},
    4648: {"name": "Explicit Credential Logon (RunAs)",          "severity": "HIGH",     "technique": "Privilege Escalation",               "mitre_id": "T1134.002"},
    4656: {"name": "Object Handle Requested (LSASS)",            "severity": "HIGH",     "technique": "Credential Access",                  "mitre_id": "T1003.001"},
    4662: {"name": "AD Object Operation (DCSync)",               "severity": "CRITICAL", "technique": "Credential Access",                  "mitre_id": "T1003.006"},
    4663: {"name": "Object Access (Browser Creds / LSASS)",      "severity": "HIGH",     "technique": "Credential Access / Collection",     "mitre_id": "T1555"},
    4672: {"name": "Special Privileges Assigned",                "severity": "HIGH",     "technique": "Privilege Escalation",               "mitre_id": "T1078.002"},
    4688: {"name": "Process Created (Security Log)",             "severity": "MEDIUM",   "technique": "Execution",                          "mitre_id": "T1059"},
    4702: {"name": "Scheduled Task Updated",                     "severity": "HIGH",     "technique": "Persistence",                        "mitre_id": "T1053.005"},
    4719: {"name": "Audit Policy Changed",                       "severity": "CRITICAL", "technique": "Defense Evasion",                    "mitre_id": "T1562.002"},
    4738: {"name": "User Account Changed",                       "severity": "HIGH",     "technique": "Persistence / Privilege Escalation", "mitre_id": "T1098"},
    4742: {"name": "Computer Account Changed",                   "severity": "HIGH",     "technique": "Persistence / Credential Access",    "mitre_id": "T1098"},
    4768: {"name": "Kerberos TGT Request",                       "severity": "MEDIUM",   "technique": "Credential Access",                  "mitre_id": "T1558.003"},
    4771: {"name": "Kerberos Pre-Auth Failed (Password Spray)",  "severity": "HIGH",     "technique": "Credential Access",                  "mitre_id": "T1110.003"},
    4794: {"name": "DSRM Password Set",                          "severity": "CRITICAL", "technique": "Persistence",                        "mitre_id": "T1098"},
    5136: {"name": "AD Directory Object Modified (ACL Abuse)",   "severity": "CRITICAL", "technique": "Privilege Escalation / Persistence", "mitre_id": "T1222.001"},
    5145: {"name": "Network Share Object Access (Named Pipe)",   "severity": "HIGH",     "technique": "Lateral Movement / Credential Access","mitre_id": "T1021.002"},
    5156: {"name": "WFP Connection Allowed (RDP Tunnel Port)",   "severity": "HIGH",     "technique": "Command and Control",                "mitre_id": "T1572"},
    5158: {"name": "WFP Port Bind Allowed",                      "severity": "MEDIUM",   "technique": "Command and Control",                "mitre_id": "T1572"},

    # ── Windows Defender ─────────────────────────────────────────────────────
    1116: {"name": "Malware Detected (No Action)",               "severity": "CRITICAL", "technique": "Execution / Credential Access",      "mitre_id": "T1059.001"},
    1117: {"name": "Malware — Action Taken",                     "severity": "CRITICAL", "technique": "Execution / Credential Access",      "mitre_id": "T1059.001"},

    # ── ESENT / ntdsutil ──────────────────────────────────────────────────────
    325:  {"name": "ESENT Database Created (ntdsutil dump start)", "severity": "CRITICAL","technique": "Credential Access",                  "mitre_id": "T1003.003"},
    326:  {"name": "ESENT Database Attached (ntds.dit access)",  "severity": "CRITICAL", "technique": "Credential Access",                  "mitre_id": "T1003.003"},
    327:  {"name": "ESENT Database Detached (ntds.dit dump end)","severity": "CRITICAL", "technique": "Credential Access",                  "mitre_id": "T1003.003"},
}


# ---------------------------------------------------------------------------
# SEVERITY ORDER (for sorting / filtering)
# ---------------------------------------------------------------------------
SEVERITY_ORDER = {
    "CRITICAL": 0,
    "HIGH":     1,
    "MEDIUM":   2,
    "LOW":      3,
    "INFO":     4,
}


# ---------------------------------------------------------------------------
# QUICK-LOOKUP HELPERS
# ---------------------------------------------------------------------------
def get_detection(event_id: int) -> dict:
    """Return the detection entry for a given Event ID, or an UNKNOWN sentinel."""
    return DETECTIONS.get(event_id, {
        "name":      "Unknown Event",
        "severity":  "INFO",
        "technique": "Unknown",
        "mitre_id":  "N/A",
    })


def get_by_severity(severity: str) -> dict:
    """Return all DETECTIONS entries matching the given severity level."""
    return {eid: d for eid, d in DETECTIONS.items() if d["severity"] == severity}


def get_by_technique(keyword: str) -> dict:
    """Return all DETECTIONS entries whose technique contains the keyword (case-insensitive)."""
    kw = keyword.lower()
    return {eid: d for eid, d in DETECTIONS.items() if kw in d["technique"].lower()}


# ---------------------------------------------------------------------------
# SUMMARY  (run as __main__ to print the full table)
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    header = f"{'EID':<6} {'Name':<48} {'Severity':<10} {'MITRE':<12} {'Technique'}"
    print(header)
    print("-" * len(header))
    for eid in sorted(DETECTIONS.keys()):
        d = DETECTIONS[eid]
        print(f"{eid:<6} {d['name']:<48} {d['severity']:<10} {d.get('mitre_id','N/A'):<12} {d['technique']}")
    print(f"\nTotal detections: {len(DETECTIONS)}")