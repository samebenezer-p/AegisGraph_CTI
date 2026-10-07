"""
Mitigation Engine: Generates prioritized Incident Response playbooks
and executable containment scripts for Security Operations Center (SOC) teams.
"""

from typing import List, Dict, Any
from backend.models import AttackStage, MitigationAction, MitreTactic


class MitigationEngine:
    """Produces tactical containment, eradication, and recovery recommendations."""

    @classmethod
    def generate_playbook(
        cls,
        stages: List[AttackStage],
        actors: List[str],
        devices: List[str],
        ips: List[str],
        apps: List[str]
    ) -> List[MitigationAction]:
        """Synthesizes prioritized mitigation actions based on the specific attack vectors observed."""
        actions: List[MitigationAction] = []
        action_counter = 1

        # 1. External IP Containment
        for ip in ips:
            if not (ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172.16.") or ip == "127.0.0.1"):
                actions.append(MitigationAction(
                    action_id=f"mit-{action_counter}",
                    priority="CRITICAL",
                    category="CONTAINMENT",
                    title=f"Block Adversary Inbound/Outbound IP ({ip})",
                    description=f"Add perimeter firewall drop rule to null-route all communications to/from attacker infrastructure {ip}.",
                    automated_command=f"netsh advfirewall firewall add rule name=\"BLOCK_ATTACKER_{ip}\" dir=in action=block remoteip={ip}",
                    target_entity=ip
                ))
                action_counter += 1

        # 2. Compromised Identity Containment
        for user in actors:
            actions.append(MitigationAction(
                action_id=f"mit-{action_counter}",
                priority="CRITICAL",
                category="CONTAINMENT",
                title=f"Revoke Active Sessions & Reset Credentials for '{user}'",
                description=f"Immediately invalidate Kerberos/SAML tokens and force password reset for user '{user}'.",
                automated_command=f"Revoke-AzureADUserAllRefreshToken -ObjectId \"{user}\" ; Disable-ADAccount -Identity \"{user}\"",
                target_entity=user
            ))
            action_counter += 1

        # 3. Host Network Isolation
        for device in devices:
            actions.append(MitigationAction(
                action_id=f"mit-{action_counter}",
                priority="HIGH",
                category="CONTAINMENT",
                title=f"Isolate Endpoint '{device}' from Enterprise Subnet",
                description=f"Sever non-management network connectivity on host '{device}' to arrest lateral movement.",
                automated_command=f"Invoke-Command -ComputerName \"{device}\" -ScriptBlock {{ Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True ; Stop-NetAdapter -Name \"*\" -Confirm:$false }}",
                target_entity=device
            ))
            action_counter += 1

        # 4. Process Tree Termination
        for app in apps:
            if app.lower() in ("powershell.exe", "cmd.exe", "mimikatz.exe", "psexec.exe", "vssadmin.exe"):
                actions.append(MitigationAction(
                    action_id=f"mit-{action_counter}",
                    priority="HIGH",
                    category="ERADICATION",
                    title=f"Kill Malicious Process Tree for '{app}'",
                    description=f"Terminate instances of {app} and inspect memory dumps for injected payloads.",
                    automated_command=f"taskkill /F /IM {app} /T",
                    target_entity=app
                ))
                action_counter += 1

        # 5. USB / Removable Storage Lockdown (If physical exfiltration detected)
        has_usb = any(s.technique_id == "T1052.001" for s in stages)
        if has_usb:
            actions.append(MitigationAction(
                action_id=f"mit-{action_counter}",
                priority="HIGH",
                category="ERADICATION",
                title="Enforce USB Removable Storage Lockdown GPO",
                description="Immediately block write-access to USB storage devices across endpoints via Active Directory GPO.",
                automated_command="Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR' -Name 'Start' -Value 4",
                target_entity="All Endpoints / Removable Media"
            ))
            action_counter += 1

        # 6. Ransomware / Shadow Copy Recovery Check
        has_ransomware = any(s.technique_id == "T1486" for s in stages)
        if has_ransomware:
            actions.append(MitigationAction(
                action_id=f"mit-{action_counter}",
                priority="CRITICAL",
                category="RECOVERY",
                title="Trigger Immutable Offline Backup Restoration",
                description="Halt storage write I/O immediately and initiate bare-metal snapshot recovery from air-gapped immutable backups.",
                automated_command="Start-DPMBackupJob -ProtectionGroup 'MissionCriticalServers' -Type Full",
                target_entity="Core Storage Infrastructure"
            ))
            action_counter += 1

        # 7. Post-Incident Hardening
        actions.append(MitigationAction(
            action_id=f"mit-{action_counter}",
            priority="MEDIUM",
            category="RECOVERY",
            title="Deploy Canary Tokens & Enable EDR Aggressive Policy",
            description="Re-baseline user authentication, deploy decoy files (honeytokens), and enforce MFA on all internal SMB shares.",
            automated_command="Enable-MMAgent -ApplicationWhitelisting -MemoryIntegrity",
            target_entity="Enterprise Fleet"
        ))

        return actions
