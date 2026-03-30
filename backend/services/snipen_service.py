"""Snipen – Host-centric Threat Hunting & Event Investigation service."""
from __future__ import annotations

import json
import time
import re
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx

from schemas.types import (
    SnipenAIQueryRequest,
    SnipenAIQueryResult,
    SnipenAnalysisResult,
    SnipenExplainResult,
    SnipenHostInfo,
    SnipenHostOverview,
    SnipenSmartEvent,
    SnipenEvent,
)
from services.wazuh_indexer import (
    _pick,
    build_auth,
    build_base_url,
    build_verify,
    detect_platform,
)


def _expand_event_id_ranges(ranges: list[tuple[int, int]]) -> list[str]:
    ids: list[str] = []
    for start, end in ranges:
        ids.extend(str(i) for i in range(start, end + 1))
    return ids


def _dedupe_preserve_order(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result


# Broad Windows Security Event ID coverage used by SNIPEN host-event fetches.
SNIPEN_WINDOWS_SECURITY_EVENT_IDS: list[str] = _expand_event_id_ranges(
    [
        (512, 697),
        (806, 809),
        (848, 861),
        (1100, 1108),
        (4608, 4719),
        (4720, 4720),
        (4722, 4799),
        (4800, 4803),
        (4816, 4826),
        (4830, 4830),
        (4864, 4900),
        (4902, 4902),
        (4904, 4913),
        (4928, 4937),
        (4944, 4965),
        (4976, 4985),
        (5024, 5025),
        (5027, 5035),
        (5037, 5051),
        (5056, 5071),
        (5120, 5127),
        (5136, 5159),
        (5168, 5170),
        (5376, 5382),
        (5440, 5453),
        (5456, 5468),
        (5471, 5474),
        (5477, 5480),
        (5483, 5485),
        (5632, 5633),
        (5712, 5712),
        (5888, 5890),
        (6144, 6145),
        (6272, 6281),
        (6400, 6410),
        (6416, 6424),
        (8191, 8191),
    ]
)

SNIPEN_EXCHANGE_EVENT_IDS: list[str] = _expand_event_id_ranges(
    [
        (25000, 25741),
    ]
)

SNIPEN_SHAREPOINT_EVENT_IDS: list[str] = _expand_event_id_ranges(
    [
        (11, 67),
    ]
)

SNIPEN_SQL_SERVER_EVENT_IDS: list[str] = _expand_event_id_ranges(
    [
        (24000, 24375),
    ]
)

SNIPEN_SYSMON_EVENT_IDS: list[str] = _dedupe_preserve_order(
    _expand_event_id_ranges(
        [
            (1, 29),
        ]
    )
    + ["225"]
)

SNIPEN_WINDOWS_DEFAULT_EVENT_IDS: list[str] = _dedupe_preserve_order(
    SNIPEN_WINDOWS_SECURITY_EVENT_IDS
    + SNIPEN_EXCHANGE_EVENT_IDS
    + SNIPEN_SHAREPOINT_EVENT_IDS
    + SNIPEN_SQL_SERVER_EVENT_IDS
    + SNIPEN_SYSMON_EVENT_IDS
)

SNIPEN_WINDOWS_SECURITY_EVENT_ID_SET: set[str] = set(SNIPEN_WINDOWS_SECURITY_EVENT_IDS)

SNIPEN_EVENT_ID_EXPLANATIONS: dict[str, str] = {
    "517": "The Windows audit log was cleared.",
    "528": "A user logon was successful.",
    "529": "A logon failed due to unknown user name or bad password.",
    "539": "A logon failed because the account is locked out.",
    "540": "A successful network logon was recorded.",
    "592": "A new process was created.",
    "601": "An attempt to install a service was detected.",
    "624": "A user account was created.",
    "628": "A user account password was set.",
    "629": "A user account was disabled.",
    "630": "A user account was deleted.",
    "642": "A user account was changed.",
    "644": "A user account was locked out.",
    "671": "A user account was unlocked.",
    "672": "A Kerberos ticket-granting ticket request was recorded.",
    "673": "A Kerberos service ticket request was recorded.",
    "675": "A Kerberos pre-authentication failure was recorded.",
    "1102": "The Windows security audit log was cleared.",
    "4608": "Windows startup sequence was logged.",
    "4609": "Windows shutdown sequence was logged.",
    "4624": "An account was successfully logged on.",
    "4625": "An account failed to log on.",
    "4634": "An account was logged off.",
    "4647": "A user initiated logoff.",
    "4648": "A logon was attempted using explicit credentials.",
    "4672": "Special privileges were assigned to a new logon session.",
    "4688": "A new process has been created.",
    "4689": "A process has exited.",
    "4697": "A service was installed on the system.",
    "4698": "A scheduled task was created.",
    "4702": "A scheduled task was updated.",
    "4719": "System audit policy was changed.",
    "4720": "A user account was created.",
    "4722": "A user account was enabled.",
    "4723": "An attempt was made to change an account password.",
    "4724": "An attempt was made to reset an account password.",
    "4725": "A user account was disabled.",
    "4726": "A user account was deleted.",
    "4728": "A member was added to a security-enabled global group.",
    "4732": "A member was added to a security-enabled local group.",
    "4738": "A user account was changed.",
    "4740": "A user account was locked out.",
    "4767": "A user account was unlocked.",
    "4768": "A Kerberos authentication ticket (TGT) was requested.",
    "4769": "A Kerberos service ticket was requested.",
    "4771": "Kerberos pre-authentication failed.",
    "4776": "A domain controller attempted to validate account credentials.",
    "4781": "An account name was changed.",
    "4798": "A user's local group membership was enumerated.",
    "4799": "A security-enabled local group membership was enumerated.",
    "5140": "A network share object was accessed.",
    "5145": "A network share access check was performed.",
    "5156": "The Windows Filtering Platform allowed a connection.",
    "5157": "The Windows Filtering Platform blocked a connection.",
    "5379": "Credential Manager credentials were read.",
    "7045": "A new service was installed on the system.",
    "1074": "A system shutdown or restart was initiated by a process/user.",
    # Legacy event IDs
    "550": "Possible denial-of-service (DoS) attack detected.",
    "561": "A handle to an object was requested.",
    "563": "Object open for delete.",
    "613": "IPsec policy agent started.",
    "614": "IPsec policy agent disabled.",
    "615": "IPsec policy agent event recorded.",
    "616": "IPsec policy agent encountered a potential serious failure.",
    "619": "Quality of Service Policy changed.",
    "625": "User account type changed.",
    "640": "General account database changed.",
    # Windows Security Event IDs - Authentication & Logon
    "4610": "An authentication package has been loaded by the Local Security Authority.",
    "4611": "A trusted logon process has been registered with the Local Security Authority.",
    "4612": "Internal resources allocated for queuing audit messages have been exhausted, leading to the loss of some audits.",
    "4614": "A notification package has been loaded by the Security Account Manager.",
    "4615": "Invalid use of LPC port.",
    "4616": "The system time was changed.",
    "4618": "A monitored security event pattern has occurred.",
    "4621": "Administrator recovered system from CrashOnAuditFail; users who are not administrators will now be allowed to log on.",
    "4622": "A security package has been loaded by the Local Security Authority.",
    "4646": "IKE DoS-prevention mode started.",
    "4649": "A replay attack was detected. May be a harmless false positive due to misconfiguration error.",
    "4650": "An IPsec Main Mode security association was established without Extended Mode or certificate authentication.",
    "4651": "An IPsec Main Mode security association was established using certificate authentication.",
    "4652": "An IPsec Main Mode negotiation failed.",
    "4653": "An IPsec Main Mode negotiation failed.",
    "4654": "An IPsec Quick Mode negotiation failed.",
    "4655": "An IPsec Main Mode security association ended.",
    # Object access
    "4656": "A handle to an object was requested.",
    "4657": "A registry value was modified.",
    "4658": "The handle to an object was closed.",
    "4659": "A handle to an object was requested with intent to delete.",
    "4660": "An object was deleted.",
    "4661": "A handle to an object was requested.",
    "4662": "An operation was performed on an object.",
    "4663": "An attempt was made to access an object.",
    "4664": "An attempt was made to create a hard link.",
    "4665": "An attempt was made to create an application client context.",
    "4666": "An application attempted an operation.",
    "4667": "An application client context was deleted.",
    "4668": "An application was initialized.",
    "4670": "Permissions on an object were changed.",
    "4671": "An application attempted to access a blocked ordinal through the TBS.",
    # Privilege use
    "4673": "A privileged service was called.",
    "4674": "An operation was attempted on a privileged object.",
    "4675": "SIDs were filtered.",
    # Process & token
    "4690": "An attempt was made to duplicate a handle to an object.",
    "4691": "Indirect access to an object was requested.",
    "4692": "Backup of data protection master key was attempted.",
    "4693": "Recovery of data protection master key was attempted.",
    "4694": "Protection of auditable protected data was attempted.",
    "4695": "Unprotection of auditable protected data was attempted.",
    "4696": "A primary token was assigned to a process.",
    # Scheduled tasks
    "4699": "A scheduled task was deleted.",
    "4700": "A scheduled task was enabled.",
    "4701": "A scheduled task was disabled.",
    # User rights & trust
    "4704": "A user right was assigned.",
    "4705": "A user right was removed.",
    "4706": "A new trust was created to a domain.",
    "4707": "A trust to a domain was removed.",
    # IPsec Services
    "4709": "IPsec Services was started.",
    "4710": "IPsec Services was disabled.",
    "4711": "PAStore Engine applied or failed to apply IPsec policy on the computer.",
    "4712": "IPsec Services encountered a potentially serious failure.",
    # Kerberos & policy
    "4713": "Kerberos policy was changed.",
    "4714": "Encrypted data recovery policy was changed.",
    "4715": "The audit policy (SACL) on an object was changed.",
    "4716": "Trusted domain information was modified.",
    "4717": "System security access was granted to an account.",
    "4718": "System security access was removed from an account.",
    # Group management
    "4727": "A security-enabled global group was created.",
    "4729": "A member was removed from a security-enabled global group.",
    "4730": "A security-enabled global group was deleted.",
    "4731": "A security-enabled local group was created.",
    "4733": "A member was removed from a security-enabled local group.",
    "4734": "A security-enabled local group was deleted.",
    "4735": "A security-enabled local group was changed.",
    "4737": "A security-enabled global group was changed.",
    "4739": "Domain Policy was changed.",
    "4741": "A computer account was changed.",
    "4742": "A computer account was changed.",
    "4743": "A computer account was deleted.",
    "4744": "A security-disabled local group was created.",
    "4745": "A security-disabled local group was changed.",
    "4746": "A member was added to a security-disabled local group.",
    "4747": "A member was removed from a security-disabled local group.",
    "4748": "A security-disabled local group was deleted.",
    "4749": "A security-disabled global group was created.",
    "4750": "A security-disabled global group was changed.",
    "4751": "A member was added to a security-disabled global group.",
    "4752": "A member was removed from a security-disabled global group.",
    "4753": "A security-disabled global group was deleted.",
    "4754": "A security-enabled universal group was created.",
    "4755": "A security-enabled universal group was changed.",
    "4756": "A member was added to a security-enabled universal group.",
    "4757": "A member was removed from a security-enabled universal group.",
    "4758": "A security-enabled universal group was deleted.",
    "4759": "A security-disabled universal group was created.",
    "4760": "A security-disabled universal group was changed.",
    "4761": "A member was added to a security-disabled universal group.",
    "4762": "A member was removed from a security-disabled universal group.",
    "4764": "A security-disabled group was deleted or a group's type was changed.",
    "4765": "SID History was added to an account.",
    "4766": "An attempt to add SID History to an account failed.",
    # Kerberos
    "4770": "A Kerberos service ticket was renewed.",
    "4772": "A Kerberos authentication ticket request failed.",
    "4774": "An account was mapped for logon.",
    "4775": "An account could not be mapped for logon.",
    "4777": "The domain controller failed to validate the credentials for an account.",
    "4778": "A session was reconnected to a Window Station.",
    "4779": "A session was disconnected from a Window Station.",
    # Account & group management (continued)
    "4780": "The ACL was set on accounts which are members of administrators groups.",
    "4782": "The password hash of an account was accessed.",
    "4783": "A basic application group was created.",
    "4784": "A basic application group was changed.",
    "4785": "A member was added to a basic application group.",
    "4786": "A member was removed from a basic application group.",
    "4787": "A nonmember was added to a basic application group.",
    "4788": "A nonmember was removed from a basic application group.",
    "4789": "A basic application group was deleted.",
    "4790": "An LDAP query group was created.",
    "4793": "The Password Policy Checking API was called.",
    "4794": "An attempt was made to set the Directory Services Restore Mode administrator password.",
    # Workstation
    "4800": "The workstation was locked.",
    "4801": "The workstation was unlocked.",
    "4802": "The screen saver was invoked.",
    "4803": "The screen saver was dismissed.",
    # RPC & network
    "4816": "RPC detected an integrity violation while decrypting an incoming message.",
    "4864": "A namespace collision was detected.",
    "4865": "A trusted forest information entry was added.",
    "4866": "A trusted forest information entry was removed.",
    "4867": "A trusted forest information entry was modified.",
    # Certificate Services
    "4868": "The certificate manager denied a pending certificate request.",
    "4869": "Certificate Services received a resubmitted certificate request.",
    "4870": "Certificate Services revoked a certificate.",
    "4871": "Certificate Services received a request to publish the certificate revocation list (CRL).",
    "4872": "Certificate Services published the certificate revocation list (CRL).",
    "4873": "A certificate request extension changed.",
    "4874": "One or more certificate request attributes changed.",
    "4875": "Certificate Services received a request to shut down.",
    "4876": "Certificate Services backup started.",
    "4877": "Certificate Services backup completed.",
    "4878": "Certificate Services restore started.",
    "4879": "Certificate Services restore completed.",
    "4880": "Certificate Services started.",
    "4881": "Certificate Services stopped.",
    "4882": "The security permissions for Certificate Services changed.",
    "4883": "Certificate Services retrieved an archived key.",
    "4884": "Certificate Services imported a certificate into its database.",
    "4885": "The audit filter for Certificate Services changed.",
    "4886": "Certificate Services received a certificate request.",
    "4887": "Certificate Services approved a certificate request and issued a certificate.",
    "4888": "Certificate Services denied a certificate request.",
    "4889": "Certificate Services set the status of a certificate request to pending.",
    "4890": "The certificate manager settings for Certificate Services changed.",
    "4891": "A configuration entry changed in Certificate Services.",
    "4892": "A property of Certificate Services changed.",
    "4893": "Certificate Services archived a key.",
    "4894": "Certificate Services imported and archived a key.",
    "4895": "Certificate Services published the CA certificate to Active Directory Domain Services.",
    "4896": "One or more rows have been deleted from the certificate database.",
    "4897": "Role separation was enabled in Certificate Services.",
    "4898": "Certificate Services loaded a template.",
    # Audit policy
    "4902": "The Per-user audit policy table was created.",
    "4904": "An attempt was made to register a security event source.",
    "4905": "An attempt was made to unregister a security event source.",
    "4906": "The CrashOnAuditFail value has changed.",
    "4907": "Auditing settings on an object were changed.",
    "4908": "Special Groups Logon table modified.",
    "4909": "The local policy settings for the TBS were changed.",
    "4910": "The Group Policy settings for the TBS were changed.",
    "4912": "Per User Audit Policy was changed.",
    # Active Directory replication
    "4928": "An Active Directory replica source naming context was established.",
    "4929": "An Active Directory replica source naming context was removed.",
    "4930": "An Active Directory replica source naming context was modified.",
    "4931": "An Active Directory replica destination naming context was modified.",
    "4932": "Synchronization of a replica of an Active Directory naming context has begun.",
    "4933": "Synchronization of a replica of an Active Directory naming context has ended.",
    "4934": "Attributes of an Active Directory object were replicated.",
    "4935": "Replication failure begins.",
    "4936": "Replication failure ends.",
    "4937": "A lingering object was removed from a replica.",
    # Windows Firewall
    "4944": "The following policy was active when the Windows Firewall started.",
    "4945": "A rule was listed when the Windows Firewall started.",
    "4946": "A rule was added to the Windows Firewall exception list.",
    "4947": "A rule was modified in the Windows Firewall exception list.",
    "4948": "A rule was deleted from the Windows Firewall exception list.",
    "4949": "Windows Firewall settings were restored to the default values.",
    "4950": "A Windows Firewall setting has changed.",
    "4951": "A rule has been ignored because its major version number was not recognized by Windows Firewall.",
    "4952": "Parts of a rule have been ignored because its minor version number was not recognized by Windows Firewall.",
    "4953": "A rule has been ignored by Windows Firewall because it could not parse the rule.",
    "4954": "Windows Firewall Group Policy settings have changed and the new settings have been applied.",
    "4956": "Windows Firewall has changed the active profile.",
    "4957": "Windows Firewall did not apply the following rule.",
    "4958": "Windows Firewall did not apply a rule because it referred to items not configured on this computer.",
    # IPsec
    "4960": "IPsec dropped an inbound packet that failed an integrity check.",
    "4961": "IPsec dropped an inbound packet that failed a replay check.",
    "4962": "IPsec dropped an inbound packet with too low a sequence number to ensure it was not a replay.",
    "4963": "IPsec dropped an inbound clear text packet that should have been secured.",
    "4964": "Special groups have been assigned to a new logon.",
    "4965": "IPsec received a packet from a remote computer with an incorrect Security Parameter Index (SPI).",
    "4976": "During Main Mode negotiation, IPsec received an invalid negotiation packet.",
    "4977": "During Quick Mode negotiation, IPsec received an invalid negotiation packet.",
    "4978": "During Extended Mode negotiation, IPsec received an invalid negotiation packet.",
    "4979": "IPsec Main Mode and Extended Mode security associations were established.",
    "4980": "IPsec Main Mode and Extended Mode security associations were established.",
    "4981": "IPsec Main Mode and Extended Mode security associations were established.",
    "4982": "IPsec Main Mode and Extended Mode security associations were established.",
    "4983": "An IPsec Extended Mode negotiation failed; the corresponding Main Mode security association has been deleted.",
    "4984": "An IPsec Extended Mode negotiation failed; the corresponding Main Mode security association has been deleted.",
    "4985": "The state of a transaction has changed.",
    # Windows Firewall service
    "5024": "The Windows Firewall Service has started successfully.",
    "5025": "The Windows Firewall Service has been stopped.",
    "5027": "The Windows Firewall Service was unable to retrieve the security policy from local storage.",
    "5028": "The Windows Firewall Service was unable to parse the new security policy.",
    "5029": "The Windows Firewall Service failed to initialize the driver.",
    "5030": "The Windows Firewall Service failed to start.",
    "5031": "The Windows Firewall Service blocked an application from accepting incoming connections on the network.",
    "5032": "Windows Firewall was unable to notify the user that it blocked an application from accepting incoming connections.",
    "5033": "The Windows Firewall Driver has started successfully.",
    "5034": "The Windows Firewall Driver has been stopped.",
    "5035": "The Windows Firewall Driver failed to start.",
    "5037": "The Windows Firewall Driver detected a critical runtime error and terminated.",
    "5038": "Code integrity determined that the image hash of a file is not valid – possible unauthorized modification or disk device error.",
    # Virtualization & filtering
    "5039": "A registry key was virtualized.",
    "5040": "An Authentication Set was added to IPsec settings.",
    "5041": "An Authentication Set was modified in IPsec settings.",
    "5042": "An Authentication Set was deleted from IPsec settings.",
    "5043": "A Connection Security Rule was added to IPsec settings.",
    "5044": "A Connection Security Rule was modified in IPsec settings.",
    "5045": "A Connection Security Rule was deleted from IPsec settings.",
    "5046": "A Crypto Set was added to IPsec settings.",
    "5047": "A Crypto Set was modified in IPsec settings.",
    "5048": "A Crypto Set was deleted from IPsec settings.",
    "5049": "An IPsec Security Association was deleted.",
    "5050": "An attempt was made to programmatically disable Windows Firewall.",
    "5051": "A file was virtualized.",
    # Cryptographic operations
    "5056": "A cryptographic self-test was performed.",
    "5057": "A cryptographic primitive operation failed.",
    "5058": "Key file operation.",
    "5059": "Key migration operation.",
    "5060": "Verification operation failed.",
    "5061": "Cryptographic operation.",
    "5062": "A kernel-mode cryptographic self-test was performed.",
    "5063": "A cryptographic provider operation was attempted.",
    "5064": "A cryptographic context operation was attempted.",
    "5065": "A cryptographic context modification was attempted.",
    "5066": "A cryptographic function operation was attempted.",
    "5067": "A cryptographic function modification was attempted.",
    "5068": "A cryptographic function provider operation was attempted.",
    "5069": "A cryptographic function property operation was attempted.",
    "5070": "A cryptographic function property modification was attempted.",
    # OCSP Responder Service
    "5120": "OCSP Responder Service started.",
    "5121": "OCSP Responder Service stopped.",
    "5122": "A configuration entry changed in OCSP Responder Service.",
    "5123": "A configuration entry changed in OCSP Responder Service.",
    "5124": "A security setting was updated on the OCSP Responder Service.",
    "5125": "A request was submitted to the OCSP Responder Service.",
    "5126": "Signing Certificate was automatically updated by the OCSP Responder Service.",
    "5127": "The OCSP Revocation Provider successfully updated the revocation information.",
    # Directory service
    "5136": "A directory service object was modified.",
    "5137": "A directory service object was created.",
    "5138": "A directory service object was undeleted.",
    "5139": "A directory service object was moved.",
    "5141": "A directory service object was deleted.",
    # Windows Filtering Platform
    "5152": "The Windows Filtering Platform blocked a packet.",
    "5153": "A more restrictive Windows Filtering Platform filter has blocked a packet.",
    "5154": "The Windows Filtering Platform permitted an application or service to listen on a port for incoming connections.",
    "5155": "The Windows Filtering Platform blocked an application or service from listening on a port.",
    "5158": "The Windows Filtering Platform permitted a bind to a local port.",
    "5159": "The Windows Filtering Platform blocked a bind to a local port.",
    # Credential Manager
    "5376": "Credential Manager credentials were backed up.",
    "5377": "Credential Manager credentials were restored from a backup.",
    "5378": "The requested credentials delegation was disallowed by policy.",
    # Windows Filtering Platform engine startup
    "5440": "The following callout was present when the Windows Filtering Platform Base Filtering Engine started.",
    "5441": "The following filter was present when the Windows Filtering Platform Base Filtering Engine started.",
    "5442": "The following provider was present when the Windows Filtering Platform Base Filtering Engine started.",
    "5443": "The following provider context was present when the Windows Filtering Platform Base Filtering Engine started.",
    "5444": "The following sublayer was present when the Windows Filtering Platform Base Filtering Engine started.",
    "5446": "A Windows Filtering Platform callout has been changed.",
    "5447": "A Windows Filtering Platform filter has been changed.",
    "5448": "A Windows Filtering Platform provider has been changed.",
    "5449": "A Windows Filtering Platform provider context has been changed.",
    "5450": "A Windows Filtering Platform sublayer has been changed.",
    "5451": "An IPsec Quick Mode security association was established.",
    "5452": "An IPsec Quick Mode security association ended.",
    "5453": "An IPsec negotiation with a remote computer failed because the IKEEXT service is not started.",
    # PAStore Engine
    "5456": "PAStore Engine applied Active Directory storage IPsec policy on the computer.",
    "5457": "PAStore Engine failed to apply Active Directory storage IPsec policy on the computer.",
    "5458": "PAStore Engine applied locally cached copy of Active Directory storage IPsec policy.",
    "5459": "PAStore Engine failed to apply locally cached copy of Active Directory storage IPsec policy.",
    "5460": "PAStore Engine applied local registry storage IPsec policy on the computer.",
    "5461": "PAStore Engine failed to apply local registry storage IPsec policy on the computer.",
    "5462": "PAStore Engine failed to apply some rules of the active IPsec policy on the computer.",
    "5463": "PAStore Engine polled for changes to the active IPsec policy and detected no changes.",
    "5464": "PAStore Engine polled for changes to the active IPsec policy, detected changes, and applied them.",
    "5465": "PAStore Engine received a control for forced reloading of IPsec policy and processed it successfully.",
    "5466": "PAStore Engine polled for changes — Active Directory unreachable, using cached IPsec policy instead.",
    "5467": "PAStore Engine polled for changes — Active Directory reachable, no changes found, cached policy no longer used.",
    "5468": "PAStore Engine polled for changes — Active Directory reachable, changes found and applied, cached policy no longer used.",
    "5471": "PAStore Engine loaded local storage IPsec policy on the computer.",
    "5472": "PAStore Engine failed to load local storage IPsec policy on the computer.",
    "5473": "PAStore Engine loaded directory storage IPsec policy on the computer.",
    "5474": "PAStore Engine failed to load directory storage IPsec policy on the computer.",
    "5477": "PAStore Engine failed to add quick mode filter.",
    "5478": "IPsec Services has started successfully.",
    "5479": "IPsec Services has been shut down successfully.",
    "5480": "IPsec Services failed to get the complete list of network interfaces; some interfaces may not be protected.",
    "5483": "IPsec Services failed to initialize RPC server and could not be started.",
    "5484": "IPsec Services experienced a critical failure and has been shut down.",
    "5485": "IPsec Services failed to process some IPsec filters on a plug-and-play event for network interfaces.",
    # Network authentication
    "5632": "A request was made to authenticate to a wireless network.",
    "5633": "A request was made to authenticate to a wired network.",
    "5712": "A Remote Procedure Call (RPC) was attempted.",
    # Netlogon
    "5827": "The Netlogon service denied a vulnerable Netlogon secure channel connection from a machine account.",
    "5828": "The Netlogon service denied a vulnerable Netlogon secure channel connection using a trust account.",
    # COM+ Catalog
    "5888": "An object in the COM+ Catalog was modified.",
    "5889": "An object was deleted from the COM+ Catalog.",
    "5890": "An object was added to the COM+ Catalog.",
    # System events
    "6008": "The previous system shutdown was unexpected.",
    "6144": "Security policy in the Group Policy objects has been applied successfully.",
    "6145": "One or more errors occurred while processing security policy in the Group Policy objects.",
    # Network Policy Server
    "6272": "Network Policy Server granted access to a user.",
    "6273": "Network Policy Server denied access to a user.",
    "6274": "Network Policy Server discarded the request for a user.",
    "6275": "Network Policy Server discarded the accounting request for a user.",
    "6276": "Network Policy Server quarantined a user.",
    "6277": "Network Policy Server granted access to a user but put it on probation because the host did not meet the health policy.",
    "6278": "Network Policy Server granted full access to a user because the host met the defined health policy.",
    "6279": "Network Policy Server locked the user account due to repeated failed authentication attempts.",
    "6280": "Network Policy Server unlocked the user account.",
    # BitLocker / volume encryption
    "24577": "Encryption of volume started.",
    "24578": "Encryption of volume stopped.",
    "24579": "Encryption of volume completed.",
    "24580": "Decryption of volume started.",
    "24581": "Decryption of volume stopped.",
    "24582": "Decryption of volume completed.",
    "24583": "Conversion worker thread for volume started.",
    "24584": "Conversion worker thread for volume temporarily stopped.",
    "24586": "An error was encountered converting volume.",
    "24588": "The conversion operation on a volume encountered a bad sector error.",
    "24592": "An attempt to automatically restart conversion on a volume failed.",
    "24593": "Metadata write error on volume while trying to modify metadata; decrypt volume if failures continue.",
    "24594": "Metadata rebuild failure on volume; decrypt volume if failures continue.",
    "24595": "Volume contains bad clusters that will be skipped during conversion.",
    "24621": "Initial state check: Rolling volume conversion transaction.",
    # Legacy event IDs - Kerberos authentication
    "674": "A security principal renewed an AS ticket or TGS ticket.",
    "676": "Authentication ticket request failed. Not generated in Windows XP or Server 2003 family.",
    "677": "A TGS ticket was not granted. Not generated in Windows XP or Server 2003 family.",
    "678": "An account was successfully mapped to a domain account.",
    "681": "Logon failure - a domain account logon was attempted. Not generated in Windows XP or Server 2003 family.",
    "682": "A user has reconnected to a disconnected terminal server session.",
    "683": "A user disconnected a terminal server session without logging off.",
    "685": "Set the security descriptor of members of administrative groups.",
    # Legacy event IDs - Object access
    "560": "Access was granted to an already existing object.",
    "562": "A handle to an object was closed.",
    "564": "A protected object was deleted.",
    "565": "Access was granted to an already existing object type.",
    "566": "A generic object operation took place.",
    "567": "A permission associated with a handle was used.",
    "568": "An attempt was made to create a hard link to a file that is being audited.",
    "569": "The resource manager in Authorization Manager attempted to create a client context.",
    "570": "A client attempted to access an object.",
    "571": "The client context was deleted by the Authorization Manager application.",
    "572": "The administrator manager initialized the application.",
    # Legacy event IDs - Certificate Services
    "772": "The certificate manager denied a pending certificate request.",
    "773": "Certificate Services received a resubmitted certificate request.",
    "774": "Certificate Services revoked a certificate.",
    "775": "Certificate Services received a request to publish the certificate revocation list (CRL).",
    "776": "Certificate Services published the certificate revocation list (CRL).",
    "777": "A certificate request extension was made.",
    "778": "One or more certificate request attributes changed.",
    "779": "Certificate Services received a request to shut down.",
    "780": "Certificate Services backup started.",
    "781": "Certificate Services backup completed.",
    "782": "Certificate Services restore started.",
    "783": "Certificate Services restore completed.",
    "784": "Certificate Services started.",
    "785": "Certificate Services stopped.",
    "786": "The security permissions for Certificate Services changed.",
    "787": "Certificate Services retrieved an archived key.",
    "788": "Certificate Services imported a certificate into its database.",
    "789": "The audit filter for Certificate Services changed.",
    "790": "Certificate Services received a certificate request.",
    "791": "Certificate Services approved a certificate request and issued a certificate.",
    "792": "Certificate Services denied a certificate request.",
    "793": "Certificate Services set the status of a certificate request to pending.",
    "794": "The certificate manager settings for Certificate Services changed.",
    "795": "A configuration entry changed in Certificate Services.",
    "796": "A property of Certificate Services changed.",
    "797": "Certificate Services archived a key.",
    "798": "Certificate Services imported and archived a key.",
    "799": "Certificate Services published the CA certificate to Active Directory.",
    "800": "One or more rows have been deleted from the certificate database.",
    "801": "Role separation enabled in Certificate Services.",
    # Legacy event IDs - User rights & trust
    "608": "A user right was assigned.",
    "609": "A user right was removed.",
    "610": "A trust relationship with another domain was created.",
    "611": "A trust relationship with another domain was removed.",
    "612": "An audit policy was changed.",
    "617": "A Kerberos policy changed.",
    "618": "Encrypted Data Recovery policy changed.",
    "620": "A trust relationship with another domain was modified.",
    "621": "System access was granted to an account.",
    "622": "System access was removed from an account.",
    "623": "Per user auditing policy was set for a user.",
    # Legacy event IDs - Forest trust & namespace
    "768": "A collision was detected between a namespace element in one forest and a namespace element in another forest.",
    "769": "Trusted forest information was added.",
    "770": "Trusted forest information was deleted.",
    "771": "Trusted forest information was modified.",
    "805": "The event log service read the security log configuration for a session.",
    # Legacy event IDs - Privilege use
    "576": "Specified privileges were added to a user's access token.",
    "577": "A user attempted to perform a privileged system service operation.",
    "578": "Privileges were used on an already open handle to a protected object.",
    # Legacy event IDs - Process tracking
    "593": "A process exited.",
    "594": "A handle to an object was duplicated.",
    "595": "Indirect access to an object was obtained.",
    "596": "A data protection master key was backed up.",
    "597": "A data protection master key was recovered from a recovery server.",
    "598": "Auditable data was protected.",
    "599": "Auditable data was unprotected.",
    "600": "A process was assigned a primary token.",
    "602": "A scheduler job was created.",
    # Legacy event IDs - System
    "512": "Windows is starting up.",
    "513": "Windows is shutting down.",
    "514": "An authentication package was loaded by the Local Security Authority.",
    "515": "A trusted logon process has registered with the Local Security Authority.",
    "516": "Internal resources allocated for queuing security event messages have been exhausted, leading to loss of some security event messages.",
    "518": "A notification package was loaded by the Security Accounts Manager.",
    "519": "A process is using an invalid local procedure call (LPC) port in an attempt to impersonate a client.",
    "520": "The system time was changed.",
    # Group management (legacy)
    "4763": "A security-disabled universal group was deleted.",
}


def _contains_token(values: list[str], token: str) -> bool:
    token_lower = token.lower()
    return any(token_lower in value.lower() for value in values)


def _resolve_event_explanation(
    event_id: str | None,
    rule_description: str | None,
    decoder: str | None,
    groups: list[str],
) -> str | None:
    if event_id and event_id in SNIPEN_EVENT_ID_EXPLANATIONS:
        return SNIPEN_EVENT_ID_EXPLANATIONS[event_id]

    if not event_id:
        return rule_description

    desc_text = (rule_description or "").lower()
    decoder_text = (decoder or "").lower()
    is_sysmon = "sysmon" in decoder_text or "sysmon" in desc_text or _contains_token(groups, "sysmon")
    is_exchange = "exchange" in decoder_text or "exchange" in desc_text or _contains_token(groups, "exchange")
    is_sharepoint = "sharepoint" in decoder_text or "sharepoint" in desc_text or _contains_token(groups, "sharepoint")
    is_sql = "sql" in decoder_text or "sql" in desc_text or _contains_token(groups, "sql")

    try:
        event_number = int(event_id)
    except (TypeError, ValueError):
        event_number = None

    if event_number is not None:
        if event_number == 225 or is_sysmon or 1 <= event_number <= 29:
            return f"Sysmon event ID {event_id}: endpoint telemetry event from Sysmon."
        if is_exchange or 25000 <= event_number <= 25741:
            return f"Exchange event ID {event_id}: Exchange mailbox/admin audit operation."
        if is_sql or 24000 <= event_number <= 24375:
            return f"SQL Server event ID {event_id}: SQL audit/action event."
        if is_sharepoint or 11 <= event_number <= 67:
            return f"SharePoint event ID {event_id}: SharePoint audit activity."

    if event_id in SNIPEN_WINDOWS_SECURITY_EVENT_ID_SET:
        return f"Windows security event ID {event_id}."

    if rule_description:
        return rule_description

    return f"Event ID {event_id} (no mapped explanation available)."


# ── Indexer helpers ──────────────────────────────────────────────────────────

def _index_pattern(connection: dict[str, Any]) -> str:
    return connection.get("indexer_index_pattern", "wazuh-alerts-*")


def _time_range_filter(hours: int) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    start = now - timedelta(hours=hours)
    return {
        "range": {
            "@timestamp": {
                "gte": start.isoformat(),
                "lte": now.isoformat(),
            }
        }
    }


# ── Host listing ─────────────────────────────────────────────────────────────

def get_snipen_hosts(connection: dict[str, Any], hours: int = 24) -> list[SnipenHostInfo]:
    """
    Aggregate all unique agent.name values from the indexer within the last
    `hours` hours, returning alert counts and basic metadata.
    """
    payload: dict[str, Any] = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [_time_range_filter(hours)]
            }
        },
        "aggs": {
            "hosts": {
                "terms": {"field": "agent.name", "size": 500},
                "aggs": {
                    "max_rule_level": {"max": {"field": "rule.level"}},
                    "last_seen": {"max": {"field": "@timestamp"}},
                    "platforms": {
                        "terms": {
                            "field": "rule.groups",
                            "size": 5,
                        }
                    },
                },
            }
        },
    }
    index = _index_pattern(connection)
    try:
        with httpx.Client(
            verify=build_verify(connection),
            timeout=30.0,
            auth=build_auth(connection),
        ) as client:
            resp = client.post(
                f"{build_base_url(connection)}/{index}/_search", json=payload
            )
            resp.raise_for_status()
            buckets = resp.json().get("aggregations", {}).get("hosts", {}).get("buckets", [])
    except Exception as exc:
        raise RuntimeError(f"Indexer host aggregation failed: {exc}") from exc

    results: list[SnipenHostInfo] = []
    for bucket in buckets:
        host = bucket.get("key", "")
        alert_count = bucket.get("doc_count", 0)
        top_rule_level = bucket.get("max_rule_level", {}).get("value")
        last_seen = bucket.get("last_seen", {}).get("value_as_string")
        group_buckets = (
            bucket.get("platforms", {}).get("buckets", [])
        )
        all_groups = [b.get("key", "") for b in group_buckets]
        platforms: list[str] = []
        if any("windows" in g.lower() or "win" in g.lower() for g in all_groups):
            platforms.append("windows")
        if any(
            k in g.lower()
            for g in all_groups
            for k in ("linux", "syslog", "sshd", "pam", "audit")
        ):
            platforms.append("linux")
        results.append(
            SnipenHostInfo(
                host=host,
                alert_count=alert_count,
                top_rule_level=int(top_rule_level) if top_rule_level is not None else None,
                last_seen=last_seen,
                platforms=platforms,
            )
        )
    results.sort(key=lambda h: h.alert_count, reverse=True)
    return results


# ── Event fetching ────────────────────────────────────────────────────────────

def _normalize_smart(raw: dict[str, Any]) -> SnipenSmartEvent:
    """Extract structured smart-view fields from a raw Wazuh alert."""
    event_id = _pick(raw, "data.win.system.eventID", "data.win.system.eventId", "win.system.eventID")
    host = _pick(raw, "agent.name", "agent.hostname", "host.name", "manager.name")
    rule_id = _pick(raw, "rule.id")
    rule_level_raw = _pick(raw, "rule.level")
    rule_description = _pick(raw, "rule.description")
    groups = _pick(raw, "rule.groups") or []
    if isinstance(groups, str):
        groups = [groups]
    decoder = _pick(raw, "decoder.name")
    location = _pick(raw, "location")
    user = _pick(
        raw,
        "data.win.eventdata.targetUserName",
        "data.win.eventdata.subjectUserName",
        "data.srcuser",
        "data.user",
    )
    logon_type = _pick(raw, "data.win.eventdata.logonType")
    ip_address = _pick(
        raw,
        "data.win.eventdata.ipAddress",
        "data.srcip",
        "data.win.eventdata.sourceNetworkAddress",
    )
    process = _pick(
        raw,
        "data.win.eventdata.processName",
        "data.win.eventdata.newProcessName",
        "data.process.name",
        "data.program",
    )
    command_line = _pick(
        raw,
        "data.win.eventdata.commandLine",
        "data.win.eventdata.CommandLine",
    )
    service_name = _pick(
        raw,
        "data.win.eventdata.serviceName",
        "data.win.eventdata.ServiceName",
        "data.win.system.channel",
    )
    registry_key = _pick(
        raw,
        "data.win.eventdata.objectName",
        "data.win.eventdata.keyName",
    )
    status = _pick(
        raw,
        "data.win.eventdata.status",
        "data.win.eventdata.failureReason",
    )
    mitre_id = _pick(raw, "rule.mitre.id", "mitre.id")
    if isinstance(mitre_id, list):
        mitre_id = ", ".join(str(x) for x in mitre_id)
    mitre_tactic = _pick(raw, "rule.mitre.tactic", "mitre.tactic")
    if isinstance(mitre_tactic, list):
        mitre_tactic = ", ".join(str(x) for x in mitre_tactic)
    timestamp = _pick(raw, "@timestamp", "timestamp")
    platform = detect_platform(raw, list(groups), decoder, event_id)
    event_id_str = str(event_id) if event_id is not None else None
    event_explanation = _resolve_event_explanation(
        event_id=event_id_str,
        rule_description=str(rule_description) if rule_description else None,
        decoder=str(decoder) if decoder else None,
        groups=[str(g) for g in groups],
    )
    return SnipenSmartEvent(
        timestamp=str(timestamp) if timestamp else None,
        host=str(host) if host else None,
        platform=platform,
        event_id=event_id_str,
        event_explanation=event_explanation,
        rule_id=str(rule_id) if rule_id is not None else None,
        rule_level=int(rule_level_raw) if rule_level_raw is not None else None,
        rule_description=str(rule_description) if rule_description else None,
        groups=[str(g) for g in groups],
        user=str(user) if user else None,
        logon_type=str(logon_type) if logon_type else None,
        ip_address=str(ip_address) if ip_address else None,
        process=str(process) if process else None,
        command_line=str(command_line) if command_line else None,
        service_name=str(service_name) if service_name else None,
        registry_key=str(registry_key) if registry_key else None,
        status=str(status) if status else None,
        mitre_id=str(mitre_id) if mitre_id else None,
        mitre_tactic=str(mitre_tactic) if mitre_tactic else None,
        decoder=str(decoder) if decoder else None,
        location=str(location) if location else None,
    )


def get_host_events(
    connection: dict[str, Any],
    host: str,
    hours: int = 24,
    limit: int = 100,
    platform_filter: str | None = None,
    event_ids_filter: list[str] | None = None,
    min_rule_level: int | None = None,
    category_filter: str | None = None,
) -> list[SnipenEvent]:
    """
    Fetch the latest `limit` events for `host` from the indexer.
    Optional filters: platform, event IDs, min rule level, category keyword.
    """
    must_filters: list[dict[str, Any]] = [
        _time_range_filter(hours),
        {"term": {"agent.name": host}},
    ]
    if min_rule_level is not None and min_rule_level > 0:
        must_filters.append({"range": {"rule.level": {"gte": min_rule_level}}})
    if platform_filter == "windows":
        must_filters.append({"exists": {"field": "data.win.system.eventID"}})
    elif platform_filter == "linux":
        must_filters.append(
            {
                "bool": {
                    "should": [
                        {"term": {"decoder.name": "sshd"}},
                        {"term": {"decoder.name": "pam"}},
                        {"term": {"decoder.name": "auditd"}},
                        {"terms": {"rule.groups": ["linux", "syslog", "audit"]}},
                    ],
                    "minimum_should_match": 1,
                }
            }
        )
    if platform_filter == "windows" and not event_ids_filter:
        event_ids_filter = SNIPEN_WINDOWS_DEFAULT_EVENT_IDS

    if event_ids_filter:
        must_filters.append(
            {"terms": {"data.win.system.eventID": event_ids_filter}}
        )
    # Category keywords mapped to rule.groups
    category_group_map: dict[str, list[str]] = {
        "auth": ["authentication_failed", "authentication_success", "logon", "login"],
        "process": ["process_creation", "execution"],
        "service": ["service_control"],
        "registry": ["registry_event"],
        "powershell": ["powershell"],
        "network": ["network_traffic"],
    }
    if category_filter and category_filter in category_group_map:
        must_filters.append(
            {
                "terms": {
                    "rule.groups": category_group_map[category_filter]
                }
            }
        )

    payload: dict[str, Any] = {
        "size": limit,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {
            "bool": {
                "filter": must_filters,
            }
        },
    }
    index = _index_pattern(connection)
    try:
        with httpx.Client(
            verify=build_verify(connection),
            timeout=45.0,
            auth=build_auth(connection),
        ) as client:
            resp = client.post(
                f"{build_base_url(connection)}/{index}/_search", json=payload
            )
            resp.raise_for_status()
            hits = resp.json().get("hits", {}).get("hits", [])
    except Exception as exc:
        raise RuntimeError(f"Indexer event fetch failed: {exc}") from exc

    events: list[SnipenEvent] = []
    for hit in hits:
        raw = hit.get("_source", {})
        doc_id = hit.get("_id")
        smart = _normalize_smart(raw)
        ev = SnipenEvent(doc_id=str(doc_id) if doc_id else None, raw=raw, smart=smart)
        events.append(ev)
    return events


def get_related_events(
    connection: dict[str, Any],
    event_raw: dict[str, Any],
    limit: int = 20,
    hours: int = 24,
) -> list[SnipenEvent]:
    """Find events related to a given event by host, rule, user, IP, process."""
    smart = _normalize_smart(event_raw)
    host = smart.host or _pick(event_raw, "agent.name")
    should_clauses: list[dict[str, Any]] = []

    if smart.rule_id:
        should_clauses.append({"term": {"rule.id": smart.rule_id}})
    if smart.user:
        should_clauses.append(
            {"term": {"data.win.eventdata.targetUserName": smart.user}}
        )
        should_clauses.append({"term": {"data.srcuser": smart.user}})
    if smart.ip_address and smart.ip_address not in ("-", "::1", "127.0.0.1"):
        should_clauses.append({"term": {"data.win.eventdata.ipAddress": smart.ip_address}})
        should_clauses.append({"term": {"data.srcip": smart.ip_address}})
    if smart.process:
        should_clauses.append(
            {"wildcard": {"data.win.eventdata.processName": f"*{smart.process.split(chr(92))[-1]}*"}}
        )

    if not should_clauses:
        # Fall back to same host, all recent events
        should_clauses.append({"match_all": {}})

    must_filters: list[dict[str, Any]] = [_time_range_filter(hours)]
    if host:
        must_filters.append({"term": {"agent.name": host}})

    payload: dict[str, Any] = {
        "size": limit,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {
            "bool": {
                "filter": must_filters,
                "should": should_clauses,
                "minimum_should_match": 1,
            }
        },
    }
    index = _index_pattern(connection)
    try:
        with httpx.Client(
            verify=build_verify(connection),
            timeout=30.0,
            auth=build_auth(connection),
        ) as client:
            resp = client.post(
                f"{build_base_url(connection)}/{index}/_search", json=payload
            )
            resp.raise_for_status()
            hits = resp.json().get("hits", {}).get("hits", [])
    except Exception as exc:
        raise RuntimeError(f"Indexer related-events fetch failed: {exc}") from exc

    events: list[SnipenEvent] = []
    for hit in hits:
        raw = hit.get("_source", {})
        smart = _normalize_smart(raw)
        doc_id = hit.get("_id")
        ev = SnipenEvent(doc_id=str(doc_id) if doc_id else None, raw=raw, smart=smart)
        events.append(ev)
    return events


# ── AI helpers ───────────────────────────────────────────────────────────────

def _call_ollama_generate(connection: dict[str, Any], prompt: str, timeout: float = 90.0) -> str:
    payload = {
        "model": connection["ollama_model"],
        "stream": False,
        "prompt": prompt,
    }
    with httpx.Client(timeout=timeout) as client:
        resp = client.post(
            f"{connection['ollama_url'].rstrip('/')}/api/generate", json=payload
        )
        resp.raise_for_status()
        return str(resp.json().get("response", "")).strip()


def _call_ollama_json(connection: dict[str, Any], prompt: str, timeout: float = 90.0) -> dict[str, Any]:
    payload = {
        "model": connection["ollama_model"],
        "stream": False,
        "format": "json",
        "prompt": prompt,
        "options": {
            "temperature": 0.2,
            "num_predict": 1400,
        },
    }
    with httpx.Client(timeout=timeout) as client:
        resp = client.post(
            f"{connection['ollama_url'].rstrip('/')}/api/generate", json=payload
        )
        resp.raise_for_status()
        raw = resp.json().get("response", "{}")
        try:
            return json.loads(raw)  # type: ignore[return-value]
        except json.JSONDecodeError:
            return {"raw": raw}


def _split_sentences(text: str) -> list[str]:
    parts = [p.strip() for p in re.split(r"(?<=[.!?])\s+", text or "") if p.strip()]
    return parts


def _pick_suspicious_fields(smart: SnipenEventSmart) -> list[str]:
    candidates: list[tuple[str, Any]] = [
        ("event_id", smart.event_id),
        ("rule_id", smart.rule_id),
        ("rule_level", smart.rule_level),
        ("rule_description", smart.rule_description),
        ("process", smart.process),
        ("command_line", smart.command_line),
        ("user", smart.user),
        ("ip_address", smart.ip_address),
        ("host", smart.host),
    ]
    return [name for name, value in candidates if value not in (None, "", "-")]


def _ensure_explain_quality(parsed: dict[str, Any], smart: SnipenEventSmart, *, remediation_mode: bool) -> dict[str, Any]:
    summary = str(parsed.get("summary", "") or "").strip()
    summary_sentences = _split_sentences(summary)
    if len(summary_sentences) < 4:
        fallback_lines = [
            f"Das Event zeigt eine sicherheitsrelevante Aktivität auf Host {smart.host or 'unbekanntem Host'}.",
            f"Regel: {smart.rule_description or smart.rule_id or 'unbekannt'} (Level {smart.rule_level if smart.rule_level is not None else 'n/a'}).",
            f"Event-ID: {smart.event_id or 'n/a'}, Prozess: {smart.process or 'n/a'}, Benutzer: {smart.user or 'n/a'}.",
        ]
        if smart.command_line:
            fallback_lines.append(f"Die Befehlszeile enthält: {smart.command_line}.")
        if smart.ip_address and smart.ip_address != "-":
            fallback_lines.append(f"Die Aktivität ist mit der IP-Adresse {smart.ip_address} verknüpft.")
        if remediation_mode:
            fallback_lines.append("Aus Incident-Response-Sicht sollte zunächst Containment erfolgen, bevor weitere Änderungen am System vorgenommen werden.")
        else:
            fallback_lines.append("Für die Bewertung sind Kontext, Baseline-Abweichungen und mögliche Angriffsschritte im zeitlichen Umfeld entscheidend.")
        summary = " ".join(fallback_lines)

    why_suspicious = str(parsed.get("why_suspicious", "") or "").strip()
    if len(_split_sentences(why_suspicious)) < 2:
        why_suspicious = (
            f"Auffällig sind die Kombination aus Regel-Level {smart.rule_level if smart.rule_level is not None else 'n/a'}, "
            f"Event-ID {smart.event_id or 'n/a'} und Prozess {smart.process or 'n/a'}. "
            f"Zusätzlich erhöhen Benutzerkontext ({smart.user or 'n/a'}) und CommandLine-Muster ({smart.command_line or 'n/a'}) das Risiko."
        )

    against_it = parsed.get("against_it")
    if against_it is not None:
        against_it = str(against_it).strip() or None

    suspicious_fields = [str(x) for x in parsed.get("suspicious_fields", []) if str(x).strip()]
    if len(suspicious_fields) < 3:
        suspicious_fields = list(dict.fromkeys(suspicious_fields + _pick_suspicious_fields(smart)))[:8]

    unusual_behavior = [str(x) for x in parsed.get("unusual_behavior", []) if str(x).strip()]
    if len(unusual_behavior) < 3:
        fallback_unusual = [
            f"Prozesskontext: {smart.process or 'n/a'} in sicherheitsrelevantem Event.",
            f"Benutzerkontext: {smart.user or 'n/a'}.",
            f"Regel-Level {smart.rule_level if smart.rule_level is not None else 'n/a'} mit Beschreibung '{smart.rule_description or smart.rule_id or 'n/a'}'.",
        ]
        if smart.command_line:
            fallback_unusual.append(f"Auffällige Befehlszeile: {smart.command_line}")
        unusual_behavior = list(dict.fromkeys(unusual_behavior + fallback_unusual))[:6]

    deviations = [str(x) for x in parsed.get("deviations", []) if str(x).strip()]
    if len(deviations) < 3:
        fallback_deviations = [
            "Abweichung vom erwarteten Prozess-/User-Verhalten.",
            "Sicherheitsregel wurde mit erhöhtem Risiko-Level ausgelöst.",
            "Event benötigt Korrelation mit zeitnahen Folgeereignissen und Baseline.",
        ]
        deviations = list(dict.fromkeys(deviations + fallback_deviations))[:6]

    remediation = [str(x) for x in parsed.get("remediation", []) if str(x).strip()]
    min_remediation = 6 if remediation_mode else 5
    if len(remediation) < min_remediation:
        fallback_remediation = [
            "Betroffenen Host logisch isolieren oder streng segmentieren.",
            "Prozessbaum und Parent/Child-Kette für den Event vollständig prüfen.",
            "Hash und Signatur der betroffenen Binärdatei gegen Threat-Intel prüfen.",
            "Persistenzmechanismen (Services, Tasks, Registry/Autostart) kontrollieren.",
            "Betroffene Credentials und privilegierte Sessions auf Missbrauch prüfen.",
            "Findings dokumentieren und Detection-Regeln/Alerting nachschärfen.",
        ]
        remediation = list(dict.fromkeys(remediation + fallback_remediation))[:8]

    next_checks = [str(x) for x in parsed.get("next_checks", []) if str(x).strip()]
    min_checks = 6 if remediation_mode else 5
    if len(next_checks) < min_checks:
        fallback_checks = [
            "Zeitlich benachbarte Events desselben Hosts korrelieren (vor/nach Event).",
            "Gleiche Event-ID und Rule-ID auf weiteren Hosts suchen.",
            "Anmeldeereignisse und Privilege-Escalation-Indikatoren im Zeitraum prüfen.",
            "Netzwerkverbindungen des Prozesses (Ziel-IP, Ports, Häufigkeit) auswerten.",
            "Datei-/Registry-/Service-Änderungen rund um den Zeitpunkt untersuchen.",
            "EDR/AV/Defender-Telemetrie auf Treffer oder Ausnahmen prüfen.",
        ]
        next_checks = list(dict.fromkeys(next_checks + fallback_checks))[:8]

    enriched = dict(parsed)
    enriched["summary"] = summary
    enriched["why_suspicious"] = why_suspicious
    enriched["against_it"] = against_it
    enriched["suspicious_fields"] = suspicious_fields
    enriched["unusual_behavior"] = unusual_behavior
    enriched["deviations"] = deviations
    enriched["remediation"] = remediation
    enriched["next_checks"] = next_checks
    return enriched


# ── Host AI Analysis ─────────────────────────────────────────────────────────

def analyze_host(
    connection: dict[str, Any],
    host: str,
    hours: int = 24,
    limit: int = 100,
    windows_only: bool = False,
    linux_only: bool = False,
    include_noise: bool = False,
    run_ai: bool = True,
) -> SnipenAnalysisResult:
    platform_filter: str | None = None
    if windows_only:
        platform_filter = "windows"
    elif linux_only:
        platform_filter = "linux"

    events = get_host_events(
        connection,
        host=host,
        hours=hours,
        limit=limit,
        platform_filter=platform_filter,
    )

    if not events:
        return SnipenAnalysisResult(
            host=host,
            hours=hours,
            total_events=0,
            ai_summary="No events found for this host in the selected time window.",
            ran_ai=False,
        )

    # Local aggregation
    rule_id_counter: Counter[str] = Counter()
    event_id_counter: Counter[str] = Counter()
    rule_desc_counter: Counter[str] = Counter()
    high_level_events: list[str] = []

    for ev in events:
        s = ev.smart
        if s.rule_id:
            rule_id_counter[s.rule_id] += 1
        if s.event_id:
            event_id_counter[s.event_id] += 1
        if s.rule_description:
            rule_desc_counter[s.rule_description] += 1
        if s.rule_level and s.rule_level >= 10:
            desc = s.rule_description or s.rule_id or "unknown rule"
            high_level_events.append(f"[Level {s.rule_level}] {desc} @ {s.timestamp or '?'}")

    top_rule_ids = [rule for rule, _ in rule_id_counter.most_common(10)]
    top_event_ids = [eid for eid, _ in event_id_counter.most_common(10)]
    top_descriptions = [d for d, _ in rule_desc_counter.most_common(15)]

    suspicious_patterns: list[str] = list(dict.fromkeys(high_level_events[:20]))
    likely_benign: list[str] = []
    recommended_checks: list[str] = []
    host_risk = "low"
    ai_summary: str | None = None

    if high_level_events:
        if len([e for e in events if (e.smart.rule_level or 0) >= 12]) >= 3:
            host_risk = "high"
        elif len([e for e in events if (e.smart.rule_level or 0) >= 10]) >= 3:
            host_risk = "medium"

    if run_ai:
        # Build a compact summary for the LLM
        summary_data = {
            "host": host,
            "total_events": len(events),
            "hours": hours,
            "top_rule_ids": top_rule_ids[:8],
            "top_event_ids": top_event_ids[:8],
            "top_descriptions": top_descriptions[:10],
            "high_level_alerts": high_level_events[:15],
            "sample_events": [
                {
                    "ts": ev.smart.timestamp,
                    "event_id": ev.smart.event_id,
                    "rule_id": ev.smart.rule_id,
                    "rule_level": ev.smart.rule_level,
                    "rule_desc": ev.smart.rule_description,
                    "user": ev.smart.user,
                    "ip": ev.smart.ip_address,
                    "process": ev.smart.process,
                }
                for ev in events[:20]
            ],
        }
        prompt = (
            f"You are a senior SOC analyst performing threat hunting. "
            f"Analyse the following Wazuh event summary for host '{host}' and return valid JSON only "
            f"with keys: suspicious_patterns (list[str]), likely_benign (list[str]), "
            f"recommended_checks (list[str]), host_risk (one of: low/medium/high/critical), "
            f"ai_summary (str, 2-4 sentences in German).\n\n"
            f"Data:\n{json.dumps(summary_data, ensure_ascii=False)}"
        )

        try:
            parsed = _call_ollama_json(connection, prompt, timeout=120.0)
            suspicious_patterns = [str(x) for x in parsed.get("suspicious_patterns", suspicious_patterns)]
            likely_benign = [str(x) for x in parsed.get("likely_benign", [])]
            recommended_checks = [str(x) for x in parsed.get("recommended_checks", [])]
            host_risk = str(parsed.get("host_risk", host_risk)).lower()
            ai_summary = str(parsed.get("ai_summary", "")) or None
        except Exception as exc:
            ai_summary = f"AI analysis failed: {exc}"

    return SnipenAnalysisResult(
        host=host,
        hours=hours,
        total_events=len(events),
        suspicious_patterns=suspicious_patterns,
        likely_benign=likely_benign,
        recommended_checks=recommended_checks,
        host_risk=host_risk,
        top_rule_ids=top_rule_ids,
        top_event_ids=top_event_ids,
        ai_summary=ai_summary,
        ran_ai=run_ai,
    )


# ── Single-event AI ──────────────────────────────────────────────────────────

def explain_event(connection: dict[str, Any], event_raw: dict[str, Any]) -> SnipenExplainResult:
    smart = _normalize_smart(event_raw)
    prompt = (
        "You are a senior SOC analyst. Explain this Wazuh security event in DETAIL and return valid JSON only. "
        "Language: German. Be concrete and technical, avoid generic phrases. "
        "with keys: summary (str, 5-8 full German sentences), "
        "why_suspicious (str, 3-6 sentences with concrete indicators), against_it (str – reasons it could be benign, 2-4 sentences, or null), "
        "severity (one of: critical/high/medium/low/info), "
        "suspicious_fields (list[str] – concrete important fields like event_id, user, ip_address, process, command_line, rule_level), "
        "unusual_behavior (list[str] – concrete observed unusual behaviors, min 3 items), "
        "deviations (list[str] – deviations from expected baseline or normal behavior, min 3 items), "
        "remediation (list[str], min 5 concrete actions), next_checks (list[str], min 5 concrete checks).\n\n"
        "risk_score (float 0-10, 10=most dangerous), "
        "confidence (one of: low/medium/high/very_high), "
        "mitre_techniques (list[str] – ATT&CK IDs with names, e.g. [\"T1059 - Command and Scripting Interpreter\"]), "
        "remediation (list[str]), next_checks (list[str]).\n\n"
        "Reasoning requirements: "
        "1) explicitly reference at least 3 concrete event fields in your text (e.g., event_id, process, user, ip_address, command_line, rule_level); "
        "2) explain attacker intent and likely impact; "
        "3) if confidence is low, explain exactly why.\n\n"
        "Smart fields:\n"
        f"{json.dumps(smart.model_dump(exclude_none=True), ensure_ascii=False)}\n\n"
        "Raw event excerpt:\n"
        f"{json.dumps({k: v for k, v in event_raw.items() if k in ('rule', 'data', 'agent', 'decoder', '@timestamp', 'location')}, ensure_ascii=False, default=str)}"
    )
    try:
        parsed = _call_ollama_json(connection, prompt, timeout=120.0)
        parsed = _ensure_explain_quality(parsed, smart, remediation_mode=False)
        return SnipenExplainResult(
            summary=str(parsed.get("summary", "No explanation returned.")),
            why_suspicious=parsed.get("why_suspicious") or None,
            against_it=parsed.get("against_it") or None,
            severity=str(parsed.get("severity", "medium")).lower(),
            suspicious_fields=[str(x) for x in parsed.get("suspicious_fields", [])],
            unusual_behavior=[str(x) for x in parsed.get("unusual_behavior", [])],
            deviations=[str(x) for x in parsed.get("deviations", [])],
            remediation=[str(x) for x in parsed.get("remediation", [])],
            next_checks=[str(x) for x in parsed.get("next_checks", [])],
            ran_ai=True,
            risk_score=float(parsed["risk_score"]) if parsed.get("risk_score") is not None else None,
            confidence=str(parsed["confidence"]).lower() if parsed.get("confidence") else None,
            mitre_techniques=[str(x) for x in parsed.get("mitre_techniques", [])],
        )
    except Exception as exc:
        return SnipenExplainResult(
            summary=f"AI explanation failed: {exc}",
            severity="medium",
            ran_ai=False,
        )


def remediate_event(connection: dict[str, Any], event_raw: dict[str, Any]) -> SnipenExplainResult:
    smart = _normalize_smart(event_raw)
    prompt = (
        "You are a senior incident responder. For the following Wazuh security event, provide specific "
        "remediation steps and return valid JSON only with keys: "
        "summary (str – what happened, 4-7 sentences in German), "
        "why_suspicious (str, 3-6 sentences with technical detail), against_it (str or null, 2-4 sentences), "
        "severity (one of: critical/high/medium/low/info), "
        "suspicious_fields (list[str] – the concrete fields that matter most), "
        "unusual_behavior (list[str] – specific suspicious behavior observed, min 3 items), "
        "deviations (list[str] – deviations from normal/expected behavior, min 3 items), "
        "risk_score (float 0-10, 10=most dangerous), "
        "confidence (one of: low/medium/high/very_high), "
        "mitre_techniques (list[str] – ATT&CK IDs with names), "
        "remediation (list[str] – concrete prioritized remediation steps, min 6 items), "
        "next_checks (list[str] – what to investigate next, min 6 items).\n\n"
        "Reasoning requirements: include containment, eradication and recovery steps; "
        "reference concrete evidence fields from the event; avoid generic one-liners.\n\n"
        "Smart fields:\n"
        f"{json.dumps(smart.model_dump(exclude_none=True), ensure_ascii=False)}\n\n"
        "Raw event excerpt:\n"
        f"{json.dumps({k: v for k, v in event_raw.items() if k in ('rule', 'data', 'agent', 'decoder', '@timestamp')}, ensure_ascii=False, default=str)}"
    )
    try:
        parsed = _call_ollama_json(connection, prompt, timeout=120.0)
        parsed = _ensure_explain_quality(parsed, smart, remediation_mode=True)
        return SnipenExplainResult(
            summary=str(parsed.get("summary", "No remediation returned.")),
            why_suspicious=parsed.get("why_suspicious") or None,
            against_it=parsed.get("against_it") or None,
            severity=str(parsed.get("severity", "medium")).lower(),
            suspicious_fields=[str(x) for x in parsed.get("suspicious_fields", [])],
            unusual_behavior=[str(x) for x in parsed.get("unusual_behavior", [])],
            deviations=[str(x) for x in parsed.get("deviations", [])],
            remediation=[str(x) for x in parsed.get("remediation", [])],
            next_checks=[str(x) for x in parsed.get("next_checks", [])],
            ran_ai=True,
            risk_score=float(parsed["risk_score"]) if parsed.get("risk_score") is not None else None,
            confidence=str(parsed["confidence"]).lower() if parsed.get("confidence") else None,
            mitre_techniques=[str(x) for x in parsed.get("mitre_techniques", [])],
        )
    except Exception as exc:
        return SnipenExplainResult(
            summary=f"AI remediation failed: {exc}",
            severity="medium",
            ran_ai=False,
        )


def ai_query_host(
    connection: dict[str, Any],
    host: str,
    query: str,
    hours: int = 24,
    limit: int = 100,
) -> SnipenAIQueryResult:
    """Interpret a natural language threat hunting query over the host's events."""
    events = get_host_events(connection, host=host, hours=hours, limit=min(limit, 200))
    if not events:
        return SnipenAIQueryResult(
            query=query,
            answer="Keine Events für diesen Host im gewählten Zeitraum gefunden.",
            ran_ai=False,
        )

    event_summaries = [
        {
            "idx": i,
            "ts": ev.smart.timestamp,
            "event_id": ev.smart.event_id,
            "rule_id": ev.smart.rule_id,
            "rule_level": ev.smart.rule_level,
            "rule_desc": ev.smart.rule_description,
            "user": ev.smart.user,
            "ip": ev.smart.ip_address,
            "process": ev.smart.process,
            "command_line": ev.smart.command_line,
            "groups": ev.smart.groups[:4] if ev.smart.groups else [],
        }
        for i, ev in enumerate(events[:120])
    ]

    prompt = (
        f"You are a senior SOC analyst. The threat hunter asks: \"{query}\"\n\n"
        f"These are recent Wazuh events from host '{host}' (last {hours}h, {len(events)} total):\n"
        f"{json.dumps(event_summaries, ensure_ascii=False)}\n\n"
        "Return valid JSON only with keys:\n"
        "answer (str – concise German answer to the question, 3-5 sentences, specific to the data),\n"
        "matched_indices (list[int] – indices of the most relevant events for the question, max 25).\n"
        "Be specific and reference actual event data in your answer."
    )

    try:
        parsed = _call_ollama_json(connection, prompt, timeout=120.0)
        answer = str(parsed.get("answer", "Keine Antwort erhalten."))
        raw_indices = parsed.get("matched_indices", [])
        matched_indices = [
            int(i)
            for i in raw_indices
            if isinstance(i, (int, float)) and 0 <= int(i) < len(events)
        ]
        matched_events = [events[i] for i in matched_indices[:25]]
        return SnipenAIQueryResult(
            query=query,
            answer=answer,
            matched_events=matched_events,
            ran_ai=True,
        )
    except Exception as exc:
        return SnipenAIQueryResult(
            query=query,
            answer=f"AI Query fehlgeschlagen: {exc}",
            ran_ai=False,
        )
