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
from services.snipen_overview import build_host_overview
from services.snipen_profiles import build_profile_context_block, get_profile_for_host
from services.event_decision_engine import (
    EventDecision,
    build_decision_context_block,
    build_static_explain_result,
    decide_event,
)
from services.artifact_action_builder import (
    build_guardrail_block,
    validate_action_list,
    build_action_plan,
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


def _fetch_agent_inventory(connection: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Return known agent hosts from Wazuh agent state indices."""
    payload: dict[str, Any] = {
        "size": 0,
        "aggs": {
            "hosts": {
                "terms": {
                    "field": "agent.name",
                    "size": 2000,
                },
                "aggs": {
                    "last_seen": {"max": {"field": "@timestamp"}},
                    "platforms": {
                        "terms": {
                            "field": "agent.os.platform",
                            "size": 3,
                        }
                    },
                },
            }
        },
    }

    try:
        with httpx.Client(
            verify=build_verify(connection),
            timeout=30.0,
            auth=build_auth(connection),
        ) as client:
            resp = client.post(
                f"{build_base_url(connection)}/wazuh-states-agents-*/_search", json=payload
            )
            resp.raise_for_status()
            buckets = resp.json().get("aggregations", {}).get("hosts", {}).get("buckets", [])
    except Exception:
        return {}

    inventory: dict[str, dict[str, Any]] = {}
    for bucket in buckets:
        host = bucket.get("key")
        if not host:
            continue
        platform_buckets = bucket.get("platforms", {}).get("buckets", [])
        raw_platforms = [str(item.get("key") or "").lower() for item in platform_buckets]
        platforms: list[str] = []
        if any("win" in item for item in raw_platforms):
            platforms.append("windows")
        if any(item in ("linux", "unix", "darwin", "macos") or "linux" in item for item in raw_platforms):
            platforms.append("linux")
        inventory[str(host)] = {
            "last_seen": bucket.get("last_seen", {}).get("value_as_string"),
            "platforms": platforms,
        }
    return inventory


def _fetch_manager_agent_inventory(connection: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Fallback inventory from Wazuh manager API (/agents)."""
    manager_url = str(connection.get("manager_url") or "").strip().rstrip("/")
    manager_user = str(connection.get("manager_username") or "").strip()
    manager_pass = str(connection.get("manager_password") or "")
    if not manager_url or not manager_user or not manager_pass:
        return {}

    try:
        with httpx.Client(verify=build_verify(connection), timeout=30.0, auth=(manager_user, manager_pass)) as client:
            auth_resp = client.get(f"{manager_url}/security/user/authenticate", params={"raw": "true"})
            auth_resp.raise_for_status()
            token = str(auth_resp.text or "").strip().strip('"')
            if not token:
                return {}
            resp = client.get(
                f"{manager_url}/agents",
                params={"limit": 5000},
                headers={"Authorization": f"Bearer {token}"},
            )
            resp.raise_for_status()
            items = resp.json().get("data", {}).get("affected_items", [])
    except Exception:
        return {}

    inventory: dict[str, dict[str, Any]] = {}
    for item in items:
        if not isinstance(item, dict):
            continue
        host = str(item.get("name") or "").strip()
        if not host:
            continue
        raw_os = item.get("os")
        platform_raw = ""
        if isinstance(raw_os, dict):
            platform_raw = str(raw_os.get("platform") or raw_os.get("name") or "").lower()
        platforms: list[str] = []
        if "win" in platform_raw:
            platforms.append("windows")
        if any(token in platform_raw for token in ("linux", "unix", "darwin", "mac")):
            platforms.append("linux")
        inventory[host] = {
            "last_seen": item.get("lastKeepAlive"),
            "platforms": platforms,
        }
    return inventory


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

    by_host: dict[str, SnipenHostInfo] = {item.host: item for item in results}
    for source in (_fetch_agent_inventory(connection), _fetch_manager_agent_inventory(connection)):
        for host, meta in source.items():
            existing = by_host.get(host)
            if existing is None:
                by_host[host] = SnipenHostInfo(
                    host=host,
                    alert_count=0,
                    top_rule_level=None,
                    last_seen=meta.get("last_seen"),
                    platforms=meta.get("platforms") or [],
                )
                continue
            if not existing.last_seen and meta.get("last_seen"):
                existing.last_seen = meta.get("last_seen")
            if not existing.platforms and meta.get("platforms"):
                existing.platforms = list(meta.get("platforms") or [])

    merged = list(by_host.values())
    merged.sort(key=lambda h: (h.alert_count, h.host.lower()), reverse=True)

    # Enrich each host with its profile assignment (best-effort, never fails the request)
    try:
        from services.snipen_profiles import list_all_assignments
        from schemas.types import SnipenHostProfileRef
        assignments = list_all_assignments()
        assignment_map = {a.host: a for a in assignments}
        for host_info in merged:
            asgn = assignment_map.get(host_info.host)
            if asgn and asgn.profile_name:
                host_info.profile = SnipenHostProfileRef(
                    name=asgn.profile_name,
                    display_name=asgn.profile_display_name or asgn.profile_name,
                    risk_tolerance=asgn.risk_tolerance or "medium",
                )
    except Exception:
        pass

    return merged


# ── Event fetching ────────────────────────────────────────────────────────────

_EVENT_FAMILY_MAP: dict[int, str] = {
    # Logon / Logoff
    4624: "logon_success", 528: "logon_success", 540: "logon_success",
    4625: "logon_failure", 529: "logon_failure", 539: "logon_failure",
    4771: "logon_failure", 4776: "logon_failure",
    4634: "logoff", 4647: "logoff", 683: "logoff",
    4648: "logon_explicit",
    # Privilege
    4672: "privilege_use", 4673: "privilege_use", 4674: "privilege_use",
    576: "privilege_use",
    # Process
    4688: "process_create", 592: "process_create",
    4689: "process_terminate", 593: "process_terminate",
    # Service / Scheduled Task
    4697: "service_install", 7045: "service_install", 601: "service_install",
    4698: "scheduled_task", 4699: "scheduled_task",
    4700: "scheduled_task", 4701: "scheduled_task", 4702: "scheduled_task",
    602: "scheduled_task",
    # Service config change
    7040: "service_config_change",
    # Account management
    4720: "account_mgmt", 4722: "account_mgmt", 4723: "account_mgmt",
    4724: "account_mgmt", 4725: "account_mgmt", 4726: "account_mgmt",
    4738: "account_mgmt", 4740: "account_mgmt", 4767: "account_mgmt",
    624: "account_mgmt", 625: "account_mgmt",
    629: "account_mgmt", 630: "account_mgmt", 642: "account_mgmt",
    644: "account_mgmt", 671: "account_mgmt",
    # Group management
    4728: "group_mgmt", 4729: "group_mgmt", 4732: "group_mgmt",
    4733: "group_mgmt", 4756: "group_mgmt", 4757: "group_mgmt",
    # Audit / Log
    1102: "log_cleared", 517: "log_cleared",
    4719: "policy_change", 4713: "policy_change", 4715: "policy_change",
    # Object / Registry
    4656: "object_access", 4657: "registry_event", 4663: "object_access",
    4670: "object_access",
    # Kerberos
    4768: "kerberos", 4769: "kerberos", 4770: "kerberos", 4772: "kerberos",
    672: "kerberos", 673: "kerberos", 675: "kerberos",
    # Network (WFP)
    5156: "network", 5157: "network",
    # Firewall policy
    4944: "firewall", 4946: "firewall", 4947: "firewall", 4948: "firewall",
    4950: "firewall",
    # ── Infrastructure / DNS / Network diagnostics ───────────────────────────
    # DNS Client (Microsoft-Windows-DNS-Client/Operational)
    1014: "dns_infra",   # DNS name resolution timeout
    1015: "dns_infra",   # DNS client query error
    1016: "dns_infra",   # DNS client query response
    1017: "dns_infra",   # DNS client event
    # WinRM / Remote management
    91:   "winrm_infra", 161: "winrm_infra",
    # PowerShell / Execution Policy (often event 4103/4104, but provider-level)
    403: "powershell_infra", 400: "powershell_infra",
    # Windows Installer / Update
    11707: "software_install", 11708: "software_install",
    11724: "software_install",
    # System/driver events
    7001: "service_state", 7002: "service_state", 7009: "service_state",
    7011: "service_state", 7022: "service_state", 7023: "service_state",
    7024: "service_state", 7026: "service_state", 7031: "service_state",
    7034: "service_state", 7035: "service_state", 7036: "service_state",
    7038: "service_state",
    # Event Log service
    1100: "log_service", 1101: "log_service", 1108: "log_service",
    # WMI
    5857: "wmi_infra", 5858: "wmi_infra", 5859: "wmi_infra",
    5860: "wmi_infra", 5861: "wmi_infra",
    # AppLocker / SRP
    8003: "applocker", 8004: "applocker", 8006: "applocker", 8007: "applocker",
    # BITS
    59: "bits_infra", 60: "bits_infra",
    # Hyper-V / Virtualization
    18500: "hyperv_infra", 18502: "hyperv_infra",
    # Wireless / WLAN
    8001: "network_infra", 8002: "network_infra", 8003: "network_infra",
    # DHCP / IP
    50: "network_infra", 51: "network_infra",
}

# ── Event class metadata ──────────────────────────────────────────────────────
# Defines how each family should be treated BEFORE the AI call.
# max_severity: ceiling the AI cannot exceed without explicit override
# isolation_allowed: whether "isolate host" is a valid remediation
# action_template: category-specific action hints injected into the prompt
_EVENT_CLASS_METADATA: dict[str, dict[str, Any]] = {
    "dns_infra": {
        "max_severity": "low",
        "isolation_allowed": False,
        "description": "DNS resolution timeout / infrastructure event – almost never a direct attack indicator.",
        "action_template": [
            "DNS-Server auf Erreichbarkeit und Antwortzeiten prüfen",
            "Tailscale/VPN-DNS-Konfiguration validieren (besonders bei *.ts.net Domains)",
            "Domain-Controller-Erreichbarkeit prüfen (LDAP SRV Lookup fehlgeschlagen?)",
            "Event-Häufigkeit mit Baseline vergleichen – neu oder regelmäßig?",
        ],
        "context_note": "Event-ID 1014 = DNS-Client-Timeout. Typisch bei: AD/DC-Lookup-Problemen, Tailscale-DNS-Fehlkonfiguration, VPN-Unterbrechungen. Kein Angriffsmuster.",
        "suspicious_only_if": "Nur auffällig bei gleichzeitigem Auftreten von 4625/4768/4769 (Auth Failures/Kerberos) oder unbekannten Zieldomains.",
    },
    "network_infra": {
        "max_severity": "low",
        "isolation_allowed": False,
        "description": "Network infrastructure / connectivity event.",
        "action_template": [
            "Netzwerkverbindung und -konfiguration prüfen",
            "IP-Konfiguration und DHCP validieren",
        ],
        "context_note": "Netzwerk-Infrastrukturereignis. Typisch für Konfigurationsänderungen oder Verbindungsprobleme.",
        "suspicious_only_if": "Nur kritisch bei unerwarteten Änderungen oder in Kombination mit Angriffsmustern.",
    },
    "winrm_infra": {
        "max_severity": "medium",
        "isolation_allowed": False,
        "description": "WinRM / remote management infrastructure event.",
        "action_template": [
            "WinRM-Konfiguration auf dem Host prüfen",
            "Wer hat WinRM-Zugriff? Autorisiert?",
            "Prüfen ob PowerShell Remoting verwendet wird",
        ],
        "context_note": "WinRM-Infrastrukturereignis. Kann bei PowerShell Remoting oder Verwaltungsaufgaben normal sein.",
        "suspicious_only_if": "Kritisch wenn von externen/unbekannten IPs oder ohne erwartbare Admin-Aktivität.",
    },
    "service_state": {
        "max_severity": "low",
        "isolation_allowed": False,
        "description": "Windows service state change (start/stop) – routine system operation.",
        "action_template": [
            "Service-Name und Änderungsursache prüfen",
            "War die Änderung geplant/autorisiert?",
        ],
        "context_note": "Service-Statusänderung. Routine-Betriebsereignis bei Updates, Neustarts.",
        "suspicious_only_if": "Nur relevant bei unbekannten Services oder direkt nach Anmeldeereignissen mit unbekannten Accounts.",
    },
    "software_install": {
        "max_severity": "medium",
        "isolation_allowed": False,
        "description": "Software installation / Windows Installer event.",
        "action_template": [
            "Installiertes Paket identifizieren – autorisiert?",
            "Wer hat die Installation initiiert?",
        ],
        "context_note": "Software-Installationsereignis. Auf DEV-Hosts oft erwartet.",
        "suspicious_only_if": "Verdächtig bei unbekannter Software, ausgelöst durch serviceaccounts oder nachts.",
    },
    "powershell_infra": {
        "max_severity": "medium",
        "isolation_allowed": False,
        "description": "PowerShell engine / execution policy infrastructure event.",
        "action_template": [
            "PowerShell-Skript und Ausführungskontext prüfen",
            "Execution Policy änderung autorisiert?",
        ],
        "context_note": "PowerShell-Infrastrukturereignis (Execution Policy, Engine-Start). Auf DEV-Hosts normal.",
        "suspicious_only_if": "Verdächtig bei Bypass-Flags, unbekannten Skripten oder nächtlicher Ausführung.",
    },
    "wmi_infra": {
        "max_severity": "medium",
        "isolation_allowed": False,
        "description": "WMI activity / subscription event.",
        "action_template": [
            "WMI-Subscription und Provider prüfen",
            "WMI-Persistenz ausschließen (Event 5861 = neue Subscription)",
        ],
        "context_note": "WMI-Ereignis. 5861 (neue WMI-Subscription) ist interessanter als Query-Ereignisse.",
        "suspicious_only_if": "Kritisch bei neuen WMI-Subscriptions (5861) in Kombination mit unbekannten Prozessen.",
    },
    "hyperv_infra": {
        "max_severity": "low",
        "isolation_allowed": False,
        "description": "Hyper-V / virtualization infrastructure event.",
        "action_template": [
            "VM-Konfigurationsänderung prüfen – autorisiert?",
        ],
        "context_note": "Hyper-V-Infrastrukturereignis. Auf Virtualisierungs-Hosts normal.",
        "suspicious_only_if": "Nur relevant bei unautorisierten VM-Erstellungen oder -Löschungen.",
    },
    "log_service": {
        "max_severity": "low",
        "isolation_allowed": False,
        "description": "Event Log service infrastructure event.",
        "action_template": ["Event Log Service-Status prüfen"],
        "context_note": "Event-Log-Dienst-Ereignis, kein direkter Sicherheitsindikator.",
        "suspicious_only_if": "Nur relevant in Kombination mit 1102 (Log Cleared).",
    },
    # ── Security families – keep as-is but provide action templates ──────────
    "log_cleared": {
        "max_severity": "critical",
        "isolation_allowed": True,
        "description": "Audit log cleared – strong sign of anti-forensics.",
        "action_template": [
            "Wer hat das Log gelöscht? (User, Session-ID)",
            "Zeitpunkt: direkt nach verdächtigem Event?",
            "Weitere Logs (Security, System, Application) auf Vollständigkeit prüfen",
            "SIEM/Forwarding-Puffer auf verlorene Events prüfen",
        ],
        "context_note": "1102/517 = Log clearing. Fast immer Täterverhalten bei laufenden Angriffen.",
        "suspicious_only_if": "Immer kritisch.",
    },
    "service_install": {
        "max_severity": "high",
        "isolation_allowed": True,
        "description": "New service installed – common persistence mechanism.",
        "action_template": [
            "Service-Binärpfad und Hash prüfen (VirusTotal)",
            "Wer hat den Service installiert? (Account, Zeitpunkt)",
            "War die Installation geplant/autorisiert?",
            "Service auf anderen Hosts suchen (laterale Ausbreitung?)",
        ],
        "context_note": "7045/4697 = neuer Service. Häufig für Persistenz genutzt.",
        "suspicious_only_if": "Nahezu immer prüfungswürdig, besonders bei unbekanntem ServiceName/Pfad.",
    },
    "service_config_change": {
        "max_severity": "medium",
        "isolation_allowed": False,
        "description": "Service configuration changed (start type, binary path).",
        "action_template": [
            "Welche Service-Eigenschaft wurde geändert?",
            "Autorisierte Änderung (Admin, Update)?",
            "Korreliere mit 4688 (Process Creation) um auslösenden Prozess zu finden",
        ],
        "context_note": "7040 = Service-Konfigurationsänderung. Häufig durch Windows Updates oder Konfigurationstools.",
        "suspicious_only_if": "Interessant bei unbekannten Services oder wenn in Kombination mit 7045/4697.",
    },
    "logon_failure": {
        "max_severity": "high",
        "isolation_allowed": False,
        "description": "Authentication failure – potential brute force or credential stuffing.",
        "action_template": [
            "Wie viele Failures? Ziel-Account gesperrt?",
            "Herkunfts-IP – intern oder extern?",
            "Zeitraum: burst (Brute-Force) oder verteilt (Spray)?",
            "4624 (Success) nach den Failures? → mögl. erfolgreicher Zugriff",
        ],
        "context_note": "4625/4771 = Auth-Fehler. Einzelne Fehler normal; ≥10 im Cluster prüfungswürdig.",
        "suspicious_only_if": "Ab ≥5 im Cluster oder von externer IP.",
    },
    "process_create": {
        "max_severity": "high",
        "isolation_allowed": False,
        "description": "Process creation – check parent/child chain and command line.",
        "action_template": [
            "Elternprozess identifizieren – erwartet?",
            "Command-Line auf Obfuscation oder suspicious Flags prüfen",
            "Hash der Executable auf VirusTotal",
            "Netzwerkverbindungen des Prozesses prüfen",
        ],
        "context_note": "4688/Sysmon 1 = Prozesserstellung. Auf DEV-Hosts powershell.exe/cmd.exe normal.",
        "suspicious_only_if": "Verdächtig bei: LOLBin-Prozessen, encoded Commands, unbekannten Pfaden, nächtlicher Ausführung.",
    },
    "scheduled_task": {
        "max_severity": "high",
        "isolation_allowed": False,
        "description": "Scheduled task creation/modification – common persistence mechanism.",
        "action_template": [
            "Task-Name und Aktion (ausgeführtes Binary) prüfen",
            "Wer hat den Task erstellt?",
            "Ausführungszeitplan: regelmäßig oder bei Anmeldung?",
        ],
        "context_note": "4698/4702 = Task-Erstellung/-Änderung. Gängiger Persistenzmechanismus.",
        "suspicious_only_if": "Immer prüfen; besonders bei unbekannten Task-Namen oder Script-Ausführung.",
    },
    "logon_success": {
        "max_severity": "low",
        "isolation_allowed": False,
        "description": "Successful logon – baseline-conform on active workstations.",
        "action_template": [
            "Logon-Type prüfen: 2=Interaktiv, 3=Netzwerk, 10=Remote",
            "Auffällig: Logon außerhalb Arbeitszeiten oder von unbekannter IP",
        ],
        "context_note": "4624 = Erfolgreiche Anmeldung. Auf aktiven Hosts normal.",
        "suspicious_only_if": "Nur bei ungewöhnlichem Logon-Type, -Zeit, oder nach 4625-Cluster.",
    },
    "logoff": {
        "max_severity": "info",
        "isolation_allowed": False,
        "description": "Session logoff – routine event.",
        "action_template": [],
        "context_note": "4634/4647 = Abmeldung. Kein Sicherheitsindikator per se.",
        "suspicious_only_if": "Nicht isoliert verdächtig.",
    },
    "privilege_use": {
        "max_severity": "medium",
        "isolation_allowed": False,
        "description": "Special privilege use – expected for admins, flag for non-admins.",
        "action_template": [
            "Welches Privilege? SeDebugPrivilege/SeBackupPrivilege besonders prüfen",
            "Account: Admin oder normaler Nutzer?",
        ],
        "context_note": "4672 = Sonderrechte. Für Admin-Accounts normal.",
        "suspicious_only_if": "Verdächtig für nicht-Admin-Accounts oder mit SeDebugPrivilege.",
    },
    "kerberos": {
        "max_severity": "high",
        "isolation_allowed": False,
        "description": "Kerberos ticket request – check for AS-REP Roasting or Pass-the-Ticket.",
        "action_template": [
            "Ticket-Typ: TGT (4768) oder Service Ticket (4769)?",
            "Encryption-Type: RC4 (0x17) = Kerberoasting-Indikator",
            "Viele 4769 für ungewöhnliche Services?",
        ],
        "context_note": "Kerberos-Events. Einzelne Requests normal; Bulk-Requests verdächtig.",
        "suspicious_only_if": "RC4-Encryption bei 4769, Bulk-Requests, ungewöhnliche Targets.",
    },
    # ── FIM / Syscheck families ──────────────────────────────────────────────
    "fim_deleted_file": {
        "max_severity": "medium",
        "isolation_allowed": False,
        "description": "Wazuh Syscheck/FIM: eine Datei wurde gelöscht. Kein Prozess, kein Command-Line-Kontext.",
        "action_template": [
            "Prüfen ob die Löschung administrativ beabsichtigt war (Deployment, Update, Konfigurationsänderung)",
            "Benachbarte Syscheck-Events unter demselben Verzeichnis korrelieren",
            "Prüfen ob die Datei durch eine neue Version ersetzt wurde (create-Event kurz danach?)",
            "Service/App-Kontext des Pfades prüfen: /etc/cups/ → CUPS, /etc/nginx/ → Webserver, etc.",
            "Paket-/Admin-Änderungen im selben Zeitraum prüfen (apt/yum/dpkg-Logs)",
            "Nur bei zusätzlicher verdächtiger Aktivität eskalieren",
        ],
        "context_note": (
            "Wazuh FIM-Delete-Event (syscheck_deleted). "
            "Kein Prozess und keine Command Line im Event – diese Felder NICHT erfinden. "
            "Einordnung primär anhand des Dateipfads: Systemkonfiguration, App-Config, Temp-Datei, Log. "
            "Einzelne PPD/Config-Löschungen bei CUPS, Druckern, Paketmanager-Updates sind sehr häufig harmlos."
        ),
        "suspicious_only_if": (
            "Erst auffällig wenn: mehrere kritische Systemdateien gleichzeitig gelöscht werden, "
            "Dateien unter /etc/sudoers.d/ /etc/cron*/ /etc/ssh/ betroffen sind, "
            "direkt vor/nach Shell-Zugriff oder Login-Events auf demselben Host, "
            "oder wenn viele Dateien eines einzelnen Dienstes in kurzer Zeit betroffen sind."
        ),
        "typical_triggers": "Package-Update, Admin-Änderung, CUPS/Druckerkonfiguration, automatischer Cleanup-Cronjob.",
    },
    "fim_modified_file": {
        "max_severity": "medium",
        "isolation_allowed": False,
        "description": "Wazuh Syscheck/FIM: eine Datei wurde modifiziert.",
        "action_template": [
            "Dateipfad und Kontext einordnen (Systemconfig, App-Config, Temp, Log)",
            "Benachbarte FIM-Events im selben Verzeichnis prüfen",
            "Zeitpunkt mit Admin/Login-Events korrelieren",
            "War eine Änderung an diesem Dienst/dieser Datei geplant?",
        ],
        "context_note": (
            "Wazuh FIM-Modify-Event. Kein Prozess/Command-Line im Event. "
            "Primäre Einordnung anhand des Pfads und Dateityps."
        ),
        "suspicious_only_if": (
            "Kritische Systemdateien (/etc/passwd, /etc/shadow, /etc/sudoers, SSH-Authorized-Keys), "
            "oder viele Dateien eines Dienstes in kurzer Zeit."
        ),
        "typical_triggers": "Konfigurationsänderung, Software-Update, Admin-Aktion, Cronjob.",
    },
    "fim_new_file": {
        "max_severity": "low",
        "isolation_allowed": False,
        "description": "Wazuh Syscheck/FIM: eine neue Datei wurde erstellt.",
        "action_template": [
            "Dateipfad und Typ einordnen",
            "Gehört die Datei zu einem installierten Paket oder Deployment?",
            "Prüfen ob die Datei ausführbar ist (Webshell, Dropper?)",
        ],
        "context_note": "FIM-Create-Event. Kein Prozesskontext. Einordnung anhand Pfad und Dateityp.",
        "suspicious_only_if": "Ausführbare Dateien in Web-Root, /tmp, /var/tmp; oder unbekannte Binaries in /usr/bin.",
        "typical_triggers": "Software-Installation, Deployment, Admin-Aktion, Konfigurationserstellung.",
    },
}

# Families that are purely infrastructure/noise – AI gets hard severity ceiling
_INFRA_FAMILIES: frozenset[str] = frozenset({
    "dns_infra", "network_infra", "winrm_infra", "service_state",
    "log_service", "hyperv_infra", "powershell_infra",
})


def _get_event_class_context(family: str) -> str:
    """Build a structured context block for AI prompts based on event-family metadata.

    Returns an empty string when the family has no metadata entry.
    """
    meta = _EVENT_CLASS_METADATA.get(family)
    if not meta:
        return ""

    isolation_str = (
        "JA (nur bei eindeutiger Evidenz)" if meta["isolation_allowed"]
        else "NEIN – für diesen Event-Typ NICHT angemessen"
    )
    severity_ceiling = meta["max_severity"].upper()

    lines = [
        "── Event-Klassen-Kontext (VERBINDLICH für deine Bewertung) ──────────────",
        f"Familie      : {family}",
        f"Beschreibung : {meta['description']}",
        f"Max. Severity: {severity_ceiling}  ← erhöhe NUR mit expliziter Korrelations-Evidenz",
        f"Host-Isolation empfehlen: {isolation_str}",
        f"Kontext-Hinweis: {meta['context_note']}",
    ]
    if meta.get("suspicious_only_if"):
        lines.append(f"Wann wirklich verdächtig: {meta['suspicious_only_if']}")
    if meta.get("typical_triggers"):
        lines.append(f"Typische Auslöser: {meta['typical_triggers']}")
    if meta.get("action_template"):
        lines.append("Empfohlene Aktionen (kategorie-spezifisch):")
        for act in meta["action_template"]:
            lines.append(f"  • {act}")
    lines.append("────────────────────────────────────────────────────────────────────")

    return "\n".join(lines)


# Sysmon event-ID → family
_SYSMON_FAMILY_MAP: dict[int, str] = {
    1: "process_create",
    2: "file_create_time",
    3: "network",
    5: "process_terminate",
    6: "driver_load",
    7: "image_load",
    8: "create_remote_thread",
    9: "raw_access_read",
    10: "process_access",
    11: "file_create",
    12: "registry_event",
    13: "registry_event",
    14: "registry_event",
    15: "file_stream",
    16: "sysmon_config",
    17: "pipe_created",
    18: "pipe_connected",
    19: "wmi_filter",
    20: "wmi_consumer",
    21: "wmi_subscription",
    22: "dns_query",
    23: "file_delete",
    25: "process_tamper",
    26: "file_delete_detected",
}


def _determine_event_family(
    event_id: str | None,
    groups: list[str],
    decoder: str | None,
) -> str:
    """Return a short family label for the event (e.g. 'logon_failure', 'process_create')."""
    decoder_str = (decoder or "").lower()
    groups_lower = [g.lower() for g in groups]

    # ── FIM / Syscheck detection (must come before Windows Event ID lookup) ──
    is_syscheck = (
        "syscheck" in decoder_str
        or any("syscheck" in g for g in groups_lower)
    )
    if is_syscheck:
        if "deleted" in decoder_str or any("deleted" in g for g in groups_lower):
            return "fim_deleted_file"
        if any(g in groups_lower for g in ("syscheck_entry_added", "syscheck_new_entry")):
            return "fim_new_file"
        return "fim_modified_file"

    is_sysmon = (
        "sysmon" in decoder_str
        or any("sysmon" in g for g in groups_lower)
    )

    try:
        eid = int(event_id) if event_id else None
    except (ValueError, TypeError):
        eid = None

    if eid is not None:
        if is_sysmon:
            return _SYSMON_FAMILY_MAP.get(eid, "sysmon")
        mapped = _EVENT_FAMILY_MAP.get(eid)
        if mapped:
            return mapped
        # Windows Security range fallback
        if 4720 <= eid <= 4767:
            return "account_mgmt"
        if 4727 <= eid <= 4764:
            return "group_mgmt"

    if is_sysmon:
        return "sysmon"
    return "other"


def _build_event_summary(
    event_family: str | None,
    user: str | None,
    target_user: str | None,
    subject_user: str | None,
    ip_address: str | None,
    process: str | None,
    service_name: str | None,
    rule_description: str | None,
    event_explanation: str | None,
) -> str | None:
    """Return a short human-readable one-liner for the event."""
    family = event_family or "other"
    effective_user = target_user or user or subject_user
    effective_ip = (
        ip_address
        if ip_address and ip_address not in ("-", "::1", "127.0.0.1", "")
        else None
    )
    proc_name = (
        process.replace("\\", "/").split("/")[-1] if process else None
    )

    def _join(*parts: str | None) -> str:
        return " | ".join(p for p in parts if p)

    if family == "logon_success":
        return _join("Logon erfolgreich", effective_user, effective_ip)
    if family == "logon_failure":
        return _join("Anmelde-Fehler", effective_user, effective_ip)
    if family == "logon_explicit":
        return _join("Explicit-Credential-Logon", effective_user, effective_ip)
    if family == "logoff":
        return _join("Abmeldung", effective_user)
    if family == "privilege_use":
        return _join("Privilege-Nutzung", effective_user)
    if family == "process_create":
        return _join("Prozess erstellt", proc_name, effective_user)
    if family == "process_terminate":
        return _join("Prozess beendet", proc_name)
    if family == "service_install":
        return _join("Service installiert", service_name)
    if family == "scheduled_task":
        return _join("Scheduled Task", effective_user)
    if family == "account_mgmt":
        return _join("Account-Änderung", effective_user or target_user)
    if family == "group_mgmt":
        return _join("Gruppen-Änderung", effective_user)
    if family == "log_cleared":
        return "Audit-Log gelöscht"
    if family == "policy_change":
        return "Policy-Änderung"
    if family == "registry_event":
        return "Registry-Zugriff"
    if family == "object_access":
        return "Objekt-Zugriff"
    if family == "network":
        return _join("Netzwerkverbindung", effective_ip)
    if family == "kerberos":
        return _join("Kerberos", effective_user)
    if family == "firewall":
        return "Firewall-Event"
    if family in ("image_load", "driver_load"):
        return _join("Image geladen", proc_name)
    if family == "file_create":
        return "Datei erstellt"
    if family == "dns_query":
        return "DNS-Abfrage"
    if family == "sysmon":
        return _join("Sysmon-Event", proc_name)
    if family == "fim_deleted_file":
        return _join("FIM: Datei gelöscht", service_name or rule_description)
    if family == "fim_modified_file":
        return _join("FIM: Datei geändert", service_name or rule_description)
    if family == "fim_new_file":
        return _join("FIM: Neue Datei", service_name or rule_description)
    # Generic fallback: shorten explanation/description
    fallback = event_explanation or rule_description
    if fallback:
        return fallback[:100]
    return None


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
    system_message = _pick(
        raw,
        "data.win.system.message",
        "win.system.message",
        "full_log",
    )
    platform = detect_platform(raw, list(groups), decoder, event_id)
    event_id_str = str(event_id) if event_id is not None else None
    event_explanation = _resolve_event_explanation(
        event_id=event_id_str,
        rule_description=str(rule_description) if rule_description else None,
        decoder=str(decoder) if decoder else None,
        groups=[str(g) for g in groups],
    )

    # ── Extended fields ──────────────────────────────────────────────────────
    parent_process = _pick(
        raw,
        "data.win.eventdata.parentProcessName",
        "data.win.eventdata.ParentProcessName",
        "data.win.eventdata.parentImage",
        "data.win.eventdata.ParentImage",
    )
    target_user = _pick(
        raw,
        "data.win.eventdata.targetUserName",
        "data.win.eventdata.TargetUserName",
    )
    subject_user = _pick(
        raw,
        "data.win.eventdata.subjectUserName",
        "data.win.eventdata.SubjectUserName",
    )
    workstation = _pick(
        raw,
        "data.win.eventdata.workstationName",
        "data.win.eventdata.WorkstationName",
    )
    substatus = _pick(
        raw,
        "data.win.eventdata.subStatus",
        "data.win.eventdata.SubStatus",
    )
    service_type = _pick(
        raw,
        "data.win.eventdata.serviceType",
        "data.win.eventdata.ServiceType",
    )
    start_type = _pick(
        raw,
        "data.win.eventdata.startType",
        "data.win.eventdata.StartType",
    )
    image_path = _pick(
        raw,
        "data.win.eventdata.imagePath",
        "data.win.eventdata.image",
        "data.win.eventdata.Image",
        "data.win.eventdata.ImagePath",
    )
    process_id = _pick(
        raw,
        "data.win.eventdata.processId",
        "data.win.eventdata.ProcessId",
        "data.win.system.processID",
    )
    new_process_id = _pick(
        raw,
        "data.win.eventdata.newProcessId",
        "data.win.eventdata.NewProcessId",
    )

    # ── FIM / Syscheck fields ────────────────────────────────────────────────
    fim_path = _pick(
        raw,
        "syscheck.path",
        "data.syscheck.path",
    )
    fim_mode = _pick(
        raw,
        "syscheck.event",
        "data.syscheck.event",
    ) or _pick(
        raw,
        "syscheck.mode",
        "data.syscheck.mode",
    )
    fim_owner = _pick(
        raw,
        "syscheck.uname_before",
        "data.syscheck.uname_before",
        "syscheck.uid_before",
        "data.syscheck.uid_before",
    )
    fim_group = _pick(
        raw,
        "syscheck.gname_before",
        "data.syscheck.gname_before",
        "syscheck.gid_before",
        "data.syscheck.gid_before",
    )

    event_family = _determine_event_family(
        event_id=event_id_str,
        groups=[str(g) for g in groups],
        decoder=str(decoder) if decoder else None,
    )
    summary = _build_event_summary(
        event_family=event_family,
        user=str(user) if user else None,
        target_user=str(target_user) if target_user else None,
        subject_user=str(subject_user) if subject_user else None,
        ip_address=str(ip_address) if ip_address else None,
        process=str(process) if process else None,
        service_name=str(service_name) if service_name else None,
        rule_description=str(rule_description) if rule_description else None,
        event_explanation=event_explanation,
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
        system_message=str(system_message) if system_message else None,
        # Extended fields
        parent_process=str(parent_process) if parent_process else None,
        target_user=str(target_user) if target_user else None,
        subject_user=str(subject_user) if subject_user else None,
        workstation=str(workstation) if workstation else None,
        substatus=str(substatus) if substatus else None,
        service_type=str(service_type) if service_type else None,
        start_type=str(start_type) if start_type else None,
        image_path=str(image_path) if image_path else None,
        process_id=str(process_id) if process_id else None,
        new_process_id=str(new_process_id) if new_process_id else None,
        event_family=event_family,
        summary=summary,
        fim_path=str(fim_path) if fim_path else None,
        fim_mode=str(fim_mode) if fim_mode else None,
        fim_owner=str(fim_owner) if fim_owner else None,
        fim_group=str(fim_group) if fim_group else None,
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

    # ---
    # Limit-Logik anpassen: Wenn limit > 10000, dann kein Limit (alle Events)
    size_value = limit if limit <= 10000 else 1000000  # 1 Mio als Hardcap für Elasticsearch
    payload: dict[str, Any] = {
        "size": size_value,
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

def _call_ollama_generate(connection: dict[str, Any], prompt: str, timeout: float = 240.0) -> str:
    payload = {
        "model": connection["ollama_model"],
        "stream": False,
        "prompt": prompt,
        "options": {"num_predict": 1200},
    }
    with httpx.Client(timeout=timeout) as client:
        resp = client.post(
            f"{connection['ollama_url'].rstrip('/')}/api/generate", json=payload
        )
        if not resp.is_success:
            body = resp.text[:500]
            raise httpx.HTTPStatusError(
                f"Ollama {resp.status_code}: {body}", request=resp.request, response=resp
            )
        return str(resp.json().get("response", "")).strip()


def _call_ollama_json(connection: dict[str, Any], prompt: str, timeout: float = 240.0) -> dict[str, Any]:
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
        if not resp.is_success:
            body = resp.text[:500]
            raise httpx.HTTPStatusError(
                f"Ollama {resp.status_code}: {body}", request=resp.request, response=resp
            )
        raw = resp.json().get("response", "{}")
        try:
            return json.loads(raw)  # type: ignore[return-value]
        except json.JSONDecodeError:
            return {"raw": raw}


def _split_sentences(text: str) -> list[str]:
    parts = [p.strip() for p in re.split(r"(?<=[.!?])\s+", text or "") if p.strip()]
    return parts


def _pick_suspicious_fields(smart: SnipenSmartEvent) -> list[str]:
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


def _ensure_explain_quality(
    parsed: dict[str, Any],
    smart: SnipenSmartEvent,
    *,
    remediation_mode: bool,
    family: str = "other",
) -> dict[str, Any]:
    family_meta = _EVENT_CLASS_METADATA.get(family, {})
    is_infra = family in _INFRA_FAMILIES

    summary = str(parsed.get("summary", "") or "").strip()
    summary_sentences = _split_sentences(summary)
    if len(summary_sentences) < 4:
        fallback_lines = [
            f"Das Event zeigt eine {'infrastrukturrelevante' if is_infra else 'sicherheitsrelevante'} Aktivität auf Host {smart.host or 'unbekanntem Host'}.",
            f"Regel: {smart.rule_description or smart.rule_id or 'unbekannt'} (Level {smart.rule_level if smart.rule_level is not None else 'n/a'}).",
            f"Event-ID: {smart.event_id or 'n/a'}, Prozess: {smart.process or 'n/a'}, Benutzer: {smart.user or 'n/a'}.",
        ]
        if smart.command_line:
            fallback_lines.append(f"Die Befehlszeile enthält: {smart.command_line}.")
        if smart.ip_address and smart.ip_address != "-":
            fallback_lines.append(f"Die Aktivität ist mit der IP-Adresse {smart.ip_address} verknüpft.")
        if remediation_mode:
            if is_infra:
                fallback_lines.append("Als ersten Schritt die Infrastruktur-Konfiguration prüfen; kein sofortiges Containment erforderlich.")
            else:
                fallback_lines.append("Aus Incident-Response-Sicht sollte zunächst Containment erfolgen, bevor weitere Änderungen am System vorgenommen werden.")
        else:
            fallback_lines.append("Für die Bewertung sind Kontext, Baseline-Abweichungen und mögliche Angriffsschritte im zeitlichen Umfeld entscheidend.")
        summary = " ".join(fallback_lines)

    why_suspicious = str(parsed.get("why_suspicious", "") or "").strip()
    if len(_split_sentences(why_suspicious)) < 2:
        if is_infra:
            why_suspicious = (
                f"Event-ID {smart.event_id or 'n/a'} gehört zur Infrastruktur-Kategorie '{family}'. "
                f"Regel-Level {smart.rule_level if smart.rule_level is not None else 'n/a'} mit Beschreibung '{smart.rule_description or smart.rule_id or 'n/a'}'. "
                "Isoliert ist dieses Event kein Angriffsindikator; relevant nur in Kombination mit Auth-Fehlern oder Prozesserstellung."
            )
        else:
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

    is_fim = family in _FIM_FAMILIES

    unusual_behavior = [str(x) for x in parsed.get("unusual_behavior", []) if str(x).strip()]
    if len(unusual_behavior) < 3:
        if is_infra:
            fallback_unusual = [
                f"Infrastruktur-Event: {smart.rule_description or smart.rule_id or 'unbekannt'}.",
                f"Event auf Host {smart.host or 'unbekannt'}.",
                "Keine direkten Angriffsindikatoren ohne Korrelation.",
            ]
        elif is_fim:
            fallback_unusual = [
                f"FIM-Event: Datei '{smart.fim_path or smart.location or '(Pfad unbekannt)'}' wurde erkannt",
                f"Syscheck-Regel: {smart.rule_description or smart.rule_id or 'syscheck'}",
                f"Erkennungsregel Level: {smart.rule_level if smart.rule_level is not None else 'unbekannt'}",
            ]
        else:
            fallback_unusual = [
                f"Prozesskontext: {smart.process} in sicherheitsrelevantem Event." if smart.process else f"Regel-Level {smart.rule_level if smart.rule_level is not None else 'unbekannt'} mit Beschreibung '{smart.rule_description or smart.rule_id or 'unbekannt'}'.",
                f"Benutzerkontext: {smart.user}." if smart.user else f"Event-ID {smart.event_id or 'unbekannt'} auf Host {smart.host or 'unbekannt'}.",
                f"Regel-Level {smart.rule_level if smart.rule_level is not None else 'unbekannt'} mit Beschreibung '{smart.rule_description or smart.rule_id or 'unbekannt'}'.",
            ]
        if smart.command_line and not is_fim:
            fallback_unusual.append(f"Auffällige Befehlszeile: {smart.command_line}")
        unusual_behavior = list(dict.fromkeys(unusual_behavior + fallback_unusual))[:6]

    deviations = [str(x) for x in parsed.get("deviations", []) if str(x).strip()]
    if len(deviations) < 3:
        if is_infra:
            fallback_deviations = [
                f"Infrastruktur-Ereignis: {family} – kein direktes Abweichungsmuster.",
                "Häufigkeit prüfen: tritt das Event öfter als im Baseline-Zeitraum auf?",
                "Zieldomains/IPs validieren: bekannte interne Infrastruktur oder extern?",
            ]
        elif is_fim:
            fallback_deviations = [
                "Abweichung von erwarteter Datei-/Konfigurationsänderung",
                "Prüfen ob Änderung durch Paket-Update oder Admin-Aktion erklärbar ist",
                "Häufigkeit solcher FIM-Events für diesen Host im Baseline vergleichen",
            ]
        else:
            fallback_deviations = [
                "Sicherheitsregel wurde mit erhöhtem Risiko-Level ausgelöst.",
                "Abweichung vom erwarteten Verhalten – Korrelation mit weiteren Events erforderlich.",
                "Event benötigt Korrelation mit zeitnahen Folgeereignissen und Baseline.",
            ]
        deviations = list(dict.fromkeys(deviations + fallback_deviations))[:6]

    remediation = [str(x) for x in parsed.get("remediation", []) if str(x).strip()]
    min_remediation = 6 if remediation_mode else 5
    if len(remediation) < min_remediation:
        # Use category-specific action template if available
        template = family_meta.get("action_template", [])
        if template:
            fallback_remediation = list(template)
        elif is_infra:
            fallback_remediation = [
                "Infrastruktur-Konfiguration (DNS, Netzwerk, VPN) überprüfen.",
                "Event-Häufigkeit mit Baseline vergleichen.",
                "Systemlogs auf weitere Fehler im selben Zeitraum prüfen.",
                "Konfigurationsänderungen rückgängig machen falls bekannt.",
            ]
        else:
            fallback_remediation = [
                "Prozessbaum und Parent/Child-Kette für den Event vollständig prüfen.",
                "Hash und Signatur der betroffenen Binärdatei gegen Threat-Intel prüfen.",
                "Persistenzmechanismen (Services, Tasks, Registry/Autostart) kontrollieren.",
                "Betroffene Credentials und privilegierte Sessions auf Missbrauch prüfen.",
                "Findings dokumentieren und Detection-Regeln/Alerting nachschärfen.",
            ]
            # Only add host isolation for families that allow it
            if family_meta.get("isolation_allowed", True):
                fallback_remediation.insert(0, "Betroffenen Host logisch isolieren oder streng segmentieren.")
        remediation = list(dict.fromkeys(remediation + fallback_remediation))[:8]

    next_checks = [str(x) for x in parsed.get("next_checks", []) if str(x).strip()]
    min_checks = 6 if remediation_mode else 5
    if len(next_checks) < min_checks:
        if is_infra:
            fallback_checks = [
                "Event-Häufigkeit in den letzten 7 Tagen analysieren – neu oder chronisch?",
                "Betroffene Dienste/Verbindungen auf anderen Hosts suchen.",
                "Netzwerk-/DNS-Konfiguration auf Fehler prüfen.",
                "Systemlogs (System, Application) im selben Zeitfenster korrelieren.",
                "Monitoring für dieses Event einrichten falls es wiederholt auftritt.",
            ]
        elif is_fim:
            fallback_checks = [
                "Weitere Syscheck-Events im gleichen Verzeichnis prüfen",
                "Prüfen, ob Datei durch neue Version ersetzt wurde",
                "Paket-/Admin-Aktivität im selben Zeitraum prüfen",
                "Service-Kontext des Pfades prüfen (z. B. CUPS, nginx, sshd)",
                "Baseline für diesen Host vergleichen",
            ]
        else:
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
    # Post-AI validation: strip forbidden phrases not supported by evidence
    event_dict = smart.model_dump(exclude_none=True)
    enriched["remediation"] = validate_action_list(remediation, event_dict)
    enriched["next_checks"] = validate_action_list(next_checks, event_dict)
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

    # Use HostOverviewBuilder for all aggregation
    overview = build_host_overview(host=host, hours=hours, events=events)

    # Fetch host profile for context-aware AI prompting
    host_profile = get_profile_for_host(host)
    profile_context = build_profile_context_block(host_profile)

    # Collect high-level event descriptions for the AI prompt
    high_level_events: list[str] = [
        f"[Level {ev.smart.rule_level}] {ev.smart.rule_description or ev.smart.rule_id or 'unknown rule'} @ {ev.smart.timestamp or '?'}"
        for ev in events
        if (ev.smart.rule_level or 0) >= 10
    ]

    suspicious_patterns: list[str] = list(dict.fromkeys(high_level_events[:20]))
    likely_benign: list[str] = []
    recommended_checks: list[str] = []
    host_risk = "low"
    ai_summary: str | None = None

    if overview.critical_alerts >= 3 or len([e for e in events if (e.smart.rule_level or 0) >= 15]) >= 1:
        host_risk = "high"
    elif overview.high_alerts >= 3 or len([e for e in events if (e.smart.rule_level or 0) >= 12]) >= 3:
        host_risk = "medium"

    if run_ai:
        # Build a compact summary for the LLM
        summary_data = {
            "host": host,
            "total_events": overview.total_events,
            "hours": hours,
            "top_rule_ids": overview.top_rule_ids[:8],
            "top_event_ids": overview.top_event_ids[:8],
            "top_descriptions": overview.top_rule_descriptions[:10],
            "severity_distribution": overview.severity_distribution,
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
            f"IMPORTANT – Host Profile Context (apply this to your risk assessment):\n"
            f"{profile_context}\n\n"
            f"Data:\n{json.dumps(summary_data, ensure_ascii=False)}"
        )

        try:
            parsed = _call_ollama_json(connection, prompt, timeout=240.0)
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
        total_events=overview.total_events,
        suspicious_patterns=suspicious_patterns,
        likely_benign=likely_benign,
        recommended_checks=recommended_checks,
        host_risk=host_risk,
        top_rule_ids=overview.top_rule_ids,
        top_event_ids=overview.top_event_ids,
        ai_summary=ai_summary,
        ran_ai=run_ai,
    )


# ── Host Snipen Overview (no AI) ─────────────────────────────────────────────

def get_host_snipen_overview(
    connection: dict[str, Any],
    host: str,
    hours: int = 24,
    limit: int = 500,
    num_timeline_buckets: int = 24,
) -> SnipenHostOverview:
    """
    Fetch events for `host` and return a pre-computed overview with severity
    distribution, top counters and a bucketed timeline.  No AI involved.
    """
    events = get_host_events(
        connection,
        host=host,
        hours=hours,
        limit=limit,
    )
    return build_host_overview(
        host=host,
        hours=hours,
        events=events,
        num_timeline_buckets=num_timeline_buckets,
    )


# ── FIM / Syscheck deterministic explainer ──────────────────────────────────

_FIM_FAMILIES: frozenset[str] = frozenset({"fim_deleted_file", "fim_modified_file", "fim_new_file"})

# Path-context registry: prefix/substring → (label, operational_context, is_sensitive)
_FIM_PATH_CONTEXTS: list[tuple[str, str, str, bool]] = [
    # (match_substring, label, operational_context, is_sensitive)
    ("/etc/cups",           "CUPS-Drucksystem",             "PPD-Dateien und Queue-Konfigurationen gehören zum CUPS-Druckdienst. Änderungen entstehen typisch durch Druckerwartung, Treiberinstallation, Package-Updates oder Admin-Konfiguration.", False),
    ("/etc/nginx",          "Nginx-Webserver",               "Nginx-Konfigurationsdatei. Änderungen durch Deployment, Zertifikats-Rotation oder Admin-Aktion.", False),
    ("/etc/apache",         "Apache-Webserver",              "Apache-Konfigurationsdatei. Änderungen durch Deployment oder Admin-Aktion.", False),
    ("/etc/httpd",          "Apache-Webserver",              "Apache-Konfigurationsdatei. Änderungen durch Deployment oder Admin-Aktion.", False),
    ("/etc/systemd",        "systemd-Unit",                  "Systemd-Service-Konfiguration. Änderungen durch Package-Updates oder Admin-Aktion.", False),
    ("/etc/init.d",         "SysV-Init-Skript",              "Init-Skript. Änderungen durch Package-Updates oder Admin-Aktion.", False),
    ("/etc/cron",           "Cron-Konfiguration",            "Cron-Job-Datei. Änderungen können für Persistenz missbraucht werden.", True),
    ("/var/spool/cron",     "Cron-Konfiguration",            "Cron-Job-Datei. Änderungen können für Persistenz missbraucht werden.", True),
    ("/etc/ssh",            "SSH-Daemon-Konfiguration",      "SSH-Konfiguration oder Schlüsseldatei. Änderungen sind sicherheitsrelevant.", True),
    ("/.ssh/",              "SSH-Benutzerschlüssel",         "SSH-Authorized-Keys oder private Schlüssel. Änderungen sind sicherheitsrelevant.", True),
    ("/etc/sudoers",        "Sudo-Konfiguration",            "Sudo-Berechtigungsdatei. Änderungen ermöglichen Rechteausweitung.", True),
    ("/etc/passwd",         "Benutzer-Datenbank",            "Linux-Benutzerdatenbank. Änderungen sind sicherheitsrelevant.", True),
    ("/etc/shadow",         "Passwort-Hashes",               "Linux-Passwort-Hash-Datei. Änderungen sind sicherheitsrelevant.", True),
    ("/etc/group",          "Gruppen-Datenbank",             "Linux-Gruppen-Datenbank. Änderungen sind sicherheitsrelevant.", True),
    ("/etc/hosts",          "Hosts-Datei",                   "Lokale DNS-Auflösung. Änderungen können für DNS-Hijacking genutzt werden.", True),
    ("/etc/ld.so",          "Linker-Konfiguration",          "Dynamischer Linker. Änderungen können für Bibliotheks-Hijacking genutzt werden.", True),
    ("/etc/profile",        "Shell-Profil",                  "Shell-Initialisierungsdatei. Änderungen können für Persistenz genutzt werden.", True),
    ("/etc/bashrc",         "Shell-Profil",                  "Shell-Initialisierungsdatei. Änderungen können für Persistenz genutzt werden.", True),
    ("/etc/environment",    "Umgebungsvariablen",            "System-Umgebungsvariablen. Änderungen sind prüfungswürdig.", True),
    ("/var/log",            "Log-Datei",                     "Systemlog. Löschungen können auf Anti-Forensik-Aktivität hindeuten.", True),
    ("/tmp/",               "Temporäres Verzeichnis",        "Temporäres Verzeichnis. Ausführbare Dateien hier sind verdächtig.", True),
    ("/var/tmp/",           "Temporäres Verzeichnis",        "Temporäres Verzeichnis. Ausführbare Dateien hier sind verdächtig.", True),
    ("/usr/bin/",           "System-Binary",                 "Systemweites Binary-Verzeichnis. Neue oder geänderte Dateien hier sind prüfungswürdig.", True),
    ("/usr/sbin/",          "System-Binary",                 "Systemweites Daemon-Binary-Verzeichnis. Neue oder geänderte Dateien hier sind prüfungswürdig.", True),
    ("/usr/local/bin/",     "Lokales Binary",                "Lokal installiertes Binary. Prüfen ob erwartet.", False),
    ("/usr/lib/",           "Systembibliothek",              "Systembibliothek. Unerwartete Änderungen sind prüfungswürdig.", False),
    ("/opt/",               "Anwendungsverzeichnis",         "Optionales Anwendungsverzeichnis. Änderungen durch Deployment oder Update.", False),
    ("/home/",              "Benutzer-Homeverzeichnis",      "Benutzerverzeichnis. Kontext hängt vom Unterverzeichnis ab.", False),
    ("/var/www",            "Webserver-Root",                "Web-Root-Verzeichnis. Neue/geänderte Skripte hier sind auf Webshells zu prüfen.", True),
]


def _fim_path_context(path: str) -> tuple[str, str, bool]:
    """Return (label, operational_context, is_sensitive) for a FIM path."""
    pl = path.lower()
    for match, label, ctx, sensitive in _FIM_PATH_CONTEXTS:
        if match.lower() in pl:
            return label, ctx, sensitive
    # Generic /etc fallback
    if pl.startswith("/etc/"):
        return "Systemkonfiguration", "Systemkonfigurationsverzeichnis. Änderungen entstehen typisch durch Package-Updates, Admin-Aktionen oder Konfigurationsmanagement.", False
    return "Systemdatei", "Systemdatei. Kontext aus dem Pfad ableiten.", False


def _fim_infer_severity(path: str, is_sensitive: bool, rule_level: int | None) -> str:
    """Heuristic severity for a FIM event based on path and rule level."""
    pl = path.lower()
    # Hard high for truly sensitive paths
    high_patterns = ("/etc/passwd", "/etc/shadow", "/etc/sudoers", "/.ssh/authorized_keys",
                     "/etc/cron", "/var/spool/cron", "/var/log", "/etc/ld.so",
                     "/usr/bin/", "/usr/sbin/", "/var/www")
    for pat in high_patterns:
        if pat in pl:
            return "high"
    if is_sensitive:
        return "medium"
    # Rule-level hint
    if rule_level is not None and rule_level >= 12:
        return "medium"
    return "low"


def explain_fim_event(
    smart: SnipenSmartEvent,
    decision: Any,
) -> SnipenExplainResult:
    """
    Fully deterministic FIM/syscheck explainer.
    No AI call, no generic fallback. Output is derived entirely from the event.
    """
    path = smart.fim_path or smart.location or "(unbekannter Pfad)"
    mode = (smart.fim_mode or "").lower()
    host = smart.host or "Unbekannter Host"
    decoder = (smart.decoder or "").lower()
    rule_level = smart.rule_level
    groups = [g.lower() for g in (smart.groups or [])]
    event_family = smart.event_family or "fim_modified_file"

    label, operational_ctx, is_sensitive = _fim_path_context(path)
    severity = _fim_infer_severity(path, is_sensitive, rule_level)

    # ── Explicit severity override for well-known low-risk prefixes ───────
    # Printer/CUPS config, nginx/apache config, systemd units, etc. are
    # routine operational changes and must never exceed "low" for a single event.
    _LOW_RISK_PREFIXES = ("/etc/cups", "/etc/nginx", "/etc/apache", "/etc/httpd",
                          "/etc/systemd", "/etc/init.d", "/usr/local/bin/", "/usr/lib/",
                          "/opt/", "/home/")
    if severity != "low" and any(path.lower().startswith(p) or p in path.lower() for p in _LOW_RISK_PREFIXES):
        severity = "low"

    # ── Determine action verb ─────────────────────────────────────────────
    if event_family == "fim_deleted_file" or "deleted" in decoder or any("deleted" in g for g in groups):
        action_verb = "gelöscht"
    elif event_family == "fim_new_file" or any(g in groups for g in ("syscheck_entry_added", "syscheck_new_entry")):
        action_verb = "neu erstellt"
    else:
        action_verb = "verändert"

    # ── scan mode description ─────────────────────────────────────────────
    if "realtime" in mode or "realtime" in decoder:
        mode_desc = "Echtzeit-Monitoring (sofort gemeldet)"
    elif "scheduled" in mode:
        mode_desc = "geplanter Syscheck-Scan"
    else:
        mode_desc = f"Syscheck-Scan (Modus: {mode or 'unbekannt'})"

    # ── Summary – no hardcoded MITRE assertions ───────────────────────────
    summary_parts = [
        f"Auf dem Host '{host}' wurde durch den Wazuh File Integrity Monitor (Syscheck) erkannt, "
        f"dass die Datei '{path}' {action_verb} wurde.",
        f"Der betroffene Pfad gehört zum Bereich: {label}.",
        f"{operational_ctx}",
        f"Das Event stammt aus einem {mode_desc} und beschreibt ausschließlich eine Dateisystem-Änderung – "
        f"kein ausführender Prozess, kein Benutzer-Login und keine Netzwerkverbindung sind in diesem Event enthalten.",
        f"Eine abschließende Bewertung erfordert die Korrelation mit weiteren Ereignissen auf diesem Host im selben Zeitraum.",
    ]
    summary = " ".join(summary_parts)

    # ── Why suspicious ───────────────────────────────────────────────────
    if is_sensitive:
        why = (
            f"Die Datei '{path}' gehört zu einem sicherheitsrelevanten Bereich ({label}). "
            f"Eine unerwartete {action_verb[:-1]}ung hier sollte verifiziert werden, besonders wenn keine geplante Änderung bekannt ist. "
            f"Falls auf '{host}' kein {label}-Kontext erwartet wird oder mehrere solche Dateien kurz hintereinander betroffen sind, "
            f"ist eine nähere Untersuchung sinnvoll."
        )
    else:
        why = (
            f"Für sich genommen ist eine einzelne {label}-Datei, die {action_verb} wurde, wenig aussagekräftig. "
            f"Auffällig wäre es nur, wenn gleichzeitig weitere Dateien in kritischeren Verzeichnissen (/etc/ssh/, /etc/sudoers, /var/log) "
            f"betroffen wären oder wenn die Änderung nicht durch eine bekannte Admin-Aktion oder ein Paket-Update erklärbar ist. "
            f"Fehlende Prozess- und Benutzerfelder sind bei FIM-Events normal und kein Verdachtsindikator."
        )

    # ── Against it ───────────────────────────────────────────────────────
    against_it = (
        f"Sehr wahrscheinlich betriebliche Ursache: {operational_ctx} "
        f"Einzelne {label}-Ereignisse treten regelmäßig bei Paket-Updates, Admin-Konfiguration und "
        f"Wartungsarbeiten auf. Der Modus '{mode or 'scheduled'}' deutet auf einen normalen Syscheck-Scan hin."
    )

    # ── Suspicious fields – only FIM-relevant, no n/a fields ─────────────
    suspicious_fields = ["fim_path"]
    if rule_level is not None:
        suspicious_fields.append("rule_level")
    if smart.fim_mode:
        suspicious_fields.append("fim_mode")
    if smart.fim_owner:
        suspicious_fields.append("fim_owner")
    if smart.fim_group:
        suspicious_fields.append("fim_group")
    if is_sensitive:
        suspicious_fields.append("path_sensitivity_high")

    # ── Unusual behavior – only observable facts, no n/a mentions ────────
    unusual_behavior = [
        f"Datei '{path}' wurde {action_verb}",
        f"Betroffener Bereich: {label}",
        f"Erkennungsmethode: {mode_desc}",
    ]
    if smart.fim_owner:
        unusual_behavior.append(f"Vorheriger Datei-Owner: {smart.fim_owner}")
    if smart.fim_group:
        unusual_behavior.append(f"Vorherige Datei-Gruppe: {smart.fim_group}")

    # ── Deviations – conditional, not invented ────────────────────────────
    deviations = [
        f"Abweichung: Falls keine geplante Änderung am {label} bekannt ist",
        f"Abweichung: Falls mehrere Dateien unter '{'/'.join(path.split('/')[:4])}/' in kurzer Zeit betroffen sind",
        "Abweichung: Falls keine zugehörige Admin-Aktion oder kein Paket-Update im selben Zeitraum erkennbar ist",
    ]

    # ── Remediation – path-specific, no generic escalation ────────────────
    path_prefix = "/".join(path.split("/")[:4])
    remediation = [
        f"Prüfen ob die Änderung an '{path}' administrativ beabsichtigt war (Deployment, Paket-Update, manuelle Konfiguration)",
        f"Benachbarte Syscheck-Events unter '{path_prefix}/' im selben Zeitraum korrelieren",
        f"CUPS-/Druckerkontext prüfen: 'systemctl status cups', 'lpstat -t'" if "/cups" in path.lower() else f"Service-Kontext zu '{label}' prüfen",
        "Paket-Manager-Log prüfen: 'grep -E \"(installed|removed|upgraded)\" /var/log/dpkg.log' (Debian) oder 'rpm -qa --last' (RHEL)",
        "Nur bei weiterer verdächtiger Aktivität eskalieren (z.B. zusätzliche FIM-Events auf sensiblen Pfaden)",
    ]

    # ── Next checks – FIM/filesystem correlation only ─────────────────────
    # No process tree, no network, no credential/privilege checks for FIM events.
    next_checks = [
        f"Weitere Syscheck-Events unter '{path_prefix}/' im selben Zeitraum suchen",
        "Prüfen ob die Datei ersetzt wurde (FIM create-Event kurz nach dem delete?)",
        "Paket-Änderungen im Zeitraum prüfen: 'zgrep -E \"(install|remove)\" /var/log/dpkg.log*'",
        "Baseline dieses Hosts mit dem aktuellen Syscheck-Stand vergleichen",
        "Service-Kontext des betroffenen Pfads prüfen (läuft der zugehörige Dienst noch normal?)",
    ]
    if "/cups" in path.lower():
        next_checks.insert(1, "CUPS-Queue-Status prüfen: 'lpstat -t', Drucker-Events in /var/log/cups/")
    if is_sensitive:
        next_checks.append("Sudo-/Admin-Logs prüfen: 'grep sudo /var/log/auth.log' – wer hatte Zugriff auf den Pfad?")

    # ── Risk score ────────────────────────────────────────────────────────
    risk_map = {"critical": 8.0, "high": 5.5, "medium": 3.0, "low": 1.5, "info": 0.5}
    risk_score = risk_map.get(severity, 2.0)

    # ── MITRE – only for genuinely high-severity paths, not low/medium ────
    # Low-severity FIM events (config files, printer PPD, etc.) must NOT inherit
    # MITRE detection mappings (T1070.004/T1485) as context evidence – those are
    # rule-engine mappings, not operational proof of malicious intent.
    mitre: list[str] = []
    if severity == "high" and smart.mitre_id:
        mitre = [smart.mitre_id]

    return SnipenExplainResult(
        summary=summary,
        why_suspicious=why,
        against_it=against_it,
        severity=severity,
        suspicious_fields=suspicious_fields,
        unusual_behavior=unusual_behavior,
        deviations=deviations,
        remediation=remediation,
        next_checks=next_checks,
        risk_score=risk_score,
        confidence="high",   # deterministic = high confidence
        mitre_techniques=mitre,
        ran_ai=False,
    )


# ── Context window helper ────────────────────────────────────────────────────

# Event families that benefit significantly from surrounding context
_CONTEXT_NEEDED_FAMILIES: frozenset[str] = frozenset({
    "network_infra", "dns_infra", "service_state", "log_service",
    "fim_modified_file", "fim_deleted_file", "fim_new_file",
    "network", "hyperv_infra", "powershell_infra",
})


def get_event_context_window(
    connection: dict[str, Any],
    event_raw: dict[str, Any],
    window_minutes: int = 15,
    max_events: int = 10,
) -> dict[str, list[SnipenEvent]]:
    """
    Fetch up to max_events events before and after the pivot event on the same host
    within ±window_minutes. Returns {"before": [...], "after": [...]}.
    Silently returns empty lists on any error (non-critical helper).
    """
    smart = _normalize_smart(event_raw)
    host = smart.host or str(_pick(event_raw, "agent.name") or "")
    timestamp_str = smart.timestamp or str(_pick(event_raw, "@timestamp") or "")

    if not host or not timestamp_str:
        return {"before": [], "after": []}

    try:
        ts = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return {"before": [], "after": []}

    window = timedelta(minutes=window_minutes)
    ts_from = (ts - window).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    ts_to = (ts + window).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    payload: dict[str, Any] = {
        "size": max_events * 2 + 2,
        "sort": [{"@timestamp": {"order": "asc"}}],
        "query": {
            "bool": {
                "filter": [
                    {"term": {"agent.name": host}},
                    {"range": {"@timestamp": {"gte": ts_from, "lte": ts_to}}},
                ]
            }
        },
    }

    index = _index_pattern(connection)
    try:
        with httpx.Client(
            verify=build_verify(connection),
            timeout=20.0,
            auth=build_auth(connection),
        ) as client:
            resp = client.post(f"{build_base_url(connection)}/{index}/_search", json=payload)
            resp.raise_for_status()
            hits = resp.json().get("hits", {}).get("hits", [])
    except Exception:
        return {"before": [], "after": []}

    before: list[SnipenEvent] = []
    after: list[SnipenEvent] = []
    for hit in hits:
        source = hit.get("_source", {})
        hit_ts_str = str(source.get("@timestamp") or "")
        if hit_ts_str == timestamp_str:
            continue  # skip pivot itself
        try:
            hit_dt = datetime.fromisoformat(hit_ts_str.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            continue
        ev_smart = _normalize_smart(source)
        ev = SnipenEvent(doc_id=hit.get("_id"), raw=source, smart=ev_smart)
        if hit_dt < ts:
            before.append(ev)
        else:
            after.append(ev)

    return {
        "before": before[-max_events:],   # most recent N before pivot
        "after": after[:max_events],      # earliest N after pivot
    }


def _build_context_summary(before: list[SnipenEvent], after: list[SnipenEvent]) -> str:
    """Build a compact text block of context events for the AI prompt."""
    def _fmt(ev: SnipenEvent) -> str:
        s = ev.smart
        ts_short = (s.timestamp or "?")[11:19]   # HH:MM:SS slice
        family = s.event_family or "other"
        desc = (s.rule_description or s.rule_id or "?")[:80]
        level = s.rule_level or 0
        extra = ""
        if s.fim_path:
            extra = f"  path={s.fim_path}"
        elif s.process:
            extra = f"  proc={s.process}"
        elif s.service_name:
            extra = f"  svc={s.service_name}"
        elif s.user:
            extra = f"  user={s.user}"
        return f"  [{level:2d}] {ts_short} [{family}] {desc}{extra}"

    lines: list[str] = []
    if before:
        lines.append(f"── {len(before)} Events VORHER (gleicher Host) ──")
        lines.extend(_fmt(ev) for ev in before)
    else:
        lines.append("── Events VORHER: keine im ±15-min-Fenster ──")
    lines.append("")
    if after:
        lines.append(f"── {len(after)} Events NACHHER (gleicher Host) ──")
        lines.extend(_fmt(ev) for ev in after)
    else:
        lines.append("── Events NACHHER: keine im ±15-min-Fenster ──")
    return "\n".join(lines)


def _detect_context_patterns(
    before: list[SnipenEvent],
    after: list[SnipenEvent],
    pivot_smart: SnipenSmartEvent,
) -> list[str]:
    """
    Detect known benign/suspicious patterns from context events.
    Returns human-readable pattern notes to enrich the explanation.
    """
    notes: list[str] = []
    all_events = before + after
    descriptions = " ".join((ev.smart.rule_description or "").lower() for ev in all_events)
    families = [ev.smart.event_family or "" for ev in all_events]

    # Package manager activity → likely explains FIM / service changes
    pkg_kw = ("dpkg", "rpm", "apt ", "yum ", "dnf ", "package", "install", "upgrad", "update")
    if any(k in descriptions for k in pkg_kw):
        notes.append(
            "Paket-Manager-Aktivität im Zeitfenster erkannt – die Änderung ist wahrscheinlich "
            "betrieblich (Package-Install/Update)."
        )

    # Service restart / reload before or after
    if "service_state" in families:
        svc_events = [ev for ev in all_events if ev.smart.event_family == "service_state"]
        svc_names = ", ".join(filter(None, (ev.smart.service_name for ev in svc_events[:3])))
        notes.append(
            f"Dienst-Zustandsänderung im Zeitfenster erkannt"
            + (f" ({svc_names})" if svc_names else "")
            + " – Service-Neustart oder Reload als Ursache prüfen."
        )

    # FIM delete + FIM create on same base path → file replacement pattern
    if pivot_smart.event_family == "fim_deleted_file" and pivot_smart.fim_path:
        pivot_dir = pivot_smart.fim_path.rsplit("/", 1)[0]
        for ev in after:
            if ev.smart.event_family == "fim_new_file" and ev.smart.fim_path:
                if (ev.smart.fim_path == pivot_smart.fim_path
                        or ev.smart.fim_path.startswith(pivot_dir)):
                    notes.append(
                        f"Datei-Ersetzungs-Muster erkannt: Delete auf '{pivot_smart.fim_path}' "
                        f"gefolgt von Create – deutet auf Config-Rotation oder Update hin, nicht auf Löschung."
                    )
                    break

    # Network infra change after service restart → operational
    if pivot_smart.event_family in ("network_infra",) and "service_state" in families:
        notes.append(
            "Dienstneustart im Kontext erkannt – Netzwerkport-Änderung ist wahrscheinlich "
            "Folge des Service-Restarts, kein eigenständiges Indiz."
        )

    return notes


# ── Single-event AI ──────────────────────────────────────────────────────────

def explain_event(connection: dict[str, Any], event_raw: dict[str, Any]) -> SnipenExplainResult:
    smart = _normalize_smart(event_raw)
    host_profile = get_profile_for_host(smart.host or "")
    profile_context = build_profile_context_block(host_profile)

    # Determine event family
    event_family = _determine_event_family(
        smart.event_id,
        list(getattr(smart, "groups", None) or []),
        getattr(smart, "decoder", None),
    )

    # ── FIM/Syscheck: fully deterministic path – bypass AI entirely ────────
    if event_family in _FIM_FAMILIES:
        decision = decide_event(
            event_id=smart.event_id,
            rule_level=smart.rule_level,
            rule_description=smart.rule_description,
            event_explanation=getattr(smart, "event_explanation", None),
            groups=list(getattr(smart, "groups", None) or []),
            event_family=event_family,
            profile_name=host_profile.name if host_profile else None,
            has_baseline_deviation=False,
            has_ti_match=bool(getattr(smart, "ti_matches", None)),
        )
        return explain_fim_event(smart, decision)

    # ── Decision Engine: pre-AI risk gate ──────────────────────────────────
    decision = decide_event(
        event_id=smart.event_id,
        rule_level=smart.rule_level,
        rule_description=smart.rule_description,
        event_explanation=getattr(smart, "event_explanation", None),
        groups=list(getattr(smart, "groups", None) or []),
        event_family=event_family,
        profile_name=host_profile.name if host_profile else None,
        has_baseline_deviation=False,
        has_ti_match=bool(getattr(smart, "ti_matches", None)),
    )

    # No-AI path for system/noise events
    if not decision.should_run_ai:
        static = build_static_explain_result(smart, decision)
        return SnipenExplainResult(
            summary=static["summary"],
            why_suspicious=static["why_suspicious"],
            against_it=static["against_it"],
            severity=static["severity"],
            risk_score=static["risk_score"],
            confidence=static["confidence"],
            mitre_techniques=[],
            remediation=static["remediation"],
            next_checks=static["next_checks"],
            unusual_behavior=static["unusual_behavior"],
            deviations=static["deviations"],
            suspicious_fields=static["suspicious_fields"],
            ran_ai=False,
        )

    # Build context blocks for the AI prompt
    decision_ctx = build_decision_context_block(decision)
    event_class_ctx = _get_event_class_context(event_family)
    guardrail_block = build_guardrail_block(smart.model_dump(exclude_none=True))

    # Derive a prominent platform note so the AI never confuses Linux with Windows.
    _plat = (smart.platform or "other").lower()
    if _plat == "linux":
        platform_note = (
            "HOST PLATFORM: Linux/Unix – this is a Linux system.\n"
            "All artefacts (paths, processes, commands, logs) are Linux-style.\n"
            "Do NOT reference Windows concepts (Event IDs, Registry, NTLM, Active Directory, etc.) "
            "unless they are explicitly present in the raw event.\n"
            "Linux-specific context: file paths start with /, daemons in /usr/sbin, "
            "config in /etc, logs in /var/log, package manager events are normal.\n"
        )
    elif _plat == "windows":
        platform_note = (
            "HOST PLATFORM: Windows – this is a Windows system.\n"
            "Use Windows-specific context: Event IDs, Registry, NTLM, Active Directory, "
            "Win32 paths (C:\\...), services, scheduled tasks.\n"
        )
    else:
        platform_note = f"HOST PLATFORM: {_plat or 'unknown'}\n"

    # Build a concise key-context block that highlights the most important observable fields
    # including file paths, command lines, registry keys, etc. that the AI must reference explicitly.
    # (FIM events are handled by explain_fim_event() above and never reach here.)
    observable_fields: dict[str, str] = {}
    if smart.system_message:
        observable_fields["system_message"] = smart.system_message
    if smart.command_line:
        observable_fields["command_line"] = smart.command_line
    if smart.process:
        observable_fields["process"] = smart.process
    if smart.registry_key:
        observable_fields["registry_key"] = smart.registry_key
    if smart.service_name:
        observable_fields["service_name"] = smart.service_name
    if smart.user:
        observable_fields["user"] = smart.user
    if smart.ip_address:
        observable_fields["ip_address"] = smart.ip_address
    if smart.location:
        observable_fields["location"] = smart.location
    observable_ctx = (
        "CRITICAL OBSERVABLE FIELDS – you MUST reference these explicitly in summary and analysis:\n"
        + "\n".join(f"  {k}: {v}" for k, v in observable_fields.items())
        if observable_fields else ""
    )

    prompt = (
        f"[SYSTEM CONTEXT]\n{platform_note}\n"
        "You are a senior SOC analyst. Explain this Wazuh security event in DETAIL and return valid JSON only. "
        "Language: German. Be concrete and technical, avoid generic phrases. "
        "Keys: summary (str, 5-8 full German sentences), "
        "why_suspicious (str, 3-6 sentences with concrete indicators), "
        "against_it (str – reasons it could be benign, 2-4 sentences, or null), "
        "severity (one of: critical/high/medium/low/info), "
        "suspicious_fields (list[str] – concrete event fields: event_id, user, ip_address, process, command_line, rule_level), "
        "unusual_behavior (list[str] – concrete observed unusual behaviors, min 3 items), "
        "deviations (list[str] – deviations from expected baseline or normal behavior, min 3 items), "
        "risk_score (float 0-10, 10=most dangerous), "
        "confidence (one of: low/medium/high/very_high), "
        "mitre_techniques (list[str] – ATT&CK IDs with names, or empty list if not allowed), "
        "remediation (list[str], min 5 concrete actions), "
        "next_checks (list[str], min 5 concrete checks).\n\n"
        "Reasoning requirements: "
        "1) reference at least 3 concrete event fields explicitly, especially file paths, command lines, registry keys from the CRITICAL OBSERVABLE FIELDS block; "
        "2) for infrastructure/network events describe the operational root cause FIRST before any security angle; "
        "3) fehlende Felder (user=n/a, process=n/a) sind KEIN Verdachtsindikator bei System-/Infrastruktur-Events; "
        "4) if confidence is low, explain exactly why.\n\n"
        f"{observable_ctx}\n\n"
        f"MANDATORY – Decision Engine Guardrails (you MUST follow these):\n{decision_ctx}\n\n"
        f"MANDATORY – Artifact-Type Guardrails (VERBOTEN-Liste beachten):\n{guardrail_block}\n\n"
        f"Additional Event Class Context:\n{event_class_ctx}\n\n"
        f"Host Profile Context:\n{profile_context}\n\n"
        "Smart fields:\n"
        f"{json.dumps(smart.model_dump(exclude_none=True), ensure_ascii=False)}\n\n"
        "Raw event excerpt:\n"
        f"{json.dumps({k: v for k, v in event_raw.items() if k in ('rule', 'data', 'agent', 'decoder', '@timestamp', 'location')}, ensure_ascii=False, default=str)}"
    )
    try:
        parsed = _call_ollama_json(connection, prompt, timeout=240.0)
        parsed = _ensure_explain_quality(parsed, smart, remediation_mode=False, family=event_family)
        # Enforce severity ceiling from decision engine
        parsed_sev = str(parsed.get("severity", decision.severity)).lower()
        _sev_order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        if _sev_order.get(parsed_sev, 2) > _sev_order.get(decision.severity, 4):
            parsed_sev = decision.severity
        # Enforce MITRE guard
        mitre = [str(x) for x in parsed.get("mitre_techniques", [])] if decision.allow_mitre else []
        return SnipenExplainResult(
            summary=str(parsed.get("summary", "No explanation returned.")),
            why_suspicious=parsed.get("why_suspicious") or None,
            against_it=parsed.get("against_it") or None,
            severity=parsed_sev,
            suspicious_fields=[str(x) for x in parsed.get("suspicious_fields", [])],
            unusual_behavior=[str(x) for x in parsed.get("unusual_behavior", [])],
            deviations=[str(x) for x in parsed.get("deviations", [])],
            remediation=[str(x) for x in parsed.get("remediation", [])],
            next_checks=[str(x) for x in parsed.get("next_checks", [])],
            ran_ai=True,
            risk_score=float(parsed["risk_score"]) if parsed.get("risk_score") is not None else decision.risk_score,
            confidence=str(parsed["confidence"]).lower() if parsed.get("confidence") else decision.confidence,
            mitre_techniques=mitre,
        )
    except Exception as exc:
        return SnipenExplainResult(
            summary=f"AI explanation failed: {exc}",
            severity="medium",
            ran_ai=False,
        )


def remediate_event(connection: dict[str, Any], event_raw: dict[str, Any]) -> SnipenExplainResult:
    smart = _normalize_smart(event_raw)
    host_profile = get_profile_for_host(smart.host or "")
    profile_context = build_profile_context_block(host_profile)

    # Determine event family
    event_family = _determine_event_family(
        smart.event_id,
        list(getattr(smart, "groups", None) or []),
        getattr(smart, "decoder", None),
    )

    # ── FIM/Syscheck: fully deterministic path – bypass AI entirely ────────
    if event_family in _FIM_FAMILIES:
        decision = decide_event(
            event_id=smart.event_id,
            rule_level=smart.rule_level,
            rule_description=smart.rule_description,
            event_explanation=getattr(smart, "event_explanation", None),
            groups=list(getattr(smart, "groups", None) or []),
            event_family=event_family,
            profile_name=host_profile.name if host_profile else None,
            has_baseline_deviation=False,
            has_ti_match=bool(getattr(smart, "ti_matches", None)),
        )
        return explain_fim_event(smart, decision)

    # ── Decision Engine: pre-AI risk gate ──────────────────────────────────
    decision = decide_event(
        event_id=smart.event_id,
        rule_level=smart.rule_level,
        rule_description=smart.rule_description,
        event_explanation=getattr(smart, "event_explanation", None),
        groups=list(getattr(smart, "groups", None) or []),
        event_family=event_family,
        profile_name=host_profile.name if host_profile else None,
        has_baseline_deviation=False,
        has_ti_match=bool(getattr(smart, "ti_matches", None)),
    )

    # No-AI path for system/noise events
    if not decision.should_run_ai:
        static = build_static_explain_result(smart, decision)
        return SnipenExplainResult(
            summary=static["summary"],
            why_suspicious=static["why_suspicious"],
            against_it=static["against_it"],
            severity=static["severity"],
            risk_score=static["risk_score"],
            confidence=static["confidence"],
            mitre_techniques=[],
            remediation=static["remediation"],
            next_checks=static["next_checks"],
            unusual_behavior=static["unusual_behavior"],
            deviations=static["deviations"],
            suspicious_fields=static["suspicious_fields"],
            ran_ai=False,
        )

    # Build context blocks for the AI prompt
    decision_ctx = build_decision_context_block(decision)
    event_class_ctx = _get_event_class_context(event_family)
    guardrail_block = build_guardrail_block(smart.model_dump(exclude_none=True))

    prompt = (
        "You are a senior incident responder. For the following Wazuh security event, provide specific "
        "remediation steps and return valid JSON only with keys: "
        "summary (str – what happened, 4-7 sentences in German), "
        "why_suspicious (str, 3-6 sentences with technical detail), "
        "against_it (str or null, 2-4 sentences), "
        "severity (one of: critical/high/medium/low/info), "
        "suspicious_fields (list[str] – the concrete fields that matter most), "
        "unusual_behavior (list[str] – specific suspicious behavior observed, min 3 items), "
        "deviations (list[str] – deviations from normal/expected behavior, min 3 items), "
        "risk_score (float 0-10, 10=most dangerous), "
        "confidence (one of: low/medium/high/very_high), "
        "mitre_techniques (list[str] – ATT&CK IDs with names, or empty list if not allowed), "
        "remediation (list[str] – concrete prioritized steps for the EVENT CLASS, min 6 items), "
        "next_checks (list[str] – what to investigate next, min 6 items).\n\n"
        "Reasoning requirements: tailor containment/eradication/recovery to the event class; "
        "reference concrete evidence fields; avoid generic one-liners; "
        "fehlende Felder (user=n/a, process=n/a) sind KEIN Verdachtsindikator bei System-/Infrastruktur-Events.\n\n"
        f"MANDATORY – Decision Engine Guardrails (you MUST follow these):\n{decision_ctx}\n\n"
        f"MANDATORY – Artifact-Type Guardrails (VERBOTEN-Liste beachten):\n{guardrail_block}\n\n"
        f"Additional Event Class Context:\n{event_class_ctx}\n\n"
        f"Host Profile Context:\n{profile_context}\n\n"
        "Smart fields:\n"
        f"{json.dumps(smart.model_dump(exclude_none=True), ensure_ascii=False)}\n\n"
        "Raw event excerpt:\n"
        f"{json.dumps({k: v for k, v in event_raw.items() if k in ('rule', 'data', 'agent', 'decoder', '@timestamp')}, ensure_ascii=False, default=str)}"
    )
    try:
        parsed = _call_ollama_json(connection, prompt, timeout=240.0)
        parsed = _ensure_explain_quality(parsed, smart, remediation_mode=True, family=event_family)
        # Enforce severity ceiling from decision engine
        parsed_sev = str(parsed.get("severity", decision.severity)).lower()
        _sev_order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        if _sev_order.get(parsed_sev, 2) > _sev_order.get(decision.severity, 4):
            parsed_sev = decision.severity
        mitre = [str(x) for x in parsed.get("mitre_techniques", [])] if decision.allow_mitre else []
        return SnipenExplainResult(
            summary=str(parsed.get("summary", "No remediation returned.")),
            why_suspicious=parsed.get("why_suspicious") or None,
            against_it=parsed.get("against_it") or None,
            severity=parsed_sev,
            suspicious_fields=[str(x) for x in parsed.get("suspicious_fields", [])],
            unusual_behavior=[str(x) for x in parsed.get("unusual_behavior", [])],
            deviations=[str(x) for x in parsed.get("deviations", [])],
            remediation=[str(x) for x in parsed.get("remediation", [])],
            next_checks=[str(x) for x in parsed.get("next_checks", [])],
            ran_ai=True,
            risk_score=float(parsed["risk_score"]) if parsed.get("risk_score") is not None else decision.risk_score,
            confidence=str(parsed["confidence"]).lower() if parsed.get("confidence") else decision.confidence,
            mitre_techniques=mitre,
        )
    except Exception as exc:
        return SnipenExplainResult(
            summary=f"AI remediation failed: {exc}",
            severity="medium",
            ran_ai=False,
        )


# ── Context-aware explain ────────────────────────────────────────────────────

def explain_event_with_context(
    connection: dict[str, Any],
    event_raw: dict[str, Any],
) -> SnipenExplainResult:
    """
    Context-aware explain: fetches ±15-min events from the same host,
    detects operational patterns, and enriches the AI prompt.

    FIM families → deterministic path + context pattern notes injected.
    AI families  → same pipeline as explain_event but with context block.
    """
    smart = _normalize_smart(event_raw)
    host_profile = get_profile_for_host(smart.host or "")
    profile_context = build_profile_context_block(host_profile)

    event_family = _determine_event_family(
        smart.event_id,
        list(getattr(smart, "groups", None) or []),
        getattr(smart, "decoder", None),
    )

    # Fetch context window (silently ignores errors, never blocks the response)
    ctx = get_event_context_window(connection, event_raw, window_minutes=15, max_events=10)
    before: list[SnipenEvent] = ctx["before"]
    after: list[SnipenEvent] = ctx["after"]
    context_summary = _build_context_summary(before, after)
    patterns = _detect_context_patterns(before, after, smart)

    # ── FIM: deterministic path + context pattern notes ───────────────────
    if event_family in _FIM_FAMILIES:
        decision = decide_event(
            event_id=smart.event_id,
            rule_level=smart.rule_level,
            rule_description=smart.rule_description,
            event_explanation=getattr(smart, "event_explanation", None),
            groups=list(getattr(smart, "groups", None) or []),
            event_family=event_family,
            profile_name=host_profile.name if host_profile else None,
            has_baseline_deviation=False,
            has_ti_match=bool(getattr(smart, "ti_matches", None)),
        )
        result = explain_fim_event(smart, decision)
        # Inject detected patterns
        if patterns:
            pattern_text = " ".join(patterns)
            result.against_it = ((result.against_it or "") + " " + pattern_text).strip()
            pattern_deviations = [f"Kontext-Muster: {p}" for p in patterns]
            result.deviations = (pattern_deviations + result.deviations)[:5]
        # Prepend context count to next_checks
        total_ctx = len(before) + len(after)
        if total_ctx > 0:
            ctx_note = (
                f"Zeitfenster: {total_ctx} weitere Events auf '{smart.host}' "
                f"(±15 min) – Timeline im Snipen-Tab prüfen"
            )
            result.next_checks = [ctx_note] + result.next_checks
        return result

    # ── Decision gate ─────────────────────────────────────────────────────
    decision = decide_event(
        event_id=smart.event_id,
        rule_level=smart.rule_level,
        rule_description=smart.rule_description,
        event_explanation=getattr(smart, "event_explanation", None),
        groups=list(getattr(smart, "groups", None) or []),
        event_family=event_family,
        profile_name=host_profile.name if host_profile else None,
        has_baseline_deviation=False,
        has_ti_match=bool(getattr(smart, "ti_matches", None)),
    )

    # No-AI path: static result + pattern notes
    if not decision.should_run_ai:
        static = build_static_explain_result(smart, decision)
        against = static.get("against_it") or ""
        if patterns:
            against = (against + " " + " ".join(patterns)).strip()
        return SnipenExplainResult(
            summary=static["summary"],
            why_suspicious=static["why_suspicious"],
            against_it=against or None,
            severity=static["severity"],
            risk_score=static["risk_score"],
            confidence=static["confidence"],
            mitre_techniques=[],
            remediation=static["remediation"],
            next_checks=static["next_checks"],
            unusual_behavior=static["unusual_behavior"],
            deviations=static["deviations"],
            suspicious_fields=static["suspicious_fields"],
            ran_ai=False,
        )

    # ── AI path: enrich prompt with context ──────────────────────────────
    decision_ctx = build_decision_context_block(decision)
    event_class_ctx = _get_event_class_context(event_family)
    guardrail_block = build_guardrail_block(smart.model_dump(exclude_none=True))

    _plat = (smart.platform or "other").lower()
    if _plat == "linux":
        platform_note = (
            "HOST PLATFORM: Linux/Unix – this is a Linux system.\n"
            "All artefacts are Linux-style. Do NOT reference Windows concepts.\n"
        )
    elif _plat == "windows":
        platform_note = (
            "HOST PLATFORM: Windows – this is a Windows system.\n"
            "Use Windows-specific context: Event IDs, Registry, NTLM, Active Directory.\n"
        )
    else:
        platform_note = f"HOST PLATFORM: {_plat or 'unknown'}\n"

    observable_fields: dict[str, str] = {}
    for attr, key in [
        ("system_message", "system_message"), ("command_line", "command_line"),
        ("process", "process"), ("registry_key", "registry_key"),
        ("service_name", "service_name"), ("user", "user"),
        ("ip_address", "ip_address"), ("location", "location"),
    ]:
        val = getattr(smart, attr, None)
        if val:
            observable_fields[key] = val
    observable_ctx = (
        "CRITICAL OBSERVABLE FIELDS – reference explicitly:\n"
        + "\n".join(f"  {k}: {v}" for k, v in observable_fields.items())
        if observable_fields else ""
    )

    patterns_block = (
        "DETECTED CONTEXT PATTERNS – incorporate into your analysis:\n"
        + "\n".join(f"  - {p}" for p in patterns) + "\n"
        if patterns else ""
    )

    prompt = (
        f"[SYSTEM CONTEXT]\n{platform_note}\n"
        "You are a senior SOC analyst. Explain this Wazuh security event IN CONTEXT of surrounding events "
        "on the same host. Return valid JSON only. Language: German. Be concrete and technical.\n"
        "Keys: summary (str, 5-8 full German sentences – incorporate the context events), "
        "why_suspicious (str, 3-6 sentences), "
        "against_it (str – benign explanations based on context, 2-4 sentences, or null), "
        "severity (critical/high/medium/low/info), "
        "suspicious_fields (list[str]), "
        "unusual_behavior (list[str] – only what is actually unusual given the context, min 3), "
        "deviations (list[str] – deviations from baseline considering context, min 3), "
        "risk_score (float 0-10), "
        "confidence (low/medium/high/very_high), "
        "mitre_techniques (list[str] or []), "
        "remediation (list[str], min 5), "
        "next_checks (list[str], min 5).\n\n"
        "CRITICAL REASONING RULE: Use the before/after context events to determine whether this event "
        "is part of a known operational pattern (update, service restart, config rotation, deployment). "
        "If a benign pattern is present, LOWER severity and confidence accordingly – do not alarm on "
        "operational noise just because it matches a rule.\n\n"
        f"{observable_ctx}\n\n"
        f"{patterns_block}"
        f"ZEITFENSTER-KONTEXT (±15 min, Host '{smart.host}'):\n{context_summary}\n\n"
        f"MANDATORY – Decision Engine Guardrails:\n{decision_ctx}\n\n"
        f"MANDATORY – Artifact-Type Guardrails:\n{guardrail_block}\n\n"
        f"Additional Event Class Context:\n{event_class_ctx}\n\n"
        f"Host Profile Context:\n{profile_context}\n\n"
        "Smart fields (pivot event):\n"
        f"{json.dumps(smart.model_dump(exclude_none=True), ensure_ascii=False)}\n\n"
        "Raw event excerpt:\n"
        f"{json.dumps({k: v for k, v in event_raw.items() if k in ('rule', 'data', 'agent', 'decoder', '@timestamp', 'location')}, ensure_ascii=False, default=str)}"
    )
    try:
        parsed = _call_ollama_json(connection, prompt, timeout=240.0)
        parsed = _ensure_explain_quality(parsed, smart, remediation_mode=False, family=event_family)
        parsed_sev = str(parsed.get("severity", decision.severity)).lower()
        _sev_order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        if _sev_order.get(parsed_sev, 2) > _sev_order.get(decision.severity, 4):
            parsed_sev = decision.severity
        mitre = [str(x) for x in parsed.get("mitre_techniques", [])] if decision.allow_mitre else []
        return SnipenExplainResult(
            summary=str(parsed.get("summary", "No explanation returned.")),
            why_suspicious=parsed.get("why_suspicious") or None,
            against_it=parsed.get("against_it") or None,
            severity=parsed_sev,
            suspicious_fields=[str(x) for x in parsed.get("suspicious_fields", [])],
            unusual_behavior=[str(x) for x in parsed.get("unusual_behavior", [])],
            deviations=[str(x) for x in parsed.get("deviations", [])],
            remediation=[str(x) for x in parsed.get("remediation", [])],
            next_checks=[str(x) for x in parsed.get("next_checks", [])],
            ran_ai=True,
            risk_score=float(parsed["risk_score"]) if parsed.get("risk_score") is not None else decision.risk_score,
            confidence=str(parsed["confidence"]).lower() if parsed.get("confidence") else decision.confidence,
            mitre_techniques=mitre,
        )
    except Exception as exc:
        return SnipenExplainResult(
            summary=f"Context-aware AI explanation failed: {exc}",
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

    host_profile = get_profile_for_host(host)
    profile_context = build_profile_context_block(host_profile)

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
        f"IMPORTANT – Host Profile Context:\n{profile_context}\n\n"
        f"These are recent Wazuh events from host '{host}' (last {hours}h, {len(events)} total):\n"
        f"{json.dumps(event_summaries, ensure_ascii=False)}\n\n"
        "Return valid JSON only with keys:\n"
        "answer (str – concise German answer to the question, 3-5 sentences, specific to the data),\n"
        "matched_indices (list[int] – indices of the most relevant events for the question, max 25).\n"
        "Be specific and reference actual event data in your answer."
    )

    try:
        parsed = _call_ollama_json(connection, prompt, timeout=240.0)
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

