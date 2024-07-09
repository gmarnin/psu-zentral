resource "zentral_munki_script_check" "mcs-auditing-audit_acls_files_configure" {
  name = "[mSCP] - Auditing - Configure Audit Log Files to Not Contain Access Control Lists"
  description = trimspace(<<EODESC
The audit log files _MUST_ not contain access control lists (ACLs).

This rule ensures that audit information and audit files are configured to be readable and writable only by system administrators, thereby preventing unauthorized access, modification, and deletion of files.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/bin/ls -le $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}') | /usr/bin/awk '{print $1}' | /usr/bin/grep -c ":"
EOSRC
  )
  expected_result = "0"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-auditing-audit_acls_folders_configure" {
  name = "[mSCP] - Auditing - Configure Audit Log Folder to Not Contain Access Control Lists"
  description = trimspace(<<EODESC
The audit log folder _MUST_ not contain access control lists (ACLs).

Audit logs contain sensitive data about the system and users. This rule ensures that the audit service is configured to create log folders that are readable and writable only by system administrators in order to prevent normal users from reading audit logs.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/bin/ls -lde /var/audit | /usr/bin/awk '{print $1}' | /usr/bin/grep -c ":"
EOSRC
  )
  expected_result = "0"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-auditing-audit_auditd_enabled" {
  name = "[mSCP] - Auditing - Enable Security Auditing"
  description = trimspace(<<EODESC
The information system _MUST_ be configured to generate audit records.

Audit records establish what types of events have occurred, when they occurred, and which users were involved. These records aid an organization in their efforts to establish, correlate, and investigate the events leading up to an outage or attack.

The content required to be captured in an audit record varies based on the impact level of an organization's system. Content that may be necessary to satisfy this requirement includes, for example, time stamps, source addresses, destination addresses, user identifiers, event descriptions, success/fail indications, filenames involved, and access or flow control rules invoked.

The information system initiates session audits at system start-up.

NOTE: Security auditing is NOT enabled by default on macOS Sonoma.
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
LAUNCHD_RUNNING=$(/bin/launchctl list | /usr/bin/grep -c com.apple.auditd)
AUDITD_RUNNING=$(/usr/sbin/audit -c | /usr/bin/grep -c "AUC_AUDITING")
if [[ $LAUNCHD_RUNNING == 1 ]] && [[ -e /etc/security/audit_control ]] && [[ $AUDITD_RUNNING == 1 ]]; then
  echo "pass"
else
  echo "fail"
fi
EOSRC
  )
  expected_result = "pass"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-auditing-audit_failure_halt" {
  name = "[mSCP] - Auditing - Configure System to Shut Down Upon Audit Failure"
  description = trimspace(<<EODESC
The audit service _MUST_ be configured to shut down the computer if it is unable to audit system events.

Once audit failure occurs, user and system activity are no longer recorded, and malicious activity could go undetected. Audit processing failures can occur due to software/hardware errors, failures in the audit capturing mechanisms, and audit storage capacity being reached or exceeded.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/usr/bin/awk -F':' '/^policy/ {print $NF}' /etc/security/audit_control | /usr/bin/tr ',' '\n' | /usr/bin/grep -Ec 'ahlt'
EOSRC
  )
  expected_result = "1"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-auditing-audit_files_group_configure" {
  name = "[mSCP] - Auditing - Configure Audit Log Files Group to Wheel"
  description = trimspace(<<EODESC
Audit log files _MUST_ have the group set to wheel.

The audit service _MUST_ be configured to create log files with the correct group ownership to prevent normal users from reading audit logs.

Audit logs contain sensitive data about the system and users. If log files are set to be readable and writable only by system administrators, the risk is mitigated.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/bin/ls -n $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}') | /usr/bin/awk '{s+=$4} END {print s}'
EOSRC
  )
  expected_result = "0"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-auditing-audit_files_mode_configure" {
  name = "[mSCP] - Auditing - Configure Audit Log Files to Mode 440 or Less Permissive"
  description = trimspace(<<EODESC
The audit service _MUST_ be configured to create log files that are readable only by the root user and group wheel. To achieve this, audit log files _MUST_ be configured to mode 440 or less permissive; thereby preventing normal users from reading, modifying or deleting audit logs.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/bin/ls -l $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}') | /usr/bin/awk '!/-r--r-----|current|total/{print $1}' | /usr/bin/wc -l | /usr/bin/tr -d ' '
EOSRC
  )
  expected_result = "0"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-auditing-audit_files_owner_configure" {
  name = "[mSCP] - Auditing - Configure Audit Log Files to be Owned by Root"
  description = trimspace(<<EODESC
Audit log files _MUST_ be owned by root.

The audit service _MUST_ be configured to create log files with the correct ownership to prevent normal users from reading audit logs.

Audit logs contain sensitive data about the system and users. If log files are set to only be readable and writable by system administrators, the risk is mitigated.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/bin/ls -n $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}') | /usr/bin/awk '{s+=$3} END {print s}'
EOSRC
  )
  expected_result = "0"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-auditing-audit_flags_aa_configure" {
  name = "[mSCP] - Auditing - Configure System to Audit All Authorization and Authentication Events"
  description = trimspace(<<EODESC
The auditing system _MUST_ be configured to flag authorization and authentication (aa) events.

Authentication events contain information about the identity of a user, server, or client. Authorization events contain information about permissions, rights, and rules. If audit records do not include aa events, it is difficult to identify incidents and to correlate incidents to subsequent events.

Audit records can be generated from various components within the information system (e.g., via a module or policy filter).
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/usr/bin/awk -F':' '/^flags/ { print $NF }' /etc/security/audit_control | /usr/bin/tr ',' '\n' | /usr/bin/grep -Ec 'aa'
EOSRC
  )
  expected_result = "1"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-auditing-audit_flags_ad_configure" {
  name = "[mSCP] - Auditing - Configure System to Audit All Administrative Action Events"
  description = trimspace(<<EODESC
The auditing system _MUST_ be configured to flag administrative action (ad) events.

Administrative action events include changes made to the system (e.g. modifying authentication policies). If audit records do not include ad events, it is difficult to identify incidents and to correlate incidents to subsequent events.

Audit records can be generated from various components within the information system (e.g., via a module or policy filter).

The information system audits the execution of privileged functions.

NOTE: We recommend changing the line "43127:AUE_MAC_SYSCALL:mac_syscall(2):ad" to "43127:AUE_MAC_SYSCALL:mac_syscall(2):zz" in the file /etc/security/audit_event. This will prevent sandbox violations from being audited by the ad flag.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/usr/bin/awk -F':' '/^flags/ { print $NF }' /etc/security/audit_control | /usr/bin/tr ',' '\n' | /usr/bin/grep -Ec 'ad'
EOSRC
  )
  expected_result = "1"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-auditing-audit_flags_ex_configure" {
  name = "[mSCP] - Auditing - Configure System to Audit All Failed Program Execution on the System"
  description = trimspace(<<EODESC
The audit system _MUST_ be configured to record enforcement actions of access restrictions, including failed program execute (-ex) attempts.

Enforcement actions are the methods or mechanisms used to prevent unauthorized access and/or changes to configuration settings. One common and effective enforcement action method is using program execution restrictions (e.g., denying users access to execute certain processes).

This configuration ensures that audit lists include events in which program execution has failed.
Without auditing the enforcement of program execution, it is difficult to identify attempted attacks, as there is no audit trail available for forensic investigation.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/usr/bin/awk -F':' '/^flags/ { print $NF }' /etc/security/audit_control | /usr/bin/tr ',' '\n' | /usr/bin/grep -Ec '\-ex'
EOSRC
  )
  expected_result = "1"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-auditing-audit_flags_fd_configure" {
  name = "[mSCP] - Auditing - Configure System to Audit All Deletions of Object Attributes"
  description = trimspace(<<EODESC
The audit system _MUST_ be configured to record enforcement actions of attempts to delete file attributes (fd).

***Enforcement actions are the methods or mechanisms used to prevent unauthorized changes to configuration settings. One common and effective enforcement action method is using access restrictions (i.e., denying modifications to a file by applying file permissions).

This configuration ensures that audit lists include events in which enforcement actions prevent attempts to delete a file.

Without auditing the enforcement of access restrictions, it is difficult to identify attempted attacks, as there is no audit trail available for forensic investigation.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/usr/bin/awk -F':' '/^flags/ { print $NF }' /etc/security/audit_control | /usr/bin/tr ',' '\n' | /usr/bin/grep -Ec '\-fd'
EOSRC
  )
  expected_result = "1"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-auditing-audit_flags_fm_failed_configure" {
  name = "[mSCP] - Auditing - Configure System to Audit All Failed Change of Object Attributes"
  description = trimspace(<<EODESC
The audit system _MUST_ be configured to record enforcement actions of failed attempts to modify file attributes (-fm).

Enforcement actions are the methods or mechanisms used to prevent unauthorized changes to configuration settings. One common and effective enforcement action method is using access restrictions (i.e., denying modifications to a file by applying file permissions).

This configuration ensures that audit lists include events in which enforcement actions prevent attempts to modify a file.

Without auditing the enforcement of access restrictions, it is difficult to identify attempted attacks, as there is no audit trail available for forensic investigation.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/usr/bin/awk -F':' '/^flags/ { print $NF }' /etc/security/audit_control | /usr/bin/tr ',' '\n' | /usr/bin/grep -Ec '\-fm'
EOSRC
  )
  expected_result = "1"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-auditing-audit_flags_fr_configure" {
  name = "[mSCP] - Auditing - Configure System to Audit All Failed Read Actions on the System"
  description = trimspace(<<EODESC
The audit system _MUST_ be configured to record enforcement actions of access restrictions, including failed file read (-fr) attempts.

Enforcement actions are the methods or mechanisms used to prevent unauthorized access and/or changes to configuration settings. One common and effective enforcement action method is using access restrictions (e.g., denying access to a file by applying file permissions).

This configuration ensures that audit lists include events in which enforcement actions prevent attempts to read a file.

Without auditing the enforcement of access restrictions, it is difficult to identify attempted attacks, as there is no audit trail available for forensic investigation.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/usr/bin/awk -F':' '/^flags/ { print $NF }' /etc/security/audit_control | /usr/bin/tr ',' '\n' | /usr/bin/grep -Ec '\-fr'
EOSRC
  )
  expected_result = "1"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-auditing-audit_flags_fw_configure" {
  name = "[mSCP] - Auditing - Configure System to Audit All Failed Write Actions on the System"
  description = trimspace(<<EODESC
The audit system _MUST_ be configured to record enforcement actions of access restrictions, including failed file write (-fw) attempts.

Enforcement actions are the methods or mechanisms used to prevent unauthorized access and/or changes to configuration settings. One common and effective enforcement action method is using access restrictions (e.g., denying users access to edit a file by applying file permissions).

This configuration ensures that audit lists include events in which enforcement actions prevent attempts to change a file.

Without auditing the enforcement of access restrictions, it is difficult to identify attempted attacks, as there is no audit trail available for forensic investigation.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/usr/bin/awk -F':' '/^flags/ { print $NF }' /etc/security/audit_control | /usr/bin/tr ',' '\n' | /usr/bin/grep -Ec '\-fw'
EOSRC
  )
  expected_result = "1"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-auditing-audit_flags_lo_configure" {
  name = "[mSCP] - Auditing - Configure System to Audit All Log In and Log Out Events"
  description = trimspace(<<EODESC
The audit system _MUST_ be configured to record all attempts to log in and out of the system (lo).

Frequently, an attacker that successfully gains access to a system has only gained access to an account with limited privileges, such as a guest account or a service account. The attacker must attempt to change to another user account with normal or elevated privileges in order to proceed. Auditing both successful and unsuccessful attempts to switch to another user account (by way of monitoring login and logout events) mitigates this risk.

The information system monitors login and logout events.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/usr/bin/awk -F':' '/^flags/ { print $NF }' /etc/security/audit_control | /usr/bin/tr ',' '\n' | /usr/bin/grep -Ec '^lo'
EOSRC
  )
  expected_result = "1"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-auditing-audit_folder_group_configure" {
  name = "[mSCP] - Auditing - Configure Audit Log Folders Group to Wheel"
  description = trimspace(<<EODESC
Audit log files _MUST_ have the group set to wheel.

The audit service _MUST_ be configured to create log files with the correct group ownership to prevent normal users from reading audit logs.

Audit logs contain sensitive data about the system and users. If log files are set to be readable and writable only by system administrators, the risk is mitigated.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/bin/ls -dn $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}') | /usr/bin/awk '{print $4}'
EOSRC
  )
  expected_result = "0"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-auditing-audit_folder_owner_configure" {
  name = "[mSCP] - Auditing - Configure Audit Log Folders to be Owned by Root"
  description = trimspace(<<EODESC
Audit log folders _MUST_ be owned by root.

The audit service _MUST_ be configured to create log folders with the correct ownership to prevent normal users from reading audit logs.

Audit logs contain sensitive data about the system and users. If log folders are set to only be readable and writable by system administrators, the risk is mitigated.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/bin/ls -dn $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}') | /usr/bin/awk '{print $3}'
EOSRC
  )
  expected_result = "0"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-auditing-audit_folders_mode_configure" {
  name = "[mSCP] - Auditing - Configure Audit Log Folders to Mode 700 or Less Permissive"
  description = trimspace(<<EODESC
The audit log folder _MUST_ be configured to mode 700 or less permissive so that only the root user is able to read, write, and execute changes to folders.

Because audit logs contain sensitive data about the system and users, the audit service _MUST_ be configured to mode 700 or less permissive; thereby preventing normal users from reading, modifying or deleting audit logs.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/usr/bin/stat -f %A $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}')
EOSRC
  )
  expected_result = "700"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-auditing-audit_retention_configure" {
  name = "[mSCP] - Auditing - Configure Audit Retention to 14d"
  description = trimspace(<<EODESC
The audit service _MUST_ be configured to require records be kept for a organizational defined value before deletion, unless the system uses a central audit record storage facility.

When "expire-after" is set to "14d", the audit service will not delete audit logs until the log data criteria is met.
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
/usr/bin/awk -F: '/expire-after/{print $2}' /etc/security/audit_control
EOSRC
  )
  expected_result = "14d"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-auditing-audit_settings_failure_notify" {
  name = "[mSCP] - Auditing - Configure Audit Failure Notification"
  description = trimspace(<<EODESC
The audit service _MUST_ be configured to immediately print messages to the console or email administrator users when an auditing failure occurs.

It is critical for the appropriate personnel to be made aware immediately if a system is at risk of failing to process audit logs as required. Without a real-time alert, security personnel may be unaware of a potentially harmful failure in the auditing system's capability, and system operation may be adversely affected.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/usr/bin/grep -c "logger -s -p" /etc/security/audit_warn
EOSRC
  )
  expected_result = "1"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-authentication-auth_pam_login_smartcard_enforce" {
  name = "[mSCP] - Authentication - Enforce Multifactor Authentication for Login"
  description = trimspace(<<EODESC
The system _MUST_ be configured to enforce multifactor authentication.

All users _MUST_ go through multifactor authentication to prevent unauthenticated access and potential compromise to the system.

IMPORTANT: Modification of Pluggable Authentication Modules (PAM) now require user authorization, or use of a Privacy Preferences Policy Control (PPPC) profile from MDM that authorizes modifying system administrator files or full disk access.

NOTE: /etc/pam.d/login will be automatically modified to its original state following any update or major upgrade to the operating system.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/usr/bin/grep -Ec '^(auth\s+sufficient\s+pam_smartcard.so|auth\s+required\s+pam_deny.so)' /etc/pam.d/login
EOSRC
  )
  expected_result = "2"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-authentication-auth_pam_su_smartcard_enforce" {
  name = "[mSCP] - Authentication - Enforce Multifactor Authentication for the su Command"
  description = trimspace(<<EODESC
The system _MUST_ be configured such that, when the su command is used, multifactor authentication is enforced.

All users _MUST_ go through multifactor authentication to prevent unauthenticated access and potential compromise to the system.

IMPORTANT: Modification of Pluggable Authentication Modules (PAM) now require user authorization, or use of a Privacy Preferences Policy Control (PPPC) profile from MDM that authorizes modifying system administrator files or full disk access.

NOTE: /etc/pam.d/su will be automatically modified to its original state following any update or major upgrade to the operating system.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/usr/bin/grep -Ec '^(auth\s+sufficient\s+pam_smartcard.so|auth\s+required\s+pam_rootok.so)' /etc/pam.d/su
EOSRC
  )
  expected_result = "2"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-authentication-auth_pam_sudo_smartcard_enforce" {
  name = "[mSCP] - Authentication - Enforce Multifactor Authentication for Privilege Escalation Through the sudo Command"
  description = trimspace(<<EODESC
The system _MUST_ be configured to enforce multifactor authentication when the sudo command is used to elevate privilege.

All users _MUST_ go through multifactor authentication to prevent unauthenticated access and potential compromise to the system.

IMPORTANT: Modification of Pluggable Authentication Modules (PAM) now require user authorization, or use of a Privacy Preferences Policy Control (PPPC) profile from MDM that authorizes modifying system administrator files or full disk access.

NOTE: /etc/pam.d/sudo will be automatically modified to its original state following any update or major upgrade to the operating system.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/usr/bin/grep -Ec '^(auth\s+sufficient\s+pam_smartcard.so|auth\s+required\s+pam_deny.so)' /etc/pam.d/sudo
EOSRC
  )
  expected_result = "2"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-authentication-auth_smartcard_allow" {
  name = "[mSCP] - Authentication - Allow Smartcard Authentication"
  description = trimspace(<<EODESC
Smartcard authentication _MUST_ be allowed.

The use of smartcard credentials facilitates standardization and reduces the risk of unauthorized access.

When enabled, the smartcard can be used for login, authorization, and screen saver unlocking.
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.security.smartcard')\
.objectForKey('allowSmartCard').js
EOS
EOSRC
  )
  expected_result = "true"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-authentication-auth_smartcard_certificate_trust_enforce_moderate" {
  name = "[mSCP] - Authentication - Set Smartcard Certificate Trust to Moderate"
  description = trimspace(<<EODESC
The macOS system _MUST_ be configured to block access to users who are no longer authorized (i.e., users with revoked certificates).

To prevent the use of untrusted certificates, the certificates on a smartcard card _MUST_ meet the following criteria: its issuer has a system-trusted certificate, the certificate is not expired, its "valid-after" date is in the past, and it passes Certificate Revocation List (CRL) and Online Certificate Status Protocol (OCSP) checking.

By setting the smartcard certificate trust level to moderate, the system will execute a soft revocation, i.e., if the OCSP/CRL server is unreachable, authentication will still succeed.

NOTE: Before applying this setting, please see the smartcard supplemental guidance.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.security.smartcard')\
.objectForKey('checkCertificateTrust').js
EOS
EOSRC
  )
  expected_result = "2"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-authentication-auth_smartcard_enforce" {
  name = "[mSCP] - Authentication - Enforce Smartcard Authentication"
  description = trimspace(<<EODESC
Smartcard authentication _MUST_ be enforced.

The use of smartcard credentials facilitates standardization and reduces the risk of unauthorized access.

When enforceSmartCard is set to "true", the smartcard must be used for login, authorization, and unlocking the screensaver.

CAUTION: enforceSmartCard will apply to the whole system. No users will be able to login with their password unless the profile is removed or a user is exempt from smartcard enforcement.

NOTE: enforceSmartcard requires allowSmartcard to be set to true in order to work.
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.security.smartcard')\
.objectForKey('enforceSmartCard').js
EOS
EOSRC
  )
  expected_result = "true"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-authentication-auth_ssh_password_authentication_disable" {
  name = "[mSCP] - Authentication - Disable Password Authentication for SSH"
  description = trimspace(<<EODESC
If remote login through SSH is enabled, password based authentication _MUST_ be disabled for user login.

All users _MUST_ go through multifactor authentication to prevent unauthenticated access and potential compromise to the system.

NOTE: /etc/ssh/sshd_config will be automatically modified to its original state following any update or major upgrade to the operating system.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/usr/sbin/sshd -G | /usr/bin/grep -Ec '^(passwordauthentication\s+no|kbdinteractiveauthentication\s+no)'
EOSRC
  )
  expected_result = "2"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-icloud-icloud_addressbook_disable" {
  name = "[mSCP] - iCloud - Disable iCloud Address Book"
  description = trimspace(<<EODESC
The macOS built-in Contacts.app connection to Apple's iCloud service _MUST_ be disabled.

Apple's iCloud service does not provide an organization with enough control over the storage and access of data, and, therefore, automated contact synchronization _MUST_ be controlled by an organization approved service.
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowCloudAddressBook').js
EOS
EOSRC
  )
  expected_result = "false"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-icloud-icloud_appleid_system_settings_disable" {
  name = "[mSCP] - iCloud - Disable the System Setting for Apple ID"
  description = trimspace(<<EODESC
The system setting for Apple ID _MUST_ be disabled.

Disabling the system setting prevents login to Apple ID and iCloud.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/usr/bin/profiles show -output stdout-xml | /usr/bin/xmllint --xpath '//key[text()="DisabledSystemSettings"]/following-sibling::*[1]' - | /usr/bin/grep -c "com.apple.systempreferences.AppleIDSettings"
EOSRC
  )
  expected_result = "1"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-icloud-icloud_bookmarks_disable" {
  name = "[mSCP] - iCloud - Disable iCloud Bookmarks"
  description = trimspace(<<EODESC
The macOS built-in Safari.app bookmark synchronization via the iCloud service _MUST_ be disabled.

Apple's iCloud service does not provide an organization with enough control over the storage and access of data and, therefore, automated bookmark synchronization _MUST_ be controlled by an organization approved service.
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowCloudBookmarks').js
EOS
EOSRC
  )
  expected_result = "false"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-icloud-icloud_calendar_disable" {
  name = "[mSCP] - iCloud - Disable the iCloud Calendar Services"
  description = trimspace(<<EODESC
The macOS built-in Calendar.app connection to Apple's iCloud service _MUST_ be disabled.

Apple's iCloud service does not provide an organization with enough control over the storage and access of data and, therefore, automated calendar synchronization _MUST_ be controlled by an organization approved service.
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowCloudCalendar').js
EOS
EOSRC
  )
  expected_result = "false"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-icloud-icloud_drive_disable" {
  name = "[mSCP] - iCloud - Disable iCloud Document Sync"
  description = trimspace(<<EODESC
The macOS built-in iCloud document synchronization service _MUST_ be disabled to prevent organizational data from being synchronized to personal or non-approved storage.

Apple's iCloud service does not provide an organization with enough control over the storage and access of data and, therefore, automated document synchronization _MUST_ be controlled by an organization approved service.
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowCloudDocumentSync').js
EOS
EOSRC
  )
  expected_result = "false"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-icloud-icloud_freeform_disable" {
  name = "[mSCP] - iCloud - Disable the iCloud Freeform Services"
  description = trimspace(<<EODESC
The macOS built-in Freeform.app connection to Apple's iCloud service _MUST_ be disabled.

Apple's iCloud service does not provide an organization with enough control over the storage and access of data and, therefore, automated calendar synchronization _MUST_ be controlled by an organization approved service.
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowCloudFreeform').js
EOS
EOSRC
  )
  expected_result = "false"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-icloud-icloud_game_center_disable" {
  name = "[mSCP] - iCloud - Disable iCloud Game Center"
  description = trimspace(<<EODESC
This works only with supervised devices (MDM) and allows to disable Apple Game Center. The rationale is Game Center is using Apple ID and will shared data on AppleID based services, therefore, Game Center _MUST_ be disabled.
This setting also prohibits functionality of adding friends to Game Center.
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowGameCenter').js
EOS
EOSRC
  )
  expected_result = "false"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-icloud-icloud_keychain_disable" {
  name = "[mSCP] - iCloud - Disable iCloud Keychain Sync"
  description = trimspace(<<EODESC
The macOS system's ability to automatically synchronize a user's passwords to their iCloud account _MUST_ be disabled.

Apple's iCloud service does not provide an organization with enough control over the storage and access of data and, therefore, password management and synchronization _MUST_ be controlled by an organization approved service.
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowCloudKeychainSync').js
EOS
EOSRC
  )
  expected_result = "false"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-icloud-icloud_mail_disable" {
  name = "[mSCP] - iCloud - Disable iCloud Mail"
  description = trimspace(<<EODESC
The macOS built-in Mail.app connection to Apple's iCloud service _MUST_ be disabled.

Apple's iCloud service does not provide an organization with enough control over the storage and access of data and, therefore, automated mail synchronization _MUST_ be controlled by an organization approved service.
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowCloudMail').js
EOS
EOSRC
  )
  expected_result = "false"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-icloud-icloud_notes_disable" {
  name = "[mSCP] - iCloud - Disable iCloud Notes"
  description = trimspace(<<EODESC
The macOS built-in Notes.app connection to Apple's iCloud service _MUST_ be disabled.

Apple's iCloud service does not provide an organization with enough control over the storage and access of data and, therefore, automated Notes synchronization _MUST_ be controlled by an organization approved service.
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowCloudNotes').js
EOS
EOSRC
  )
  expected_result = "false"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-icloud-icloud_photos_disable" {
  name = "[mSCP] - iCloud - Disable iCloud Photo Library"
  description = trimspace(<<EODESC
The macOS built-in Photos.app connection to Apple's iCloud service _MUST_ be disabled.

Apple's iCloud service does not provide an organization with enough control over the storage and access of data and, therefore, automated photo synchronization _MUST_ be controlled by an organization approved service.
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowCloudPhotoLibrary').js
EOS
EOSRC
  )
  expected_result = "false"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-icloud-icloud_private_relay_disable" {
  name = "[mSCP] - iCloud - Disable iCloud Private Relay"
  description = trimspace(<<EODESC
Enterprise networks may be required to audit all network traffic by policy, therefore, iCloud Private Relay _MUST_ be disabled.

Network administrators can also prevent the use of this feature by blocking DNS resolution of mask.icloud.com and mask-h2.icloud.com.
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowCloudPrivateRelay').js
EOS
EOSRC
  )
  expected_result = "false"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-icloud-icloud_reminders_disable" {
  name = "[mSCP] - iCloud - Disable iCloud Reminders"
  description = trimspace(<<EODESC
The macOS built-in Reminders.app connection to Apple's iCloud service _MUST_ be disabled.

Apple's iCloud service does not provide an organization with enough control over the storage and access of data and, therefore, automated reminders synchronization _MUST_ be controlled by an organization approved service.
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowCloudReminders').js
EOS
EOSRC
  )
  expected_result = "false"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-icloud-icloud_sync_disable" {
  name = "[mSCP] - iCloud - Disable iCloud Desktop and Document Folder Sync"
  description = trimspace(<<EODESC
The macOS system's ability to automatically synchronize a user's desktop and documents folder to their iCloud Drive _MUST_ be disabled.

Apple's iCloud service does not provide an organization with enough control over the storage and access of data and, therefore, automated file synchronization _MUST_ be controlled by an organization approved service.
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowCloudDesktopAndDocuments').js
EOS
EOSRC
  )
  expected_result = "false"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-macos-os_account_modification_disable" {
  name = "[mSCP] - macOS - Disable AppleID and Internet Account Modifications"
  description = trimspace(<<EODESC
The system _MUST_ disable account modification. 

Account modification includes adding additional or modifying internet accounts in Apple Mail, Calendar, Contacts, in the Internet Account System Setting Pane, or the AppleID System Setting Pane.

This prevents the addition of unauthorized accounts.

[IMPORTANT]
====
Some organizations may allow the use and configuration of the built-in Mail.app, Calendar.app, and Contacts.app for organizational communication. Information System Security Officers (ISSOs) may make the risk-based decision not to disable the Internet Accounts System Preference pane to avoid losing this functionality, but they are advised to first fully weigh the potential risks posed to their organization.
====
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowAccountModification').js
EOS
EOSRC
  )
  expected_result = "false"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-macos-os_airdrop_disable" {
  name = "[mSCP] - macOS - Disable AirDrop"
  description = trimspace(<<EODESC
AirDrop _MUST_ be disabled to prevent file transfers to or from unauthorized devices.
AirDrop allows users to share and receive files from other nearby Apple devices.
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowAirDrop').js
EOS
EOSRC
  )
  expected_result = "false"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-macos-os_appleid_prompt_disable" {
  name = "[mSCP] - macOS - Disable Apple ID Setup during Setup Assistant"
  description = trimspace(<<EODESC
The prompt for Apple ID setup during Setup Assistant _MUST_ be disabled.

macOS will automatically prompt new users to set up an Apple ID while they are going through Setup Assistant if this is not disabled, misleading new users to think they need to create Apple ID accounts upon their first login.
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.SetupAssistant.managed')\
.objectForKey('SkipCloudSetup').js
EOS
EOSRC
  )
  expected_result = "true"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-macos-os_asl_log_files_owner_group_configure" {
  name = "[mSCP] - macOS - Configure Apple System Log Files Owned by Root and Group to Wheel"
  description = trimspace(<<EODESC
The Apple System Logs (ASL) _MUST_ be owned by root.

ASL logs contain sensitive data about the system and users. If ASL log files are set to only be readable and writable by system administrators, the risk is mitigated.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/usr/bin/stat -f '%Su:%Sg:%N' $(/usr/bin/grep -e '^>' /etc/asl.conf /etc/asl/* | /usr/bin/awk '{ print $2 }') 2> /dev/null | /usr/bin/awk '!/^root:wheel:/{print $1}' | /usr/bin/wc -l | /usr/bin/tr -d ' '
EOSRC
  )
  expected_result = "0"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-macos-os_asl_log_files_permissions_configure" {
  name = "[mSCP] - macOS - Configure Apple System Log Files To Mode 640 or Less Permissive"
  description = trimspace(<<EODESC
The Apple System Logs (ASL) _MUST_ be configured to be writable by root and readable only by the root user and group wheel. To achieve this, ASL log files _MUST_ be configured to mode 640 permissive or less; thereby preventing normal users from reading, modifying or deleting audit logs. System logs frequently contain sensitive information that could be used by an attacker. Setting the correct permissions mitigates this risk.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/usr/bin/stat -f '%A:%N' $(/usr/bin/grep -e '^>' /etc/asl.conf /etc/asl/* | /usr/bin/awk '{ print $2 }') 2> /dev/null | /usr/bin/awk '!/640/{print $1}' | /usr/bin/wc -l | /usr/bin/tr -d ' '
EOSRC
  )
  expected_result = "0"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-macos-os_authenticated_root_enable" {
  name = "[mSCP] - macOS - Enable Authenticated Root"
  description = trimspace(<<EODESC
Authenticated Root _MUST_ be enabled.

When Authenticated Root is enabled the macOS is booted from a signed volume that is cryptographically protected to prevent tampering with the system volume.

NOTE: Authenticated Root is enabled by default on macOS systems.

WARNING: If more than one partition with macOS is detected, the csrutil command will hang awaiting input.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/usr/bin/csrutil authenticated-root | /usr/bin/grep -c 'enabled'
EOSRC
  )
  expected_result = "1"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-macos-os_bonjour_disable" {
  name = "[mSCP] - macOS - Disable Bonjour Multicast"
  description = trimspace(<<EODESC
Bonjour multicast advertising _MUST_ be disabled to prevent the system from broadcasting its presence and available services over network interfaces.
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.mDNSResponder')\
.objectForKey('NoMulticastAdvertisements').js
EOS
EOSRC
  )
  expected_result = "true"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-macos-os_certificate_authority_trust" {
  name = "[mSCP] - macOS - Issue or Obtain Public Key Certificates from an Approved Service Provider"
  description = trimspace(<<EODESC
The organization _MUST_ issue or obtain public key certificates from an organization-approved service provider and ensure only approved trust anchors are in the System Keychain.
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
/usr/bin/security dump-keychain /Library/Keychains/System.keychain | /usr/bin/awk -F'"' '/labl/ {print $4}'
EOSRC
  )
  expected_result = "a list containing approved root certificates"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-macos-os_config_data_install_enforce" {
  name = "[mSCP] - macOS - Enforce Installation of XProtect Remediator and Gatekeeper Updates Automatically"
  description = trimspace(<<EODESC
Software Update _MUST_ be configured to update XProtect Remediator and Gatekeeper automatically.

This setting enforces definition updates for XProtect Remediator and Gatekeeper; with this setting in place, new malware and adware that Apple has added to the list of malware or untrusted software will not execute. These updates do not require the computer to be restarted.

link:https://support.apple.com/en-us/HT207005[]

NOTE: Software update will automatically update XProtect Remediator and Gatekeeper by default in the macOS.
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.SoftwareUpdate')\
.objectForKey('ConfigDataInstall').js
EOS
EOSRC
  )
  expected_result = "true"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-macos-os_config_profile_ui_install_disable" {
  name = "[mSCP] - macOS - Disable Installation of Configuration Profiles through the User Interface"
  description = trimspace(<<EODESC
Installation of configuration profiles through the user interface _MUST_ be disabled and only be permitted through an authorized MDM server.
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowUIConfigurationProfileInstallation').js
EOS
EOSRC
  )
  expected_result = "false"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-macos-os_dictation_disable" {
  name = "[mSCP] - macOS - Disable Dictation"
  description = trimspace(<<EODESC
Dictation _MUST_ be disabled on Intel based Macs as the feature On Device Dictation is only available on Apple Silicon devices.
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowDictation').js
EOS
EOSRC
  )
  expected_result = "false"
  arch_amd64      = true
  arch_arm64      = false
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-macos-os_filevault_autologin_disable" {
  name = "[mSCP] - macOS - Disable FileVault Automatic Login"
  description = trimspace(<<EODESC
If FileVault is enabled, automatic login _MUST_ be disabled, so that both FileVault and login window authentication are required.

The default behavior of macOS when FileVault is enabled is to automatically log in to the computer once successfully passing your FileVault credentials.

NOTE: DisableFDEAutoLogin does not have to be set on Apple Silicon based macOS systems that are smartcard enforced as smartcards are available at pre-boot.
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.loginwindow')\
.objectForKey('DisableFDEAutoLogin').js
EOS
EOSRC
  )
  expected_result = "true"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-macos-os_firewall_default_deny_require" {
  name = "[mSCP] - macOS - Control Connections to Other Systems via a Deny-All and Allow-by-Exception Firewall Policy"
  description = trimspace(<<EODESC
A deny-all and allow-by-exception firewall policy _MUST_ be employed for managing connections to other systems.

Organizations _MUST_ ensure the built-in packet filter firewall is configured correctly to employ the default deny rule.

Failure to restrict network connectivity to authorized systems permits inbound connections from malicious systems. It also permits outbound connections that may facilitate the exfiltration of data.

If you are using a third-party firewall solution, this setting does not apply.

[IMPORTANT]
====
Configuring the built-in packet filter firewall to employ the default deny rule has the potential to interfere with applications on the system in an unpredictable manner. Information System Security Officers (ISSOs) may make the risk-based decision not to configure the built-in packet filter firewall to employ the default deny rule to avoid losing functionality, but they are advised to first fully weigh the potential risks posed to their organization.
====
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/sbin/pfctl -a '*' -sr &> /dev/null | /usr/bin/grep -c "block drop in all"
EOSRC
  )
  expected_result = "1"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-macos-os_firewall_log_enable" {
  name = "[mSCP] - macOS - Enable Firewall Logging"
  description = trimspace(<<EODESC
Firewall logging _MUST_ be enabled.

Firewall logging ensures that malicious network activity will be logged to the system.

NOTE: The firewall data is logged to Apple's Unified Logging with the subsystem `com.apple.alf` and the data is marked as private. In order to enable private data, review the `com.apple.alf.private_data.mobileconfig` file in the project's `includes` folder.
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
/usr/bin/osascript -l JavaScript << EOS
function run() {
  let pref1 = $.NSUserDefaults.alloc.initWithSuiteName('com.apple.security.firewall')\
  .objectForKey('EnableLogging').js
  let pref2 = $.NSUserDefaults.alloc.initWithSuiteName('com.apple.security.firewall')\
  .objectForKey('LoggingOption').js
  if ( pref1 == true && pref2 == "detail" ){
    return("true")
  } else {
    return("false")
  }
}
EOS
EOSRC
  )
  expected_result = "true"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-macos-os_firmware_password_require" {
  name = "[mSCP] - macOS - Enable Firmware Password"
  description = trimspace(<<EODESC
A firmware password _MUST_ be enabled and set.

Single user mode, recovery mode, the Startup Manager, and several other tools are available on macOS by holding the "Option" key down during startup. Setting a firmware password restricts access to these tools.

To set a firmware passcode use the following command:

[source,bash]
----
/usr/sbin/firmwarepasswd -setpasswd
----

NOTE: If firmware password or passcode is forgotten, the only way to reset the forgotten password is through the use of a machine specific binary generated and provided by Apple. Schedule a support call, and provide proof of purchase before the firmware binary will be generated.

NOTE: Firmware passwords are not supported on Apple Silicon devices. This rule is only applicable to Intel devices.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/usr/sbin/firmwarepasswd -check | /usr/bin/grep -c "Password Enabled: Yes"
EOSRC
  )
  expected_result = "1"
  arch_amd64      = true
  arch_arm64      = false
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-macos-os_gatekeeper_enable" {
  name = "[mSCP] - macOS - Enable Gatekeeper"
  description = trimspace(<<EODESC
Gatekeeper _MUST_ be enabled.

Gatekeeper is a security feature that ensures that applications are digitally signed by an Apple-issued certificate before they are permitted to run. Digital signatures allow the macOS host to verify that the application has not been modified by a malicious third party.

Administrator users will still have the option to override these settings on a case-by-case basis.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/usr/sbin/spctl --status | /usr/bin/grep -c "assessments enabled"
EOSRC
  )
  expected_result = "1"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-macos-os_gatekeeper_rearm" {
  name = "[mSCP] - macOS - Enforce Gatekeeper 30 Day Automatic Rearm"
  description = trimspace(<<EODESC
Gatekeeper _MUST_ be configured to automatically rearm after 30 days if disabled.
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.security')\
.objectForKey('GKAutoRearm').js
EOS
EOSRC
  )
  expected_result = "true"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-macos-os_handoff_disable" {
  name = "[mSCP] - macOS - Disable Handoff"
  description = trimspace(<<EODESC
Handoff _MUST_ be disabled.

Handoff allows you to continue working on a document or project when the user switches from one Apple device to another. Disabling Handoff prevents data transfers to unauthorized devices.
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowActivityContinuation').js
EOS
EOSRC
  )
  expected_result = "false"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-macos-os_home_folders_secure" {
  name = "[mSCP] - macOS - Secure User's Home Folders"
  description = trimspace(<<EODESC
The system _MUST_ be configured to prevent access to other user's home folders.

The default behavior of macOS is to allow all valid users access to the top level of every other user's home folder while restricting access only to the Apple default folders within.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/usr/bin/find /System/Volumes/Data/Users -mindepth 1 -maxdepth 1 -type d ! \( -perm 700 -o -perm 711 \) | /usr/bin/grep -v "Shared" | /usr/bin/grep -v "Guest" | /usr/bin/wc -l | /usr/bin/xargs
EOSRC
  )
  expected_result = "0"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-macos-os_httpd_disable" {
  name = "[mSCP] - macOS - Disable the Built-in Web Server"
  description = trimspace(<<EODESC
The built-in web server is a non-essential service built into macOS and _MUST_ be disabled.

NOTE: The built in web server service is disabled at startup by default macOS.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/bin/launchctl print-disabled system | /usr/bin/grep -c '"org.apache.httpd" => disabled'
EOSRC
  )
  expected_result = "1"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-macos-os_icloud_storage_prompt_disable" {
  name = "[mSCP] - macOS - Disable iCloud Storage Setup during Setup Assistant"
  description = trimspace(<<EODESC
The prompt to set up iCloud storage services during Setup Assistant _MUST_ be disabled.

The default behavior of macOS is to prompt new users to set up storage in iCloud. Disabling the iCloud storage setup prompt provides organizations more control over the storage of their data.
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.SetupAssistant.managed')\
.objectForKey('SkipiCloudStorageSetup').js
EOS
EOSRC
  )
  expected_result = "true"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-macos-os_ir_support_disable" {
  name = "[mSCP] - macOS - Disable Infrared (IR) support"
  description = trimspace(<<EODESC
Infrared (IR) support _MUST_ be disabled to prevent users from controlling the system with IR devices.

By default, if IR is enabled, the system will accept IR control from any remote device.

NOTE: This is applicable only to models of Mac Mini systems earlier than Mac Mini8,1.
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.driver.AppleIRController')\
.objectForKey('DeviceEnabled').js
EOS
EOSRC
  )
  expected_result = "false"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-macos-os_loginwindow_adminhostinfo_undefined" {
  name = "[mSCP] - macOS - Prevent AdminHostInfo from Being Available at LoginWindow"
  description = trimspace(<<EODESC
The system _MUST_ be configured to not display sensitive information at the LoginWindow. The key AdminHostInfo when configured will allow the HostName, IP Address, and operating system version and build to be displayed.
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.loginwindow')\
.objectIsForcedForKey('AdminHostInfo')
EOS
EOSRC
  )
  expected_result = "false"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-macos-os_mdm_require" {
  name = "[mSCP] - macOS - Enforce Enrollment in Mobile Device Management"
  description = trimspace(<<EODESC
You _MUST_ enroll your Mac in a Mobile Device Management (MDM) software.

User Approved MDM (UAMDM) enrollment or enrollment via Apple Business Manager (ABM)/Apple School Manager (ASM) is required to manage certain security settings. Currently these include:

* Allowed Kernel Extensions
* Allowed Approved System Extensions
* Privacy Preferences Policy Control Payload
* ExtensibleSingleSignOn
* FDEFileVault

In macOS 11, UAMDM grants Supervised status on a Mac, unlocking the following MDM features, which were previously locked behind ABM:

* Activation Lock Bypass
* Access to Bootstrap Tokens
* Scheduling Software Updates
* Query list and delete local users
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/usr/bin/profiles status -type enrollment | /usr/bin/awk -F: '/MDM enrollment/ {print $2}' | /usr/bin/grep -c "Yes (User Approved)"
EOSRC
  )
  expected_result = "1"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-macos-os_newsyslog_files_owner_group_configure" {
  name = "[mSCP] - macOS - Configure System Log Files Owned by Root and Group to Wheel"
  description = trimspace(<<EODESC
The system log files _MUST_ be owned by root.

System logs contain sensitive data about the system and users. If log files are set to only be readable and writable by system administrators, the risk is mitigated.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/usr/bin/stat -f '%Su:%Sg:%N' $(/usr/bin/grep -v '^#' /etc/newsyslog.conf | /usr/bin/awk '{ print $1 }') 2> /dev/null | /usr/bin/awk '!/^root:wheel:/{print $1}' | /usr/bin/wc -l | /usr/bin/tr -d ' '
EOSRC
  )
  expected_result = "0"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-macos-os_newsyslog_files_permissions_configure" {
  name = "[mSCP] - macOS - Configure System Log Files to Mode 640 or Less Permissive"
  description = trimspace(<<EODESC
The system logs _MUST_ be configured to be writable by root and readable only by the root user and group wheel. To achieve this, system log files _MUST_ be configured to mode 640 permissive or less; thereby preventing normal users from reading, modifying or deleting audit logs. System logs frequently contain sensitive information that could be used by an attacker. Setting the correct permissions mitigates this risk.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/usr/bin/stat -f '%A:%N' $(/usr/bin/grep -v '^#' /etc/newsyslog.conf | /usr/bin/awk '{ print $1 }') 2> /dev/null | /usr/bin/awk '!/640/{print $1}' | /usr/bin/wc -l | /usr/bin/tr -d ' '
EOSRC
  )
  expected_result = "0"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-macos-os_nfsd_disable" {
  name = "[mSCP] - macOS - Disable Network File System Service"
  description = trimspace(<<EODESC
Support for Network File Systems (NFS) services is non-essential and, therefore, _MUST_ be disabled.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/bin/launchctl print-disabled system | /usr/bin/grep -c '"com.apple.nfsd" => disabled'
EOSRC
  )
  expected_result = "1"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-macos-os_on_device_dictation_enforce" {
  name = "[mSCP] - macOS - Enforce On Device Dictation"
  description = trimspace(<<EODESC
Dictation _MUST_ be restricted to on device only to prevent potential data exfiltration.

The information system _MUST_ be configured to provide only essential capabilities.
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('forceOnDeviceOnlyDictation').js
EOS
EOSRC
  )
  expected_result = "true"
  arch_amd64      = false
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-macos-os_password_autofill_disable" {
  name = "[mSCP] - macOS - Disable Password Autofill"
  description = trimspace(<<EODESC
Password Autofill _MUST_ be disabled.

macOS allows users to save passwords and use the Password Autofill feature in Safari and compatible apps. To protect against malicious users gaining access to the system, this feature _MUST_ be disabled to prevent users from being prompted to save passwords in applications.
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowPasswordAutoFill').js
EOS
EOSRC
  )
  expected_result = "false"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-macos-os_password_proximity_disable" {
  name = "[mSCP] - macOS - Disable Proximity Based Password Sharing Requests"
  description = trimspace(<<EODESC
Proximity based password sharing requests _MUST_ be disabled.

The default behavior of macOS is to allow users to request passwords from other known devices (macOS and iOS). This feature _MUST_ be disabled to prevent passwords from being shared.
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowPasswordProximityRequests').js
EOS
EOSRC
  )
  expected_result = "false"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-macos-os_password_sharing_disable" {
  name = "[mSCP] - macOS - Disable Password Sharing"
  description = trimspace(<<EODESC
Password Sharing _MUST_ be disabled.

The default behavior of macOS is to allow users to share a password over Airdrop between other macOS and iOS devices. This feature _MUST_ be disabled to prevent passwords from being shared.
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowPasswordSharing').js
EOS
EOSRC
  )
  expected_result = "false"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-macos-os_policy_banner_loginwindow_enforce" {
  name = "[mSCP] - macOS - Display Policy Banner at Login Window"
  description = trimspace(<<EODESC
Displaying a standardized and approved use notification before granting access to the operating system ensures that users are provided with privacy and security notification verbiage that is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.

System use notifications are required only for access via login interfaces with human users and are not required when such human interfaces do not exist.

The policy banner will show if a "PolicyBanner.rtf" or "PolicyBanner.rtfd" exists in the "/Library/Security" folder.

The banner text of the document _MUST_ read:

[source,text]
----
You are accessing a U.S. Government information system, which includes: 1) this computer, 2) this computer network, 3) all Government-furnished computers connected to this network, and 4) all Government-furnished devices and storage media attached to this network or to a computer on this network. You understand and consent to the following: you may access this information system for authorized use only; unauthorized use of the system is prohibited and subject to criminal and civil penalties; you have no reasonable expectation of privacy regarding any communication or data transiting or stored on this information system at any time and for any lawful Government purpose, the Government may monitor, intercept, audit, and search and seize any communication or data transiting or stored on this information system; and any communications or data transiting or stored on this information system may be disclosed or used for any lawful Government purpose. This information system may contain Controlled Unclassified Information (CUI) that is subject to safeguarding or dissemination controls in accordance with law, regulation, or Government-wide policy. Accessing and using this system indicates your understanding of this warning.
----
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/bin/ls -ld /Library/Security/PolicyBanner.rtf* | /usr/bin/wc -l | /usr/bin/tr -d ' '
EOSRC
  )
  expected_result = "1"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-macos-os_policy_banner_ssh_configure" {
  name = "[mSCP] - macOS - Display Policy Banner at Remote Login"
  description = trimspace(<<EODESC
Remote login service _MUST_ be configured to display a policy banner at login.

Displaying a standardized and approved use notification before granting access to the operating system ensures that users are provided with privacy and security notification verbiage that is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.

System use notifications are required only for access via login interfaces with human users and are not required when such human interfaces do not exist.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
bannerText="You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. By using this IS (which includes any device attached to this IS), you consent to the following conditions:
-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.
-At any time, the USG may inspect and seize data stored on this IS.
-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG authorized purpose.
-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.
-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."
test "$(cat /etc/banner)" = "$bannerText" && echo "1" || echo "0"
EOSRC
  )
  expected_result = "1"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-macos-os_policy_banner_ssh_enforce" {
  name = "[mSCP] - macOS - Enforce SSH to Display Policy Banner"
  description = trimspace(<<EODESC
SSH _MUST_ be configured to display a policy banner.

Displaying a standardized and approved use notification before granting access to the operating system ensures that users are provided with privacy and security notification verbiage that is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.

System use notifications are required only for access via login interfaces with human users and are not required when such human interfaces do not exist

NOTE: /etc/ssh/sshd_config will be automatically modified to its original state following any update or major upgrade to the operating system.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/usr/sbin/sshd -G | /usr/bin/grep -c "^banner /etc/banner"
EOSRC
  )
  expected_result = "1"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-macos-os_rapid_security_response_allow" {
  name = "[mSCP] - macOS - Enforce Rapid Security Response Mechanism"
  description = trimspace(<<EODESC
Rapid security response mechanism _MUST_ be enabled.
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowRapidSecurityResponseInstallation').js
EOS
EOSRC
  )
  expected_result = "true"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-macos-os_rapid_security_response_removal_disable" {
  name = "[mSCP] - macOS - Disable User Ability from Being Able to Undo Rapid Security Responses"
  description = trimspace(<<EODESC
Rapid security response (RSR) mechanism _MUST_ be enabled and the ability for the user to disable RSR _MUST_ be disabled.
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowRapidSecurityResponseRemoval').js
EOS
EOSRC
  )
  expected_result = "false"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-macos-os_recovery_lock_enable" {
  name = "[mSCP] - macOS - Enable Recovery Lock"
  description = trimspace(<<EODESC
A recovery lock password _MUST_ be enabled and set.

Single user mode, recovery mode, the Startup Manager, and several other tools are available on macOS by holding down specific key combinations during startup. Setting a recovery lock restricts access to these tools.

IMPORTANT: Recovery lock passwords are not supported on Intel devices. This rule is only applicable to Apple Silicon devices.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/usr/libexec/mdmclient QuerySecurityInfo | /usr/bin/grep -c "IsRecoveryLockEnabled = 1"
EOSRC
  )
  expected_result = "1"
  arch_amd64      = false
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-macos-os_root_disable" {
  name = "[mSCP] - macOS - Disable Root Login"
  description = trimspace(<<EODESC
To assure individual accountability and prevent unauthorized access, logging in as root at the login window _MUST_ be disabled.

The macOS system _MUST_ require individuals to be authenticated with an individual authenticator prior to using a group authenticator, and administrator users _MUST_ never log in directly as root.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/usr/bin/dscl . -read /Users/root UserShell 2>&1 | /usr/bin/grep -c "/usr/bin/false"
EOSRC
  )
  expected_result = "1"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-macos-os_screensaver_loginwindow_enforce" {
  name = "[mSCP] - macOS - Enforce Screen Saver at Login Window"
  description = trimspace(<<EODESC
A default screen saver _MUST_ be configured to display at the login window and _MUST_ not display any sensitive information.
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.screensaver')\
.objectForKey('moduleName').js
EOS
EOSRC
  )
  expected_result = "Sonoma"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-macos-os_secure_boot_verify" {
  name = "[mSCP] - macOS - Ensure Secure Boot Level Set to Full"
  description = trimspace(<<EODESC
The Secure Boot security setting _MUST_ be set to full.

Full security is the default Secure Boot setting in macOS. During startup, when Secure Boot is set to full security, the Mac will verify the integrity of the operating system before allowing the operating system to boot.

NOTE: This will only return a proper result on a T2 or Apple Silicon Macs.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/usr/libexec/mdmclient QuerySecurityInfo | /usr/bin/grep -c "SecureBootLevel = full"
EOSRC
  )
  expected_result = "1"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-macos-os_setup_assistant_filevault_enforce" {
  name = "[mSCP] - macOS - Enforce FileVault in Setup Assistant"
  description = trimspace(<<EODESC
FileVault _MUST_ be enforced in Setup Assistant.

The information system implements cryptographic mechanisms to protect the confidentiality and integrity of information stored on digital media during transport outside of controlled areas.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.MCX.FileVault2')\
.objectForKey('ForceEnableInSetupAssistant')
EOS
EOSRC
  )
  expected_result = "1"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-macos-os_sip_enable" {
  name = "[mSCP] - macOS - Ensure System Integrity Protection is Enabled"
  description = trimspace(<<EODESC
System Integrity Protection (SIP) _MUST_ be enabled.

SIP is vital to protecting the integrity of the system as it prevents malicious users and software from making unauthorized and/or unintended modifications to protected files and folders; ensures the presence of an audit record generation capability for defined auditable events for all operating system components; protects audit tools from unauthorized access, modification, and deletion; restricts the root user account and limits the actions that the root user can perform on protected parts of the macOS; and prevents non-privileged users from granting other users direct access to the contents of their home directories and folders.

NOTE: SIP is enabled by default in macOS.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/usr/bin/csrutil status | /usr/bin/grep -c 'System Integrity Protection status: enabled.'
EOSRC
  )
  expected_result = "1"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-macos-os_siri_prompt_disable" {
  name = "[mSCP] - macOS - Disable Siri Setup during Setup Assistant"
  description = trimspace(<<EODESC
The prompt for Siri during Setup Assistant _MUST_ be disabled.

Organizations _MUST_ apply organization-wide configuration settings. The macOS Siri Assistant Setup prompt guides new users through enabling their own specific Siri settings; this is not essential and, therefore, _MUST_ be disabled to prevent against the risk of individuals electing Siri settings with the potential to override organization-wide settings.
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.SetupAssistant.managed')\
.objectForKey('SkipSiriSetup').js
EOS
EOSRC
  )
  expected_result = "true"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-macos-os_skip_unlock_with_watch_enable" {
  name = "[mSCP] - macOS - Disable Unlock with Apple Watch During Setup Assistant"
  description = trimspace(<<EODESC
The prompt for Apple Watch unlock setup during Setup Assistant _MUST_ be disabled.

Disabling Apple watches is a necessary step to ensuring that the information system retains a session lock until the user reestablishes access using an authorized identification and authentication procedures.
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.SetupAssistant.managed')\
.objectForKey('SkipUnlockWithWatch').js
EOS
EOSRC
  )
  expected_result = "true"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-macos-os_ssh_fips_compliant" {
  name = "[mSCP] - macOS - Limit SSH to FIPS Compliant Connections"
  description = trimspace(<<EODESC
SSH _MUST_ be configured to limit the Ciphers, HostbasedAcceptedAlgorithms, HostKeyAlgorithms, KexAlgorithms, MACs, PubkeyAcceptedAlgorithms, CASignatureAlgorithms to algorithms that are FIPS 140 validated.

FIPS 140-2 is the current standard for validating that mechanisms used to access cryptographic modules utilize authentication that meet federal requirements.

Operating systems utilizing encryption _MUST_ use FIPS validated mechanisms for authenticating to cryptographic modules.

NOTE: For more information on FIPS compliance with the version of SSH included in the macOS, the manual page apple_ssh_and_fips has additional information.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
fips_ssh_config="Host *
Ciphers aes128-gcm@openssh.com
HostbasedAcceptedAlgorithms ecdsa-sha2-nistp256,ecdsa-sha2-nistp256-cert-v01@openssh.com
HostKeyAlgorithms ecdsa-sha2-nistp256,ecdsa-sha2-nistp256-cert-v01@openssh.com
KexAlgorithms ecdh-sha2-nistp256
MACs hmac-sha2-256
PubkeyAcceptedAlgorithms ecdsa-sha2-nistp256,ecdsa-sha2-nistp256-cert-v01@openssh.com
CASignatureAlgorithms ecdsa-sha2-nistp256"
/usr/bin/grep -c "$fips_ssh_config" /etc/ssh/ssh_config.d/fips_ssh_config
EOSRC
  )
  expected_result = "8"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-macos-os_ssh_server_alive_count_max_configure" {
  name = "[mSCP] - macOS - Set SSH Active Server Alive Maximum to 0"
  description = trimspace(<<EODESC
SSH _MUST_ be configured with an Active Server Alive Maximum Count set to 0. Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle session or an incomplete login attempt will also free up resources committed by the managed network element.

NOTE: /etc/ssh/ssh_config will be automatically modified to its original state following any update or major upgrade to the operating system.
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
ret="pass"
for u in $(/usr/bin/dscl . -list /Users UniqueID | /usr/bin/awk '$2 > 500 {print $1}'); do
  sshCheck=$(/usr/bin/sudo -u $u /usr/bin/ssh -G . | /usr/bin/grep -c "^serveralivecountmax 0")
  if [[ "$sshCheck" == "0" ]]; then
    ret="fail"
    break
  fi
done
/bin/echo $ret
EOSRC
  )
  expected_result = "pass"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-macos-os_ssh_server_alive_interval_configure" {
  name = "[mSCP] - macOS - Configure SSH ServerAliveInterval option set to 900"
  description = trimspace(<<EODESC
SSH _MUST_ be configured with an Active Server Alive Maximum Count set to 900.

Setting the Active Server Alive Maximum Count to 900 will log users out after a 900 seconds interval of inactivity.

NOTE: /etc/ssh/ssh_config will be automatically modified to its original state following any update or major upgrade to the operating system.
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
ret="pass"
for u in $(/usr/bin/dscl . -list /Users UniqueID | /usr/bin/awk '$2 > 500 {print $1}'); do
  sshCheck=$(/usr/bin/sudo -u $u /usr/bin/ssh -G . | /usr/bin/grep -c "^serveraliveinterval 900")
  if [[ "$sshCheck" == "0" ]]; then
    ret="fail"
    break
  fi
done
/bin/echo $ret
EOSRC
  )
  expected_result = "pass"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-macos-os_sshd_channel_timeout_configure" {
  name = "[mSCP] - macOS - Configure SSHD Channel Timeout to 900"
  description = trimspace(<<EODESC
If SSHD is enabled it _MUST_ be configured with session ChannelTime out set to 900.

This will set the time out when the session is inactive.

NOTE: /etc/ssh/sshd_config will be automatically modified to its original state following any update or major upgrade to the operating system.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/usr/sbin/sshd -G | /usr/bin/awk -F "=" '/channeltimeout session:*/{print $2}'
EOSRC
  )
  expected_result = "900"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-macos-os_sshd_client_alive_count_max_configure" {
  name = "[mSCP] - macOS - Configure SSHD ClientAliveCountMax to 0"
  description = trimspace(<<EODESC
If SSHD is enabled it _MUST_ be configured with the Client Alive Maximum Count set to 0.

This will set the number of client alive messages which may be sent without the SSH server receiving any messages back from the client.  If this threshold is reached while client alive messages are being sent, the SSH server will disconnect the client, terminating the session.  The client alive messages are sent through the encrypted channel and therefore will not be spoofable.  The client alive mechanism is valuable when the client or server depend on knowing when a connection has become unresponsive.

NOTE: This setting is not intended to manage idle user sessions where there is no input from the client. Its purpose is to monitor for interruptions in network connectivity and force the session to terminate after the connection appears to be broken.

NOTE: /etc/ssh/sshd_config will be automatically modified to its original state following any update or major upgrade to the operating system.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/usr/sbin/sshd -G | /usr/bin/awk '/clientalivecountmax/{print $2}'
EOSRC
  )
  expected_result = "0"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-macos-os_sshd_client_alive_interval_configure" {
  name = "[mSCP] - macOS - Configure SSHD ClientAliveInterval to 900"
  description = trimspace(<<EODESC
If SSHD is enabled then it _MUST_ be configured with the Client Alive Interval set to 900.

Sets a timeout interval in seconds after which if no data has been received from the client, sshd(8) will send a message through the encrypted channel to request a response from the client.

This setting works in conjunction with ClientAliveCountMax to determine the termination of the connection after the threshold has been reached.

NOTE: This setting is not intended to manage idle user sessions where there is no input from the client. Its purpose is to monitor for interruptions in network connectivity and force the session to terminate after the connection appears to be broken.

NOTE: /etc/ssh/sshd_config will be automatically modified to its original state following any update or major upgrade to the operating system.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/usr/sbin/sshd -G | /usr/bin/awk '/clientaliveinterval/{print $2}'
EOSRC
  )
  expected_result = "900"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-macos-os_sshd_fips_compliant" {
  name = "[mSCP] - macOS - Limit SSHD to FIPS Compliant Connections"
  description = trimspace(<<EODESC
If SSHD is enabled then it _MUST_ be configured to limit the Ciphers, HostbasedAcceptedAlgorithms, HostKeyAlgorithms, KexAlgorithms, MACs, PubkeyAcceptedAlgorithms, CASignatureAlgorithms to algorithms that are FIPS 140 validated.

FIPS 140-2 is the current standard for validating that mechanisms used to access cryptographic modules utilize authentication that meet federal requirements.

Operating systems utilizing encryption _MUST_ use FIPS validated mechanisms for authenticating to cryptographic modules.

NOTE: For more information on FIPS compliance with the version of SSHD included in the macOS, the manual page apple_ssh_and_fips has additional information.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
fips_sshd_config=("Ciphers aes128-gcm@openssh.com" "HostbasedAcceptedAlgorithms ecdsa-sha2-nistp256,ecdsa-sha2-nistp256-cert-v01@openssh.com" "HostKeyAlgorithms ecdsa-sha2-nistp256,ecdsa-sha2-nistp256-cert-v01@openssh.com" "KexAlgorithms ecdh-sha2-nistp256" "MACs hmac-sha2-256" "PubkeyAcceptedAlgorithms ecdsa-sha2-nistp256,ecdsa-sha2-nistp256-cert-v01@openssh.com" "CASignatureAlgorithms ecdsa-sha2-nistp256")
total=0
for config in $fips_sshd_config; do
  total=$(expr $(/usr/sbin/sshd -G | /usr/bin/grep -i -c "$config") + $total)
done

echo $total
EOSRC
  )
  expected_result = "7"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-macos-os_sshd_unused_connection_timeout_configure" {
  name = "[mSCP] - macOS - Configure SSHD Unused Connection Timeout to 900"
  description = trimspace(<<EODESC
If SSHD is enabled it _MUST_ be configured with unused connection timeout set to 900.

This will set the time out when there are no open channels within an session.

NOTE: /etc/ssh/sshd_config will be automatically modified to its original state following any update or major upgrade to the operating system.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/usr/sbin/sshd -G | /usr/bin/awk '/unusedconnectiontimeout/{print $2}'
EOSRC
  )
  expected_result = "900"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-macos-os_sudo_timeout_configure" {
  name = "[mSCP] - macOS - Configure Sudo Timeout Period to 0"
  description = trimspace(<<EODESC
The file /etc/sudoers _MUST_ include a timestamp_timeout of 0.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/usr/bin/sudo /usr/bin/sudo -V | /usr/bin/grep -c "Authentication timestamp timeout: 0.0 minutes"
EOSRC
  )
  expected_result = "1"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-macos-os_sudoers_timestamp_type_configure" {
  name = "[mSCP] - macOS - Configure Sudoers Timestamp Type"
  description = trimspace(<<EODESC
The file /etc/sudoers _MUST_ be configured to not include a timestamp_type of global or ppid and be configured for timestamp record types of tty.

This rule ensures that the "sudo" command will prompt for the administrator's password at least once in each newly opened terminal window. This prevents a malicious user from taking advantage of an unlocked computer or an abandoned logon session by bypassing the normal password prompt requirement.
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
/usr/bin/sudo /usr/bin/sudo -V | /usr/bin/awk -F": " '/Type of authentication timestamp record/{print $2}'
EOSRC
  )
  expected_result = "tty"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-macos-os_system_read_only" {
  name = "[mSCP] - macOS - Ensure System Volume is Read Only"
  description = trimspace(<<EODESC
The System volume _MUST_ be mounted as read-only in order to ensure that configurations critical to the integrity of the macOS have not been compromised. System Integrity Protection (SIP) will prevent the system volume from being mounted as writable.

NOTE: The system volume is read only by default in macOS.
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
/usr/sbin/system_profiler SPStorageDataType | /usr/bin/awk '/Mount Point: \/$/{x=NR+2}(NR==x){print $2}'
EOSRC
  )
  expected_result = "No"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-macos-os_tftpd_disable" {
  name = "[mSCP] - macOS - Disable Trivial File Transfer Protocol Service"
  description = trimspace(<<EODESC
If the system does not require Trivial File Transfer Protocol (TFTP), support it is non-essential and _MUST_ be disabled.

The information system _MUST_ be configured to provide only essential capabilities. Disabling TFTP helps prevent the unauthorized connection of devices and the unauthorized transfer of information.

NOTE: TFTP service is disabled at startup by default macOS.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/bin/launchctl print-disabled system | /usr/bin/grep -c '"com.apple.tftpd" => disabled'
EOSRC
  )
  expected_result = "1"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-macos-os_time_server_enabled" {
  name = "[mSCP] - macOS - Enable Time Synchronization Daemon"
  description = trimspace(<<EODESC
The macOS time synchronization daemon (timed) _MUST_ be enabled for proper time synchronization to an authorized time server.

NOTE: The time synchronization daemon is enabled by default on macOS.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/bin/launchctl list | /usr/bin/grep -c com.apple.timed
EOSRC
  )
  expected_result = "1"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-macos-os_touchid_prompt_disable" {
  name = "[mSCP] - macOS - Disable TouchID Prompt during Setup Assistant"
  description = trimspace(<<EODESC
The prompt for TouchID during Setup Assistant _MUST_ be disabled.

macOS prompts new users through enabling TouchID during Setup Assistant; this is not essential and, therefore, _MUST_ be disabled to prevent against the risk of individuals electing to enable TouchID to override organization-wide settings.
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.SetupAssistant.managed')\
.objectForKey('SkipTouchIDSetup').js
EOS
EOSRC
  )
  expected_result = "true"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-macos-os_unlock_active_user_session_disable" {
  name = "[mSCP] - macOS - Disable Login to Other User's Active and Locked Sessions"
  description = trimspace(<<EODESC
The ability to log in to another user's active or locked session _MUST_ be disabled.

macOS has a privilege that can be granted to any user that will allow that user to unlock active user's sessions. Disabling the admins and/or user's ability to log into another user's active and locked session prevents unauthorized persons from viewing potentially sensitive and/or personal information.

NOTE: Configuring this setting will change the user experience and disable TouchID from unlocking the screensaver. To restore the user experience and allow TouchID to unlock the screensaver, you can run `/usr/bin/sudo /usr/bin/defaults write /Library/Preferences/com.apple.loginwindow screenUnlockMode -int 1`. This setting can also be deployed with a configuration profile.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/usr/bin/security authorizationdb read system.login.screensaver 2>&1 | /usr/bin/grep -c '<string>authenticate-session-owner</string>'
EOSRC
  )
  expected_result = "1"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-macos-os_uucp_disable" {
  name = "[mSCP] - macOS - Disable Unix-to-Unix Copy Protocol Service"
  description = trimspace(<<EODESC
The system _MUST_ not have the Unix-to-Unix Copy Protocol (UUCP) service active.

UUCP, a set of programs that enable the sending of files between different UNIX systems as well as sending commands to be executed on another system, is not essential and _MUST_ be disabled in order to prevent the unauthorized connection of devices, transfer of information, and tunneling.

NOTE: UUCP service is disabled at startup by default macOS.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/bin/launchctl print-disabled system | /usr/bin/grep -c '"com.apple.uucp" => disabled'
EOSRC
  )
  expected_result = "1"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-passwordpolicy-pwpolicy_account_inactivity_enforce" {
  name = "[mSCP] - Password Policy - Disable Accounts after 35 Days of Inactivity"
  description = trimspace(<<EODESC
The macOS _MUST_ be configured to disable accounts after 35 days of inactivity.

This rule prevents malicious users from making use of unused accounts to gain access to the system while avoiding detection.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/usr/bin/pwpolicy -getaccountpolicies 2> /dev/null | /usr/bin/tail +2 | /usr/bin/xmllint --xpath '//dict/key[text()="policyAttributeInactiveDays"]/following-sibling::integer[1]/text()' -
EOSRC
  )
  expected_result = "35"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-passwordpolicy-pwpolicy_account_lockout_enforce" {
  name = "[mSCP] - Password Policy - Limit Consecutive Failed Login Attempts to 3"
  description = trimspace(<<EODESC
The macOS _MUST_ be configured to limit the number of failed login attempts to a maximum of 3. When the maximum number of failed attempts is reached, the account _MUST_ be locked for a period of time after.

This rule protects against malicious users attempting to gain access to the system via brute-force hacking methods.
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
/usr/bin/pwpolicy -getaccountpolicies 2> /dev/null | /usr/bin/tail +2 | /usr/bin/xmllint --xpath '//dict/key[text()="policyAttributeMaximumFailedAuthentications"]/following-sibling::integer[1]/text()' - | /usr/bin/awk '{ if ($1 <= 3) {print "yes"} else {print "no"}}'
EOSRC
  )
  expected_result = "yes"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-passwordpolicy-pwpolicy_account_lockout_timeout_enforce" {
  name = "[mSCP] - Password Policy - Set Account Lockout Time to 15 Minutes"
  description = trimspace(<<EODESC
The macOS _MUST_ be configured to enforce a lockout time period of at least 15 minutes when the maximum number of failed logon attempts is reached.

This rule protects against malicious users attempting to gain access to the system via brute-force hacking methods.
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
/usr/bin/pwpolicy -getaccountpolicies 2> /dev/null | /usr/bin/tail +2 | /usr/bin/xmllint --xpath '//dict/key[text()="autoEnableInSeconds"]/following-sibling::integer[1]/text()' - | /usr/bin/awk '{ if ($1/60 >= 15 ) {print "yes"} else {print "no"}}'
EOSRC
  )
  expected_result = "yes"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-passwordpolicy-pwpolicy_alpha_numeric_enforce" {
  name = "[mSCP] - Password Policy - Require Passwords Contain a Minimum of One Numeric Character"
  description = trimspace(<<EODESC
The macOS _MUST_ be configured to require at least one numeric character be used when a password is created.

This rule enforces password complexity by requiring users to set passwords that are less vulnerable to malicious users.

NOTE: The guidance for password based authentication in NIST 800-53 (Rev 5) and NIST 800-63B state that complexity rules should be organizationally defined. The values defined are based off of common complexity values. But your organization may define its own password complexity rules.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/usr/bin/pwpolicy -getaccountpolicies 2> /dev/null | /usr/bin/tail +2 | /usr/bin/xmllint --xpath '//dict/key[text()="policyIdentifier"]/following-sibling::*[1]/text()' - | /usr/bin/grep "requireAlphanumeric" -c
EOSRC
  )
  expected_result = "1"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-passwordpolicy-pwpolicy_custom_regex_enforce" {
  name = "[mSCP] - Password Policy - Require Passwords to Match the Defined Custom Regular Expression"
  description = trimspace(<<EODESC
The macOS _MUST_ be configured to meet complexity requirements defined in ^(?=.*[A-Z])(?=.*[a-z]).*$.

This rule enforces password complexity by requiring users to set passwords that are less vulnerable to malicious users.

NOTE: The guidance for password based authentication in NIST 800-53 (Rev 5) and NIST 800-63B state that complexity rules should be organizationally defined. The values defined are based off of common complexity values. But your organization may define its own password complexity rules.

NOTE: The configuration profile generated must be installed from an MDM server.
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
/usr/bin/pwpolicy -getaccountpolicies 2> /dev/null | /usr/bin/tail +2 | /usr/bin/xmllint --xpath 'boolean(//*[contains(text(),"policyAttributePassword matches '\''^(?=.*[A-Z])(?=.*[a-z]).*$'\''")])' -
EOSRC
  )
  expected_result = "true"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-passwordpolicy-pwpolicy_history_enforce" {
  name = "[mSCP] - Password Policy - Prohibit Password Reuse for a Minimum of 5 Generations"
  description = trimspace(<<EODESC
The macOS _MUST_ be configured to enforce a password history of at least 5 previous passwords when a password is created.

This rule ensures that users are  not allowed to re-use a password that was used in any of the 5 previous password generations.

Limiting password reuse protects against malicious users attempting to gain access to the system via brute-force hacking methods.

NOTE: The guidance for password based authentication in NIST 800-53 (Rev 5) and NIST 800-63B state that complexity rules should be organizationally defined. The values defined are based off of common complexity values. But your organization may define its own password complexity rules.
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
/usr/bin/pwpolicy -getaccountpolicies 2> /dev/null | /usr/bin/tail +2 | /usr/bin/xmllint --xpath '//dict/key[text()="policyAttributePasswordHistoryDepth"]/following-sibling::*[1]/text()' - | /usr/bin/awk '{ if ($1 >= 5 ) {print "yes"} else {print "no"}}'
EOSRC
  )
  expected_result = "yes"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-passwordpolicy-pwpolicy_max_lifetime_enforce" {
  name = "[mSCP] - Password Policy - Restrict Maximum Password Lifetime to 60 Days"
  description = trimspace(<<EODESC
The macOS _MUST_ be configured to enforce a maximum password lifetime limit of at least 60 days.

This rule ensures that users are forced to change their passwords frequently enough to prevent malicious users from gaining and maintaining access to the system.

NOTE: The guidance for password based authentication in NIST 800-53 (Rev 5) and NIST 800-63B state that complexity rules should be organizationally defined. The values defined are based off of common complexity values. But your organization may define its own password complexity rules.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/usr/bin/pwpolicy -getaccountpolicies 2> /dev/null | /usr/bin/tail +2 | /usr/bin/xmllint --xpath '//dict/key[text()="policyAttributeExpiresEveryNDays"]/following-sibling::*[1]/text()' -
EOSRC
  )
  expected_result = "60"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-passwordpolicy-pwpolicy_minimum_length_enforce" {
  name = "[mSCP] - Password Policy - Require a Minimum Password Length of 15 Characters"
  description = trimspace(<<EODESC
The macOS _MUST_ be configured to require a minimum of 15 characters be used when a password is created.

This rule enforces password complexity by requiring users to set passwords that are less vulnerable to malicious users.

NOTE: The guidance for password based authentication in NIST 800-53 (Rev 5) and NIST 800-63B state that complexity rules should be organizationally defined. The values defined are based off of common complexity values. But your organization may define its own password complexity rules.
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
/usr/bin/pwpolicy -getaccountpolicies 2> /dev/null | /usr/bin/tail +2 | /usr/bin/xmllint --xpath 'boolean(//*[contains(text(),"policyAttributePassword matches '\''.{15,}'\''")])' -
EOSRC
  )
  expected_result = "true"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-passwordpolicy-pwpolicy_minimum_lifetime_enforce" {
  name = "[mSCP] - Password Policy - Set Minimum Password Lifetime to 24 Hours"
  description = trimspace(<<EODESC
The macOS _MUST_ be configured to enforce a minimum password lifetime limit of 24 hours.

This rule discourages users from cycling through their previous passwords to get back to a preferred one.

NOTE: The guidance for password based authentication in NIST 800-53 (Rev 5) and NIST 800-63B state that complexity rules should be organizationally defined. The values defined are based off of common complexity values. But your organization may define its own password complexity rules.
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
/usr/bin/pwpolicy -getaccountpolicies 2> /dev/null | /usr/bin/tail +2 | /usr/bin/xmllint --xpath '//dict/key[text()="policyAttributeMinimumLifetimeHours"]/following-sibling::integer[1]/text()' - | /usr/bin/awk '{ if ($1 >= 24 ) {print "yes"} else {print "no"}}'
EOSRC
  )
  expected_result = "yes"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-passwordpolicy-pwpolicy_simple_sequence_disable" {
  name = "[mSCP] - Password Policy - Prohibit Repeating, Ascending, and Descending Character Sequences"
  description = trimspace(<<EODESC
The macOS _MUST_ be configured to prohibit the use of repeating, ascending, and descending character sequences when a password is created.

This rule enforces password complexity by requiring users to set passwords that are less vulnerable to malicious users.

NOTE: The guidance for password based authentication in NIST 800-53 (Rev 5) and NIST 800-63B state that complexity rules should be organizationally defined. The values defined are based off of common complexity values. But your organization may define its own password complexity rules.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/usr/bin/pwpolicy -getaccountpolicies 2> /dev/null | /usr/bin/tail +2 | /usr/bin/xmllint --xpath '//dict/key[text()="policyIdentifier"]/following-sibling::*[1]/text()' - | /usr/bin/grep "allowSimple" -c
EOSRC
  )
  expected_result = "1"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-passwordpolicy-pwpolicy_special_character_enforce" {
  name = "[mSCP] - Password Policy - Require Passwords Contain a Minimum of One Special Character"
  description = trimspace(<<EODESC
The macOS _MUST_ be configured to require at least one special character be used when a password is created.

Special characters are those characters that are not alphanumeric. Examples include: ~ ! @ # $ % ^ *.

This rule enforces password complexity by requiring users to set passwords that are less vulnerable to malicious users.

NOTE: The guidance for password based authentication in NIST 800-53 (Rev 5) and NIST 800-63B state that complexity rules should be organizationally defined. The values defined are based off of common complexity values. But your organization may define its own password complexity rules.
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
/usr/bin/pwpolicy -getaccountpolicies 2> /dev/null | /usr/bin/tail +2 | /usr/bin/xmllint --xpath 'boolean(//*[contains(text(),"policyAttributePassword matches '\''(.*[^a-zA-Z0-9].*){1,}'\''")])' -
EOSRC
  )
  expected_result = "true"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-systemsettings-system_settings_airplay_receiver_disable" {
  name = "[mSCP] - System Settings - Disable Airplay Receiver"
  description = trimspace(<<EODESC
Airplay Receiver allows you to send content from another Apple device to be displayed on the screen as it's being played from your other device.

Support for Airplay Receiver is non-essential and _MUST_ be disabled.

The information system _MUST_ be configured to provide only essential capabilities.
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowAirPlayIncomingRequests').js
EOS
EOSRC
  )
  expected_result = "false"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-systemsettings-system_settings_apple_watch_unlock_disable" {
  name = "[mSCP] - System Settings - Prevent Apple Watch from Terminating a Session Lock"
  description = trimspace(<<EODESC
Apple Watches are not an approved authenticator and their use _MUST_ be disabled.

Disabling Apple watches is a necessary step to ensuring that the information system retains a session lock until the user reestablishes access using an authorized identification and authentication procedures.

NOTE: Unlocking the system with an Apple Watch is not an approved authenticator for US Federal Government usage as it has not been verified to meet the strength requirements outlined in NIST SP 800-63.
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowAutoUnlock').js
EOS
EOSRC
  )
  expected_result = "false"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-systemsettings-system_settings_automatic_login_disable" {
  name = "[mSCP] - System Settings - Disable Unattended or Automatic Logon to the System"
  description = trimspace(<<EODESC
Automatic logon _MUST_ be disabled.

When automatic logons are enabled, the default user account is automatically logged on at boot time without prompting the user for a password. Even if the screen is later locked, a malicious user would be able to reboot the computer and find it already logged in. Disabling automatic logons mitigates this risk.
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.loginwindow')\
.objectForKey('com.apple.login.mcx.DisableAutoLoginClient').js
EOS
EOSRC
  )
  expected_result = "true"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-systemsettings-system_settings_automatic_logout_enforce" {
  name = "[mSCP] - System Settings - Enforce Auto Logout After 86400 Seconds of Inactivity"
  description = trimspace(<<EODESC
Auto logout _MUST_ be configured to automatically terminate a user session and log out the after 86400 seconds of inactivity.

NOTE:The maximum that macOS can be configured for autologoff is 86400 seconds.

[IMPORTANT]
====
The automatic logout may cause disruptions to an organization's workflow and/or loss of data. Information System Security Officers (ISSOs) are advised to first fully weigh the potential risks posed to their organization before opting to disable the automatic logout setting.
====
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('.GlobalPreferences')\
.objectForKey('com.apple.autologout.AutoLogOutDelay').js
EOS
EOSRC
  )
  expected_result = "86400"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-systemsettings-system_settings_bluetooth_disable" {
  name = "[mSCP] - System Settings - Disable Bluetooth When no Approved Device is Connected"
  description = trimspace(<<EODESC
The macOS system _MUST_ be configured to disable Bluetooth unless there is an approved device connected.

[IMPORTANT]
====
Information System Security Officers (ISSOs) may make the risk-based decision not to disable Bluetooth, so as to maintain necessary functionality, but they are advised to first fully weigh the potential risks posed to their organization.
====
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.MCXBluetooth')\
.objectForKey('DisableBluetooth').js
EOS
EOSRC
  )
  expected_result = "true"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-systemsettings-system_settings_bluetooth_settings_disable" {
  name = "[mSCP] - System Settings - Disable the Bluetooth System Settings Pane"
  description = trimspace(<<EODESC
The Bluetooth System Setting pane _MUST_ be disabled to prevent access to the bluetooth configuration.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/usr/bin/profiles show -output stdout-xml | /usr/bin/xmllint --xpath '//key[text()="DisabledSystemSettings"]/following-sibling::*[1]' - | /usr/bin/grep -c com.apple.BluetoothSettings
EOSRC
  )
  expected_result = "1"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-systemsettings-system_settings_bluetooth_sharing_disable" {
  name = "[mSCP] - System Settings - Disable Bluetooth Sharing"
  description = trimspace(<<EODESC
Bluetooth Sharing _MUST_ be disabled.

Bluetooth Sharing allows users to wirelessly transmit files between the macOS and Bluetooth-enabled devices, including personally owned cellphones and tablets. A malicious user might introduce viruses or malware onto the system or extract sensitive files via Bluetooth Sharing. When Bluetooth Sharing is disabled, this risk is mitigated.

[NOTE]
====
The check and fix are for the currently logged in user. To get the currently logged in user, run the following.
[source,bash]
----
CURRENT_USER=$( /usr/sbin/scutil <<< "show State:/Users/ConsoleUser" | /usr/bin/awk '/Name :/ && ! /loginwindow/ { print $3 }' )
----
====
EODESC
  )
  type = "ZSH_BOOL"
  source = trimspace(<<EOSRC
/usr/bin/sudo -u "$CURRENT_USER" /usr/bin/defaults -currentHost read com.apple.Bluetooth PrefKeyServicesEnabled
EOSRC
  )
  expected_result = "0"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-systemsettings-system_settings_cd_dvd_sharing_disable" {
  name = "[mSCP] - System Settings - Disable CD/DVD Sharing"
  description = trimspace(<<EODESC
CD/DVD Sharing _MUST_ be disabled.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/usr/bin/pgrep -q ODSAgent; /bin/echo $?
EOSRC
  )
  expected_result = "1"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-systemsettings-system_settings_content_caching_disable" {
  name = "[mSCP] - System Settings - Disable Content Caching Service"
  description = trimspace(<<EODESC
Content caching _MUST_ be disabled.

Content caching is a macOS service that helps reduce Internet data usage and speed up software installation on Mac computers. It is not recommended for devices furnished to employees to act as a caching server.
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowContentCaching').js
EOS
EOSRC
  )
  expected_result = "false"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-systemsettings-system_settings_critical_update_install_enforce" {
  name = "[mSCP] - System Settings - Enforce Critical Security Updates to be Installed"
  description = trimspace(<<EODESC
Ensure that security updates are installed as soon as they are available from Apple.
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.SoftwareUpdate')\
.objectForKey('CriticalUpdateInstall').js
EOS
EOSRC
  )
  expected_result = "true"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-systemsettings-system_settings_diagnostics_reports_disable" {
  name = "[mSCP] - System Settings - Disable Sending Diagnostic and Usage Data to Apple"
  description = trimspace(<<EODESC
The ability to submit diagnostic data to Apple _MUST_ be disabled.

The information system _MUST_ be configured to provide only essential capabilities. Disabling the submission of diagnostic and usage information will mitigate the risk of unwanted data being sent to Apple.
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
/usr/bin/osascript -l JavaScript << EOS
function run() {
let pref1 = $.NSUserDefaults.alloc.initWithSuiteName('com.apple.SubmitDiagInfo')\
.objectForKey('AutoSubmit').js
let pref2 = $.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowDiagnosticSubmission').js
if ( pref1 == false && pref2 == false ){
    return("true")
} else {
    return("false")
}
}
EOS
EOSRC
  )
  expected_result = "true"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-systemsettings-system_settings_filevault_enforce" {
  name = "[mSCP] - System Settings - Enforce FileVault"
  description = trimspace(<<EODESC
FileVault _MUST_ be enforced.

The information system implements cryptographic mechanisms to protect the confidentiality and integrity of information stored on digital media during transport outside of controlled areas.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
dontAllowDisable=$(/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.MCX')\
.objectForKey('dontAllowFDEDisable').js
EOS
)
fileVault=$(/usr/bin/fdesetup status | /usr/bin/grep -c "FileVault is On.")
if [[ "$dontAllowDisable" == "true" ]] && [[ "$fileVault" == 1 ]]; then
  echo "1"
else
  echo "0"
fi
EOSRC
  )
  expected_result = "1"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-systemsettings-system_settings_find_my_disable" {
  name = "[mSCP] - System Settings - Disable Find My Service"
  description = trimspace(<<EODESC
The Find My service _MUST_ be disabled.

A Mobile Device Management (MDM) solution _MUST_ be used to carry out remote locking and wiping instead of Apple's Find My service.

Apple's Find My service uses a personal AppleID for authentication. Organizations should rely on MDM solutions, which have much more secure authentication requirements, to perform remote lock and remote wipe.
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
/usr/bin/osascript -l JavaScript << EOS
function run() {
  let pref1 = ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowFindMyDevice'))
  let pref2 = ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowFindMyFriends'))
  let pref3 = ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.icloud.managed')\
.objectForKey('DisableFMMiCloudSetting'))
  if ( pref1 == false && pref2 == false && pref3 == true ) {
    return("true")
  } else {
    return("false")
  }
}
EOS
EOSRC
  )
  expected_result = "true"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-systemsettings-system_settings_firewall_enable" {
  name = "[mSCP] - System Settings - Enable macOS Application Firewall"
  description = trimspace(<<EODESC
The macOS Application Firewall is the built-in firewall that comes with macOS, and it _MUST_ be enabled.

When the macOS Application Firewall is enabled, the flow of information within the information system and between interconnected systems will be controlled by approved authorizations.
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
profile="$(/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.security.firewall')\
.objectForKey('EnableFirewall').js
EOS
)"

plist="$(/usr/bin/defaults read /Library/Preferences/com.apple.alf globalstate 2>/dev/null)"

if [[ "$profile" == "true" ]] && [[ "$plist" =~ [1,2] ]]; then
  echo "true"
else
  echo "false"
fi
EOSRC
  )
  expected_result = "true"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-systemsettings-system_settings_firewall_stealth_mode_enable" {
  name = "[mSCP] - System Settings - Enable Firewall Stealth Mode"
  description = trimspace(<<EODESC
Firewall Stealth Mode _MUST_ be enabled.

When stealth mode is enabled, the Mac will not respond to any probing requests, and only requests from authorized applications will still be authorized.

[IMPORTANT]
====
Enabling firewall stealth mode may prevent certain remote mechanisms used for maintenance and compliance scanning from properly functioning. Information System Security Officers (ISSOs) are advised to first fully weigh the potential risks posed to their organization before opting not to enable stealth mode.
====
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
profile="$(/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.security.firewall')\
.objectForKey('EnableStealthMode').js
EOS
)"

plist=$(/usr/bin/defaults read /Library/Preferences/com.apple.alf stealthenabled 2>/dev/null)

if [[ "$profile" == "true" ]] && [[ $plist == 1 ]]; then
  echo "true"
else
  echo "false"
fi
EOSRC
  )
  expected_result = "true"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-systemsettings-system_settings_gatekeeper_identified_developers_allowed" {
  name = "[mSCP] - System Settings - Apply Gatekeeper Settings to Block Applications from Unidentified Developers"
  description = trimspace(<<EODESC
The information system implements cryptographic mechanisms to authenticate software prior to installation.

Gatekeeper settings must be configured correctly to only allow the system to run applications downloaded from the Mac App Store or applications signed with a valid Apple Developer ID code. Administrator users will still have the option to override these settings on a per-app basis. Gatekeeper is a security feature that ensures that applications must be digitally signed by an Apple-issued certificate in order to run. Digital signatures allow the macOS to verify that the application has not been modified by a malicious third party.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/usr/sbin/spctl --status --verbose | /usr/bin/grep -c "developer id enabled"
EOSRC
  )
  expected_result = "1"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-systemsettings-system_settings_gatekeeper_override_disallow" {
  name = "[mSCP] - System Settings - Configure Gatekeeper to Disallow End User Override"
  description = trimspace(<<EODESC
Gatekeeper _MUST_ be configured with a configuration profile to prevent normal users from overriding its settings.

If users are allowed to disable Gatekeeper or set it to a less restrictive setting, malware could be introduced into the system.
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.systempolicy.managed')\
.objectForKey('DisableOverride').js
EOS
EOSRC
  )
  expected_result = "true"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-systemsettings-system_settings_guest_access_smb_disable" {
  name = "[mSCP] - System Settings - Disable Guest Access to Shared SMB Folders"
  description = trimspace(<<EODESC
Guest access to shared Server Message Block (SMB) folders _MUST_ be disabled.

Turning off guest access prevents anonymous users from accessing files shared via SMB.
EODESC
  )
  type = "ZSH_BOOL"
  source = trimspace(<<EOSRC
/usr/bin/defaults read /Library/Preferences/SystemConfiguration/com.apple.smb.server AllowGuestAccess
EOSRC
  )
  expected_result = "0"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-systemsettings-system_settings_guest_account_disable" {
  name = "[mSCP] - System Settings - Disable the Guest Account"
  description = trimspace(<<EODESC
Guest access _MUST_ be disabled.

Turning off guest access prevents anonymous users from accessing files.
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
/usr/bin/osascript -l JavaScript << EOS
function run() {
  let pref1 = ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.MCX')\
.objectForKey('DisableGuestAccount'))
  let pref2 = ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.MCX')\
.objectForKey('EnableGuestAccount'))
  if ( pref1 == true && pref2 == false ) {
    return("true")
  } else {
    return("false")
  }
}
EOS
EOSRC
  )
  expected_result = "true"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-systemsettings-system_settings_hot_corners_disable" {
  name = "[mSCP] - System Settings - Disable Hot Corners"
  description = trimspace(<<EODESC
Hot corners _MUST_ be disabled.

The information system conceals, via the session lock, information previously visible on the display with a publicly viewable image. Although hot comers can be used to initiate a session lock or to launch useful applications, they can also be configured to disable an automatic session lock from initiating. Such a configuration introduces the risk that a user might forget to manually lock the screen before stepping away from the computer.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/usr/bin/profiles -P -o stdout | /usr/bin/grep -Ec '"wvous-bl-corner" = 0|"wvous-br-corner" = 0|"wvous-tl-corner" = 0|"wvous-tr-corner" = 0'
EOSRC
  )
  expected_result = "4"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-systemsettings-system_settings_improve_siri_dictation_disable" {
  name = "[mSCP] - System Settings - Disable Sending Siri and Dictation Information to Apple"
  description = trimspace(<<EODESC
The ability for Apple to store and review audio of your Siri and Dictation interactions _MUST_ be disabled.

The information system _MUST_ be configured to provide only essential capabilities. Disabling the submission of Siri and Dictation information will mitigate the risk of unwanted data being sent to Apple.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.assistant.support')\
.objectForKey('Siri Data Sharing Opt-In Status').js
EOS
EOSRC
  )
  expected_result = "2"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-systemsettings-system_settings_internet_accounts_disable" {
  name = "[mSCP] - System Settings - Disable the Internet Accounts System Preference Pane"
  description = trimspace(<<EODESC
The Internet Accounts System Setting _MUST_ be disabled to prevent the addition of unauthorized internet accounts.

[IMPORTANT]
====
Some organizations may allow the use and configuration of the built-in Mail.app, Calendar.app, and Contacts.app for organizational communication. Information System Security Officers (ISSOs) may make the risk-based decision not to disable the Internet Accounts System Preference pane to avoid losing this functionality, but they are advised to first fully weigh the potential risks posed to their organization.
====
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/usr/bin/profiles show -output stdout-xml | /usr/bin/xmllint --xpath '//key[text()="DisabledSystemSettings"]/following-sibling::*[1]' - | /usr/bin/grep -c com.apple.Internet-Accounts-Settings.extension
EOSRC
  )
  expected_result = "1"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-systemsettings-system_settings_internet_sharing_disable" {
  name = "[mSCP] - System Settings - Disable Internet Sharing"
  description = trimspace(<<EODESC
If the system does not require Internet sharing, support for it is non-essential and _MUST_ be disabled.

The information system _MUST_ be configured to provide only essential capabilities. Disabling Internet sharing helps prevent the unauthorized connection of devices, unauthorized transfer of information, and unauthorized tunneling.
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.MCX')\
.objectForKey('forceInternetSharingOff').js
EOS
EOSRC
  )
  expected_result = "true"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-systemsettings-system_settings_location_services_disable" {
  name = "[mSCP] - System Settings - Disable Location Services"
  description = trimspace(<<EODESC
Location Services _MUST_ be disabled.

The information system _MUST_ be configured to provide only essential capabilities.  Disabling Location Services helps prevent the unauthorized connection of devices, unauthorized transfer of information, and unauthorized tunneling.
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
/usr/bin/sudo -u _locationd /usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.locationd')\
.objectForKey('LocationServicesEnabled').js
EOS
EOSRC
  )
  expected_result = "false"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-systemsettings-system_settings_loginwindow_prompt_username_password_enforce" {
  name = "[mSCP] - System Settings - Configure Login Window to Prompt for Username and Password"
  description = trimspace(<<EODESC
The login window _MUST_ be configured to prompt all users for both a username and a password.

By default, the system displays a list of known users on the login window, which can make it easier for a malicious user to gain access to someone else's account. Requiring users to type in both their username and password mitigates the risk of unauthorized users gaining access to the information system.
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.loginwindow')\
.objectForKey('SHOWFULLNAME').js
EOS
EOSRC
  )
  expected_result = "true"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-systemsettings-system_settings_media_sharing_disabled" {
  name = "[mSCP] - System Settings - Disable Media Sharing"
  description = trimspace(<<EODESC
Media sharing _MUST_ be disabled.

When Media Sharing is enabled, the computer starts a network listening service that shares the contents of the user's music collection with other users in the same subnet.

The information system _MUST_ be configured to provide only essential capabilities. Disabling Media Sharing helps prevent the unauthorized connection of devices and the unauthorized transfer of information. Disabling Media Sharing mitigates this risk.

NOTE: The Media Sharing preference panel will still allow "Home Sharing" and "Share media with guests" to be checked but the service will not be enabled.
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
/usr/bin/osascript -l JavaScript << EOS
function run() {
  let pref1 = ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.preferences.sharing.SharingPrefsExtension')\
  .objectForKey('homeSharingUIStatus'))
  let pref2 = ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.preferences.sharing.SharingPrefsExtension')\
  .objectForKey('legacySharingUIStatus'))
  let pref3 = ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.preferences.sharing.SharingPrefsExtension')\
  .objectForKey('mediaSharingUIStatus'))
  if ( pref1 == 0 && pref2 == 0 && pref3 == 0 ) {
    return("true")
  } else {
    return("false")
  }
}
EOS
EOSRC
  )
  expected_result = "true"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-systemsettings-system_settings_password_hints_disable" {
  name = "[mSCP] - System Settings - Disable Password Hints"
  description = trimspace(<<EODESC
Password hints _MUST_ be disabled.

Password hints leak information about passwords that are currently in use and can lead to loss of confidentiality.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.loginwindow')\
.objectForKey('RetriesUntilHint').js
EOS
EOSRC
  )
  expected_result = "0"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-systemsettings-system_settings_personalized_advertising_disable" {
  name = "[mSCP] - System Settings - Disable Personalized Advertising"
  description = trimspace(<<EODESC
Ad tracking and targeted ads _MUST_ be disabled.

The information system _MUST_ be configured to provide only essential capabilities. Disabling ad tracking ensures that applications and advertisers are unable to track users' interests and deliver targeted advertisements.
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowApplePersonalizedAdvertising').js
EOS
EOSRC
  )
  expected_result = "false"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-systemsettings-system_settings_printer_sharing_disable" {
  name = "[mSCP] - System Settings - Disable Printer Sharing"
  description = trimspace(<<EODESC
Printer Sharing _MUST_ be disabled.
EODESC
  )
  type = "ZSH_BOOL"
  source = trimspace(<<EOSRC
/usr/sbin/cupsctl | /usr/bin/grep -c "_share_printers=0"
EOSRC
  )
  expected_result = "1"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-systemsettings-system_settings_rae_disable" {
  name = "[mSCP] - System Settings - Disable Remote Apple Events"
  description = trimspace(<<EODESC
If the system does not require Remote Apple Events, support for Apple Remote Events is non-essential and _MUST_ be disabled.

The information system _MUST_ be configured to provide only essential capabilities. Disabling Remote Apple Events helps prevent the unauthorized connection of devices, the unauthorized transfer of information, and unauthorized tunneling.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/bin/launchctl print-disabled system | /usr/bin/grep -c '"com.apple.AEServer" => disabled'
EOSRC
  )
  expected_result = "1"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-systemsettings-system_settings_remote_management_disable" {
  name = "[mSCP] - System Settings - Disable Remote Management"
  description = trimspace(<<EODESC
Remote Management _MUST_ be disabled.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/usr/libexec/mdmclient QuerySecurityInfo | /usr/bin/grep -c "RemoteDesktopEnabled = 0"
EOSRC
  )
  expected_result = "1"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-systemsettings-system_settings_screen_sharing_disable" {
  name = "[mSCP] - System Settings - Disable Screen Sharing and Apple Remote Desktop"
  description = trimspace(<<EODESC
Support for both Screen Sharing and Apple Remote Desktop (ARD) is non-essential and _MUST_ be disabled.

The information system _MUST_ be configured to provide only essential capabilities. Disabling screen sharing and ARD helps prevent the unauthorized connection of devices, the unauthorized transfer of information, and unauthorized tunneling.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/bin/launchctl print-disabled system | /usr/bin/grep -c '"com.apple.screensharing" => disabled'
EOSRC
  )
  expected_result = "1"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-systemsettings-system_settings_screensaver_ask_for_password_delay_enforce" {
  name = "[mSCP] - System Settings - Enforce Session Lock After Screen Saver is Started"
  description = trimspace(<<EODESC
A screen saver _MUST_ be enabled and the system _MUST_ be configured to require a password to unlock once the screensaver has been on for a maximum of 5 seconds.

An unattended system with an excessive grace period is vulnerable to a malicious user.
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
/usr/bin/osascript -l JavaScript << EOS
function run() {
  let delay = ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.screensaver')\
.objectForKey('askForPasswordDelay'))
  if ( delay <= 5 ) {
    return("true")
  } else {
    return("false")
  }
}
EOS
EOSRC
  )
  expected_result = "true"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-systemsettings-system_settings_screensaver_password_enforce" {
  name = "[mSCP] - System Settings - Enforce Screen Saver Password"
  description = trimspace(<<EODESC
Users _MUST_ authenticate when unlocking the screen saver.

The screen saver acts as a session lock and prevents unauthorized users from accessing the current user's account.
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.screensaver')\
.objectForKey('askForPassword').js
EOS
EOSRC
  )
  expected_result = "true"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-systemsettings-system_settings_screensaver_timeout_enforce" {
  name = "[mSCP] - System Settings - Enforce Screen Saver Timeout"
  description = trimspace(<<EODESC
The screen saver timeout _MUST_ be set to 1300 seconds or a shorter length of time.

This rule ensures that a full session lock is triggered within no more than 1300 seconds of inactivity.
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
/usr/bin/osascript -l JavaScript << EOS
function run() {
  let timeout = ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.screensaver')\
.objectForKey('idleTime'))
  if ( timeout <= 1300 ) {
    return("true")
  } else {
    return("false")
  }
}
EOS
EOSRC
  )
  expected_result = "true"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-systemsettings-system_settings_siri_disable" {
  name = "[mSCP] - System Settings - Disable Siri"
  description = trimspace(<<EODESC
Support for Siri is non-essential and _MUST_ be disabled.

The information system _MUST_ be configured to provide only essential capabilities.
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowAssistant').js
EOS
EOSRC
  )
  expected_result = "false"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-systemsettings-system_settings_siri_settings_disable" {
  name = "[mSCP] - System Settings - Disable the System Settings Pane for Siri"
  description = trimspace(<<EODESC
The System Settings pane for Siri _MUST_ be hidden.

Hiding the System Settings pane prevents the users from configuring Siri.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/usr/bin/profiles show -output stdout-xml | /usr/bin/xmllint --xpath '//key[text()="DisabledSystemSettings"]/following-sibling::*[1]' - | /usr/bin/grep -c com.apple.Siri-Settings.extension
EOSRC
  )
  expected_result = "1"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-systemsettings-system_settings_smbd_disable" {
  name = "[mSCP] - System Settings - Disable Server Message Block Sharing"
  description = trimspace(<<EODESC
Support for Server Message Block (SMB) file sharing is non-essential and _MUST_ be disabled.

The information system _MUST_ be configured to provide only essential capabilities.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/bin/launchctl print-disabled system | /usr/bin/grep -c '"com.apple.smbd" => disabled'
EOSRC
  )
  expected_result = "1"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-systemsettings-system_settings_ssh_enable" {
  name = "[mSCP] - System Settings - Enable SSH Server for Remote Access Sessions"
  description = trimspace(<<EODESC
Remote access sessions _MUST_ use encrypted methods to protect unauthorized individuals from gaining access.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/bin/launchctl print-disabled system | /usr/bin/grep -c '"com.openssh.sshd" => enabled'
EOSRC
  )
  expected_result = "1"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-systemsettings-system_settings_system_wide_preferences_configure" {
  name = "[mSCP] - System Settings - Require Administrator Password to Modify System-Wide Preferences"
  description = trimspace(<<EODESC
The system _MUST_ be configured to require an administrator password in order to modify the system-wide preferences in System Settings.

Some Preference Panes in System Settings contain settings that affect the entire system. Requiring a password to unlock these system-wide settings reduces the risk of a non-authorized user modifying system configurations.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
authDBs=("system.preferences" "system.preferences.energysaver" "system.preferences.network" "system.preferences.printing" "system.preferences.sharing" "system.preferences.softwareupdate" "system.preferences.startupdisk" "system.preferences.timemachine")
result="1"
for section in $${authDBs[@]}; do
  if [[ $(/usr/bin/security -q authorizationdb read "$section" | /usr/bin/xmllint -xpath 'name(//*[contains(text(), "shared")]/following-sibling::*[1])' -) != "false" ]]; then
    result="0"
  fi
  if [[ $(security -q authorizationdb read "$section" | /usr/bin/xmllint -xpath '//*[contains(text(), "group")]/following-sibling::*[1]/text()' - ) != "admin" ]]; then
    result="0"
  fi
  if [[ $(/usr/bin/security -q authorizationdb read "$section" | /usr/bin/xmllint -xpath 'name(//*[contains(text(), "authenticate-user")]/following-sibling::*[1])' -) != "true" ]]; then
    result="0"
  fi
  if [[ $(/usr/bin/security -q authorizationdb read "$section" | /usr/bin/xmllint -xpath 'name(//*[contains(text(), "session-owner")]/following-sibling::*[1])' -) != "false" ]]; then
    result="0"
  fi
done
echo $result
EOSRC
  )
  expected_result = "1"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-systemsettings-system_settings_time_server_configure" {
  name = "[mSCP] - System Settings - Configure macOS to Use an Authorized Time Server"
  description = trimspace(<<EODESC
Approved time server _MUST_ be the only server configured for use. As of macOS 10.13 only one time server is supported.

This rule ensures the uniformity of time stamps for information systems with multiple system clocks and systems connected over a network.
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.MCX')\
.objectForKey('timeServer').js
EOS
EOSRC
  )
  expected_result = "time.nist.gov"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-systemsettings-system_settings_time_server_enforce" {
  name = "[mSCP] - System Settings - Enforce macOS Time Synchronization"
  description = trimspace(<<EODESC
Time synchronization _MUST_ be enforced on all networked systems.

This rule ensures the uniformity of time stamps for information systems with multiple system clocks and systems connected over a network.
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.timed')\
.objectForKey('TMAutomaticTimeOnlyEnabled').js
EOS
EOSRC
  )
  expected_result = "true"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-systemsettings-system_settings_token_removal_enforce" {
  name = "[mSCP] - System Settings - Configure User Session Lock When a Smart Token is Removed"
  description = trimspace(<<EODESC
The screen lock _MUST_ be configured to initiate automatically when the smart token is removed from the system.

Session locks are temporary actions taken when users stop work and move away from the immediate vicinity of the information system but do not want to log out because of the temporary nature of their absences. While a session lock is not an acceptable substitute for logging out of an information system for longer periods of time, they prevent a malicious user from accessing the information system when a user has removed their smart token.

[IMPORTANT]
====
Information System Security Officers (ISSOs) may make the risk-based decision not to enforce a session lock when a smart token is removed, so as to maintain necessary workflow capabilities, but they are advised to first fully weigh the potential risks posed to their organization.
====
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.security.smartcard')\
.objectForKey('tokenRemovalAction').js
EOS
EOSRC
  )
  expected_result = "1"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-systemsettings-system_settings_touch_id_settings_disable" {
  name = "[mSCP] - System Settings - Disable the Touch ID System Settings Pane"
  description = trimspace(<<EODESC
The System Settings pane for Touch ID _MUST_ be disabled.

Disabling the System Settings pane prevents the users from configuring Touch ID.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/usr/bin/profiles show -output stdout-xml | /usr/bin/xmllint --xpath '//key[text()="DisabledSystemSettings"]/following-sibling::*[1]' - | /usr/bin/grep -c "com.apple.Touch-ID-Settings.extension"
EOSRC
  )
  expected_result = "1"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-systemsettings-system_settings_touchid_unlock_disable" {
  name = "[mSCP] - System Settings - Disable TouchID for Unlocking the Device"
  description = trimspace(<<EODESC
TouchID enables the ability to unlock a Mac system with a user's fingerprint.

TouchID _MUST_ be disabled for "Unlocking your Mac" on all macOS devices that are capable of using Touch ID.

The system _MUST_ remain locked until the user establishes access using an authorized identification and authentication method.

NOTE: TouchID is not an approved biometric authenticator for US Federal Government usage as it has not been verified to meet the strength requirements outlined in NIST SP 800-63.
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
/usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('allowFingerprintForUnlock').js
EOS
EOSRC
  )
  expected_result = "false"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-systemsettings-system_settings_usb_restricted_mode" {
  name = "[mSCP] - System Settings - USB Devices Must be Authorized Before Allowing"
  description = trimspace(<<EODESC
USB devices connected to a Mac _MUST_ be authorized.

[IMPORTANT]
====
This feature is removed if a smartcard is paired or smartcard attribute mapping is configured.
====
EODESC
  )
  type = "ZSH_STR"
  source = trimspace(<<EOSRC
/usr/bin/osascript -l JavaScript << EOS
  function run() {
    let pref1 = ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
  .objectForKey('allowUSBRestrictedMode'))
    if ( pref1 == false ) {
      return("false")
    } else {
      return("true")
    }
  }
EOS
EOSRC
  )
  expected_result = "true"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

resource "zentral_munki_script_check" "mcs-systemsettings-system_settings_wallet_applepay_settings_disable" {
  name = "[mSCP] - System Settings - Disable the System Settings Pane for Wallet and Apple Pay"
  description = trimspace(<<EODESC
The System Settings pane for Wallet and Apple Pay _MUST_ be disabled.

Disabling the System Settings pane prevents the users from configuring Wallet and Apple Pay.
EODESC
  )
  type = "ZSH_INT"
  source = trimspace(<<EOSRC
/usr/bin/profiles show -output stdout-xml | /usr/bin/xmllint --xpath '//key[text()="DisabledSystemSettings"]/following-sibling::*[1]' - | /usr/bin/grep -c "com.apple.WalletSettingsExtension"
EOSRC
  )
  expected_result = "1"
  arch_amd64      = true
  arch_arm64      = true
  min_os_version  = "14"
  max_os_version  = "15"
}

