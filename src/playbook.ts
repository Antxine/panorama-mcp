/**
 * Troubleshooting knowledge given to the model (server instructions, prompt and resource).
 * Keep it factual and actionable: the model relies on it to avoid naive conclusions.
 */

export const SERVER_INSTRUCTIONS = `Read-only troubleshooting assistant for Palo Alto firewalls managed by Panorama.
Logs are queried on Panorama; live state (User-ID, sessions, GlobalProtect, test commands) is proxied to a managed firewall with the 'device' parameter.

Method for a ticket (a user is blocked / something does not work):
1. Extract facts: user, source IP, device/site, URL or destination, action attempted (browse, upload, download, app), time.
2. Start with diagnose_user_blocks (user or IP, reported_url, incident_time). It covers every log type and flags blocks on OTHER domains at the same time.
3. Drill down with diagnose_url_access, diagnose_threat_block or diagnose_flow depending on the layer found.
4. Conclude with: root cause (facts from tool output), confidence, the minimal fix, and what to verify after.

Rules:
- Always check what already exists before proposing a change. Never propose creating a URL category, object, rule or exception that already covers the need: propose fixing/using the existing one instead (add the missing entry, reference the category in the right rule, fix the rule order/user/zone...).
- Separate observed facts (quote the log/rule) from hypotheses. Do not invent rule, profile or category names.
- The site in the ticket is not necessarily the blocked one: uploads, storage, CDN, APIs and SSO often live on other domains.
- No log does not mean no block: see the visibility pitfalls in the playbook (resource panorama://playbook).
- Evidence must belong to the ticket's user. If you use logs of other users (found by URL or application), say so explicitly and confirm the user's identity or IP.
- Before naming a profile group, profile, category, application, schedule or tag in a proposal, check that it exists (find_objects / resolve_application). Base new exception rules on the existing ones returned as existing_exception_rules (same device group, position before the enforcing rule, same profile group, schedule and naming convention, ticket number in description).
- Keep log windows short: use incident_time (+/-30 min) or last-24-hrs. 30-day searches time out.
- This server is read-only: describe changes for a human to apply in Panorama, then commit and push.
- Consult the playbook resource for less common cases.`;

/** Method and answer format for a ticket; exposed as a tool because not every MCP client supports prompts. */
export const TICKET_METHOD = `Ticket diagnosis method:
1. List the facts from the ticket: user (email or name; ad_lookup_user gives the logged identities and AD groups), IP, requested site/URL, block page URL and category if a screenshot is described, action attempted (browse, upload, download, app), time, location (office, Citrix, GlobalProtect). Say which ones are missing.
2. Run diagnose_user_blocks with what you have: user and/or src_ip, reported_url, blocked_url, incident_time. If it returns need_identity, pick the identity or ask the human.
3. Drill down on the blocking layer: diagnose_url_access (URL filtering), diagnose_threat_block (files, signatures), diagnose_flow (policy deny, App-ID, apps like GenAI). Use resolve_application and find_objects to check names. Read get_troubleshooting_playbook if the cause is unclear.
4. Answer in the ticket's language with these sections: Summary / Evidence (quote logs and rules, say whose logs they are) / Root cause (confidence level) / Recommended fix (minimal; extend an existing exception rule or copy its pattern; only objects verified to exist; device group and position) / Risk / What to ask the user if data is missing.
Never propose creating something that already covers the need. If the reported site is not the blocked one, say so explicitly.`;

export const PLAYBOOK = `# Panorama troubleshooting playbook

## Visibility pitfalls (no log does not mean no block)
- A rule without a log forwarding profile does not send its logs to Panorama. Check \`log_forwarding\` in find_security_rules output.
- interzone-default / intrazone-default do not log by default. A silent deny often means that no explicit rule matched.
- URL filtering does not log categories whose action is 'allow'. Only alert/block/continue/override show up.
- Log times are in Panorama's timezone, and forwarding can lag. Widen the window before concluding.
- User names differ between sources and log searches need the exact identity:
  - GlobalProtect and Prisma Access users are logged by UPN (name@domain, external users often name-external@domain).
  - Citrix and AD-mapped users are logged as DOMAIN\\id (for example emea\\u123456) behind shared Citrix IPs.
  - ad_lookup_user (when available) turns an email or display name into every log identity and lists the user's AD groups; diagnose_user_blocks uses it automatically.
  - Without AD, run diagnose_user_blocks with blocked_url or reported_url: it lists the identities seen for that URL. Otherwise ask for the ID or the source IP.
- Group-based rules: ad_user_rules lists the rules targeting the user through their AD groups (nested included) and, with 'contains', the relevant rules reserved to other groups with the group the user lacks. The usual fix is then adding the user to the existing group (identity team), not a new rule.
- Groups in rules may come from the Cloud Identity Engine (Entra DN like CN=...,DC=tenant,DC=onmicrosoft,DC=com); cloud-only groups are not visible in on-prem AD.

## Third-party dependencies (ABC.com works but upload fails)
- Web apps call other domains for uploads, storage, APIs, CDN, auth: S3, Azure Blob, GCS, CloudFront, Akamai, SharePoint, OneDrive, Box, Dropbox, and Okta/Entra ID for SSO.
- Look for blocks on other domains around the incident time (diagnose_user_blocks with reported_url).
- Fix the dependency (category, rule, file-blocking), not the reported site.
- When logs are not enough, ask the user for the DevTools Network tab (failed or red requests) or a HAR file, then analyze those domains.

## URL filtering
- Before creating a custom category, run url_category_find. The URL may already be covered.
- If it is covered but still blocked, one of these explains it:
  1. The category is not referenced by the rule that should allow it, or is referenced in a rule placed after a blocking rule.
  2. The URL filtering profile of the matching rule blocks another category the URL also belongs to. Custom categories take precedence over PAN-DB. Across several matched custom categories, the most restrictive action wins.
  3. The entry pattern does not match. 'example.com/' does not match 'www.example.com': it needs '*.example.com/'. A pattern without a trailing '/' also matches 'example.com.evil.net'.
  4. The config was not pushed. Check the device's policy_sync, which shows 'Out of Sync' when a push is pending.
- A security rule with a URL category in its 'category' field matches only traffic of that category. The same category in a URL filtering profile sets an action instead: two different mechanisms.
- 'Category Match' custom categories match only when the URL belongs to ALL listed PAN-DB categories.
- Without decryption, the category is derived from the SNI or certificate only. Path-based entries (example.com/path) cannot match HTTPS traffic that is not decrypted.
- 'not-resolved' means the PAN-DB cloud lookup failed (firewall reachability or DNS). 'unknown' means the site is not categorized yet.
- Risk categories (high-risk, newly-registered-domain) are often blocked in addition to the main category.
- The fix for a miscategorized site is a recategorization request at Palo Alto's Test A Site portal. A custom category is only a workaround.
- Credential phishing detection (credential-enforcement) can block form submission while browsing still works.

## Files: false positives and uploads
- virus / wildfire-virus / ml-virus: an antivirus or WildFire signature matched. Check the WildFire verdict with search_logs log_type=wildfire and the file hash.
  - For a false positive, request a verdict change from Palo Alto first.
  - A threat exception by threat ID in the antivirus profile actually applied is the workaround.
  - Check first whether that exception already exists.
- WildFire submission logs with a malware verdict do not block by themselves. Blocking comes later from signatures.
- file subtype: a file-blocking profile matched on file type, direction (upload or download) and application.
  - 'continue' works only in browsers and breaks sync clients and APIs.
- Upload blocked while download works: check, in this order:
  1. file-blocking rules with direction upload/both
  2. application functions such as '*-uploading', '*-posting' or '*-file-transfer' that no allow rule permits for that user or group (App-ID shifts from the base application)
  3. data filtering
  4. vulnerability signatures on the upload request (false positives on forms and multipart bodies)
- Exceptions only work in the profile the matching rule uses, directly or through its profile group. An exception added to another profile has no effect.

## Security policy
- Evaluation order: shared pre-rules, parent device group pre-rules, device group pre-rules, then local firewall rules (invisible from Panorama), then post-rules (device group, then parent, then shared), then default rules.
- Rules can target specific firewalls (target devices), be disabled, or have an expired schedule.
- App-ID shift: a rule allowing 'ssl' or 'web-browsing' does not allow the specific application App-ID identifies later. Allow the application and its dependencies.
- The 'application-default' service only allows the application's standard ports. The same application on a non-standard port is denied.
- NAT: security rules use the pre-NAT IP addresses and the post-NAT destination zone.
- Rules based on users or groups require a User-ID mapping for the source IP. Common reasons it fails:
  - Terminal servers or Citrix without the Terminal Server agent
  - stale mapping after DHCP or VPN changes
  - group not in the group include list
  - group mapping not refreshed after an AD change
- Rules with a HIP profile require GlobalProtect HIP data. hipmatch logs show whether the host matched.

## Prisma Access
- Logs from device_name 'GP cloud service' (mobile users) or 'RN-...' (remote networks) come from Prisma Access, not from managed firewalls.
- Their policies come from the Prisma device groups (Mobile_User_Device_Group, Remote_Network_Device_Group) and what those groups inherit.
- Live commands (User-ID lookup, test security-policy-match, sessions) are not available. Rely on logs and config.

## Applications
- A rule's application field can hold a custom application, an application group or an application filter.
- Use resolve_application to see which one it is, and why an App-ID falls into a deny rule (for example a GenAI filter).
- Allow exceptions must use the specific App-ID seen in the logs, not the whole group or filter.

## Other layers
- Decryption errors (decryption logs, session_end_reason decrypt-*): certificate pinning, mutual TLS, or unsupported ciphers. The fix is a targeted no-decrypt rule.
- DNS Security or DNS signatures sinkhole answers. The user sees a DNS or connectivity error, not a block page. Anti-spyware logs show it.
- EDLs (external dynamic lists) can block IPs, domains or URLs. Check them with edl_lookup.
- Zone protection: 'reject non-SYN TCP' combined with asymmetric routing drops sessions (threat subtype packet, flood or scan).
- app 'incomplete' or 'insufficient-data', and sessions aged out with 0 bytes received: the server never answered. It is a routing, NAT or remote-side issue, not a policy block.
- GlobalProtect issues: globalprotect logs (stage, error), gp_current_users, HIP.
`;
