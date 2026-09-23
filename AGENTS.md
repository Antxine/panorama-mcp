# Agent instructions

When the user shares a support ticket (ServiceNow excerpt) or asks to debug a blocked user, use the Panorama MCP server:

1. Call `start_ticket_diagnosis` first and follow the method it returns.
2. Start the evidence gathering with `diagnose_user_blocks`, then drill down with `diagnose_url_access`, `diagnose_threat_block` or `diagnose_flow`.
3. Never propose creating a URL category, object, rule or exception that already covers the need: the diagnose tools report what already exists.
4. The site named in the ticket is not necessarily the blocked one (uploads/storage/CDN/SSO on other domains).
5. The MCP server is read-only: describe changes for a human to apply in Panorama.
6. Answer in the language of the ticket.
