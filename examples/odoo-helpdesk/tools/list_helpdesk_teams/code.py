teams = env['helpdesk.team'].search([])
ai['result'] = "\n".join("- %s" % t.name for t in teams) or "No helpdesk teams available."
