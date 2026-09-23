priority_map = {'low': '0', 'medium': '1', 'high': '2', 'urgent': '3'}
if priority not in priority_map:
    raise UserError("Priority must be one of: low, medium, high, urgent.")

subject = subject.strip()
description = description.strip()
if not subject or not description:
    raise UserError("Both 'subject' and 'description' must be non-empty.")

vals = {
    'name': subject[:200],
    'description': description,
    'priority': priority_map[priority],
}

if team.strip():
    team_rec = env['helpdesk.team'].search([('name', 'ilike', team.strip())], limit=1)
    if not team_rec:
        raise UserError("No helpdesk team matches '%s'." % team)
    vals['team_id'] = team_rec.id

if customer_email.strip():
    email = customer_email.strip().lower()
    partner = env['res.partner'].search([('email', '=ilike', email)], limit=1)
    vals.update({'partner_id': partner.id} if partner else {'partner_email': email})

ticket = env['helpdesk.ticket'].create(vals)
ai['result'] = "Created ticket #%s: %s (team: %s, priority: %s)" % (
    ticket.ticket_ref or ticket.id,
    ticket.name,
    ticket.team_id.name or 'none',
    priority,
)
