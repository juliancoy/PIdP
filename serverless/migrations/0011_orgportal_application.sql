-- Rename the shared application's display identity without changing its ID,
-- slug, subjects, credentials, or account links.
UPDATE websites
SET name = 'OrgPortal',
    description = 'Shared member identity for OrgPortal and its communities.'
WHERE slug = 'code-collective';

UPDATE websites
SET login_hosts = json_insert(login_hosts, '$[#]', 'orgportal.cc')
WHERE slug = 'code-collective'
  AND NOT EXISTS (SELECT 1 FROM json_each(websites.login_hosts) WHERE value = 'orgportal.cc');

UPDATE websites
SET allowed_redirect_origins = json_insert(allowed_redirect_origins, '$[#]', 'https://orgportal.cc')
WHERE slug = 'code-collective'
  AND NOT EXISTS (SELECT 1 FROM json_each(websites.allowed_redirect_origins) WHERE value = 'https://orgportal.cc');
