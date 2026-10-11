-- Rename the one shared login application in place. Subjects use website ID,
-- not slug; group branding and domains never create identity namespaces.
UPDATE websites
SET slug = 'orgportal', name = 'OrgPortal',
    description = 'One OrgPortal account for all groups.'
WHERE slug = 'code-collective';
