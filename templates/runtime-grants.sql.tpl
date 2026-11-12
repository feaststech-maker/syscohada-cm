-- Executed as the table owner after migrations. Role membership is configured by postgres.
REVOKE ALL ON DATABASE syscohada FROM PUBLIC;
GRANT CONNECT ON DATABASE syscohada TO syscohada_runtime;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO syscohada_runtime;
GRANT SELECT ON tenants, users, companies, fiscal_years, accounts, journals,
 entries, entry_lines, tax_adjustments, rule_sets, dgi_templates,
 financial_statements, attachments, audit_events, admin_settings TO syscohada_runtime;
GRANT INSERT, UPDATE ON companies, fiscal_years, accounts, journals, entries,
 entry_lines, tax_adjustments, financial_statements, attachments TO syscohada_runtime;
GRANT DELETE ON entry_lines, entries TO syscohada_runtime;
GRANT INSERT ON admin_settings TO syscohada_runtime;
GRANT UPDATE (remember_token, updated_at) ON users TO syscohada_runtime;
GRANT EXECUTE ON FUNCTION public.dsf_current_tenant(), public.dsf_current_actor() TO syscohada_runtime;
