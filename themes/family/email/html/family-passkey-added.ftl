<#-- A passkey added after the first (PasskeyNotice): when, on what, and whom to contact if it
     was not them; the inviting domain's name and help contact when it has settings (TenantEmail:
     tenantName, tenantHelp), else neutral. -->
<#import "template.ftl" as layout>
<#assign contact = tenantHelp!((tenantName??)?then(msg("familyPasskeyContactDefault", tenantName!""), msg("familyPasskeyContactNeutral")))>
<@layout.emailLayout>
${kcSanitize(msg("familyPasskeyBodyHtml", tenantName!realmName, email, addedReadable, addedUtc, device, contact))?no_esc}
</@layout.emailLayout>
