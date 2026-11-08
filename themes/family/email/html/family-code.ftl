<#import "template.ftl" as layout>
<@layout.emailLayout>
${kcSanitize(msg("familyCodeBodyHtml", code, tenantName!realmName, minutes, link))?no_esc}
</@layout.emailLayout>
