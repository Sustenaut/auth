<#-- Access to a domain has ended (FamilyRemoval); see text/family-removed.ftl. -->
<#import "template.ftl" as layout>
<#assign help = tenantHelp!msg("familyWhoeverInvited")>
<@layout.emailLayout>
${kcSanitize("<p>" + msg("familyRemoved_" + reason, domainName, help) + "</p>")?no_esc}
<#if disabled>${kcSanitize("<p>" + msg("familyRemovedDeleted", deleteDays) + "</p>")?no_esc}</#if>
</@layout.emailLayout>
