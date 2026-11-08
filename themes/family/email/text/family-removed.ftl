<#ftl output_format="plainText">
<#-- Access to a domain has ended (FamilyRemoval): reason removed, moved, left or gone. -->
<#assign help = tenantHelp!msg("familyWhoeverInvited")>
${msg("familyRemoved_" + reason, domainName, help)}<#if disabled>

${msg("familyRemovedDeleted", deleteDays)}</#if>
