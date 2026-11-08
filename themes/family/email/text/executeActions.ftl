<#ftl output_format="plainText">
<#-- The invitation (its link signs in); see html/executeActions.ftl. -->
<#assign intro = tenantIntro!((tenantName??)?then(msg("familyInviteIntroDefault", tenantName!""), msg("familyInviteIntroNeutral", realmName)))>
<#assign where = tenantHome!msg("familyInviteWhere")>
${msg("familyInviteBody", intro, link, linkExpirationFormatter(linkExpiration), where)}
