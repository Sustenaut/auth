<#-- The invitation (its link signs in: FamilyInviteSignIn), in the inviting domain's words
     when it has settings (TenantEmail: tenantName, tenantIntro, tenantHome); else neutral. -->
<#import "template.ftl" as layout>
<#assign intro = tenantIntro!((tenantName??)?then(msg("familyInviteIntroDefault", tenantName!""), msg("familyInviteIntroNeutral", realmName)))>
<#assign where = tenantHome!msg("familyInviteWhere")>
<@layout.emailLayout>
${kcSanitize(msg("familyInviteBodyHtml", intro, link, linkExpirationFormatter(linkExpiration), where))?no_esc}
</@layout.emailLayout>
