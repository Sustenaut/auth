<#-- Family: the email's "Sign me in" link opened somewhere other than the browser that asked
     (FamilyLinkHandler): the code to type there, in large digits; this device is not signed
     in. Without familyLinkCode: the link no longer works (used, replaced or expired). -->
<#import "template.ftl" as layout>
<@layout.registrationLayout displayMessage=false; section>
<!-- template: family login-family-link.ftl -->
    <#if section = "header">
        <#if familyLinkCode??>${msg("familyLinkCodeTitle")}<#else>${msg("familyLinkUsedTitle")}</#if>
    <#elseif section = "form">
        <#if familyLinkCode??>
            <p id="family-link-code" style="font-size:3em;font-weight:bold;letter-spacing:0.25em;text-align:center;margin:0.5em 0;">${familyLinkCode}</p>
            <p id="family-link-where">${msg("familyLinkTypeThis")}</p>
            <p id="family-link-not-here">${msg("familyLinkNotHere")}</p>
        <#else>
            <p id="family-link-used">${msg("familyLinkUsed")}</p>
        </#if>
    </#if>
</@layout.registrationLayout>
