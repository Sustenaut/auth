<#-- Sustenaut: wallet only. The parent theme puts the wallet buttons under a
     username/password form; here the buttons are the whole page. There are no
     passwords, no registration and no reset flow. -->
<#import "template.ftl" as layout>
<#import "social-providers.ftl" as identityProviders>
<@layout.registrationLayout displayMessage=true displayInfo=false; section>
<!-- template: sustenaut login-default.ftl -->
    <#if section = "header">
        ${msg("loginAccountTitle")}
    <#elseif section = "form">
        <#if !(oid4vp?? && oid4vp.loginProfiles?? && oid4vp.loginProfiles?has_content)>
            <p id="kc-no-wallet-profile">Wallet sign-in is not available for this application.</p>
        </#if>
    <#elseif section = "socialProviders">
        <#if oid4vp?? && oid4vp.loginProfiles?? && oid4vp.loginProfiles?has_content>
            <@identityProviders.show social=social/>
        </#if>
        <#-- AGPL-3.0 section 13: offer the source of the modified plugin to everyone who uses it. -->
        <p id="sk-plugin-source" style="font-size:0.8em;margin-top:1.5em;">${msg('sustenautPluginSource')}
            <a href="${url.resourcesPath}/plugin-source/README.txt">${msg('sustenautPluginSourceLink')}</a></p>
    </#if>
</@layout.registrationLayout>
