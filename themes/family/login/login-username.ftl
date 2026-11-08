<#-- Family: one email field and "Email me a sign-in link": the email has a link and a code.
     Someone with a passkey on this device gets it offered in the field by the browser
     (conditional UI; passkeys.ftl here: no passkey button, no modal). No password, no
     registration, no reset (FamilySignInForm, extension/). -->
<#import "template.ftl" as layout>
<#import "field.ftl" as field>
<#import "buttons.ftl" as buttons>
<#import "passkeys.ftl" as passkeys>
<@layout.registrationLayout displayMessage=!messagesPerField.existsError('username') displayInfo=true; section>
<!-- template: family login-username.ftl -->
    <#-- The registered domain's settings (its client's sustenaut.tenant.* attributes), if any. -->
    <#assign tenantName = (client.attributes["sustenaut.tenant.displayName"])!"">
    <#assign tenantHelp = (client.attributes["sustenaut.tenant.helpContact"])!"">
    <#if section = "header">
        <#if tenantName?has_content>${msg("familySignInTo", tenantName)}<#else>${msg("loginAccountTitle")}</#if>
    <#elseif section = "form">
        <div id="kc-form">
            <div id="kc-form-wrapper">
                <form id="kc-form-login" class="${properties.kcFormClass!}" onsubmit="login.disabled = true; return true;" action="${url.loginAction}" method="post">
                    <#if !usernameHidden??>
                        <@field.input name="username" label=msg("email") value=login.username!'' autofocus=true
                            autocomplete="${(enableWebAuthnConditionalUI?has_content)?then('username webauthn', 'username')}" />
                    </#if>
                    <@buttons.actionGroup>
                        <@buttons.button id="kc-login" name="login" label="familyEmailMe" />
                    </@buttons.actionGroup>
                </form>
            </div>
        </div>
        <@passkeys.conditionalUIData />
    <#elseif section = "info">
        <p id="family-invite-only">${msg("familyInviteOnly")}<#if tenantHelp?has_content> ${msg("familyAsk", tenantHelp)}</#if></p>
    </#if>
</@layout.registrationLayout>
