<#-- Family: after "Email me a sign-in link" (FamilySignInForm): open the email's link, or type
     its code here. The same page for every address, whether or not it has an account. -->
<#import "template.ftl" as layout>
<#import "field.ftl" as field>
<#import "buttons.ftl" as buttons>
<@layout.registrationLayout displayMessage=!messagesPerField.existsError('code') displayInfo=true; section>
<!-- template: family login-family-code.ftl -->
    <#if section = "header">
        ${msg("familyCodeTitle")}
    <#elseif section = "form">
        <p id="family-code-sent">${msg("familyCodeSent", familyEmail!'')}</p>
        <form id="kc-family-code-form" class="${properties.kcFormClass!}" onsubmit="login.disabled = true; return true;" action="${url.loginAction}" method="post">
            <@field.input name="code" label=msg("familyCodeLabel") autocomplete="one-time-code" autofocus=true />
            <@buttons.actionGroup>
                <@buttons.button id="kc-login" name="login" label="doLogIn" />
            </@buttons.actionGroup>
        </form>
        <form id="kc-family-code-other" action="${url.loginAction}" method="post">
            <@buttons.actionGroup horizontal=true>
                <@buttons.button id="family-resend" name="resend" label="familyCodeResend" type="secondary" fullWidth=false />
                <@buttons.button id="family-restart" name="restart" label="familyUseOtherEmail" type="link" fullWidth=false />
            </@buttons.actionGroup>
        </form>
    <#elseif section = "info">
        <#assign tenantHelp = (client.attributes["sustenaut.tenant.helpContact"])!"">
        <p>${msg("familyCodeHelp")} ${msg("familyAsk", tenantHelp?has_content?then(tenantHelp, msg("familyWhoeverInvited")))}</p>
    </#if>
</@layout.registrationLayout>
