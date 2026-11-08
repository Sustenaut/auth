<#-- Family: once per device, after a sign-in by email (link, code or invitation)
     (FamilyPasskeyOffer). "Set up" goes on to Keycloak's passkey setup (with its own "Not
     now"); "Not now" to the app. Either way this device is not asked again. -->
<#import "template.ftl" as layout>
<#import "buttons.ftl" as buttons>
<@layout.registrationLayout displayMessage=false; section>
<!-- template: family family-passkey-offer.ftl -->
    <#if section = "header">
        ${msg("familyPasskeyOfferTitle")}
    <#elseif section = "form">
        <p id="family-passkey-offer">${msg("familyPasskeyOfferText")}</p>
        <form id="kc-family-passkey-offer" class="${properties.kcFormClass!}" action="${url.loginAction}" method="post">
            <@buttons.actionGroup>
                <@buttons.button id="family-passkey-setup" name="setup" label="familyPasskeySetUp" />
                <@buttons.button id="family-passkey-not-now" name="notnow" label="familyPasskeyNotNow" type="secondary" />
            </@buttons.actionGroup>
        </form>
    </#if>
</@layout.registrationLayout>
