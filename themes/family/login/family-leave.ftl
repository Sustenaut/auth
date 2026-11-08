<#-- Family: "Remove my access" (LeaveDomainAction, kc_action=sustenaut-leave). Says what goes;
     Keycloak's own cancel-aia button goes back with nothing changed. For someone the domain
     did not invite (leaveNothing), only that there is nothing to remove, and the way back. -->
<#import "template.ftl" as layout>
<#import "buttons.ftl" as buttons>
<@layout.registrationLayout displayInfo=false; section>
<!-- template: family family-leave.ftl -->
    <#if section = "header">
        ${msg("familyLeaveTitle", leaveName)}
    <#elseif section = "form" && leaveNothing>
        <p id="family-leave-nothing">${msg("familyLeaveNothing", leaveName)}</p>
        <form id="kc-family-leave-form" class="${properties.kcFormClass!}" action="${url.loginAction}" method="post">
            <@buttons.actionGroup>
                <@buttons.button id="family-leave-cancel" name="cancel-aia" label="familyLeaveBack" />
            </@buttons.actionGroup>
        </form>
    <#elseif section = "form">
        <p id="family-leave-what">${msg("familyLeaveWhat", leaveName)}</p>
        <#if leaveLast>
            <p id="family-leave-account">${msg("familyLeaveLast", leaveDays)}</p>
        <#else>
            <p id="family-leave-account">${msg("familyLeaveKept")}</p>
        </#if>
        <form id="kc-family-leave-form" class="${properties.kcFormClass!}" action="${url.loginAction}" method="post">
            <@buttons.actionGroup horizontal=true>
                <@buttons.button id="family-leave-confirm" name="confirm" label="familyLeaveConfirm" />
                <@buttons.button id="family-leave-cancel" name="cancel-aia" label="familyLeaveCancel" type="secondary" />
            </@buttons.actionGroup>
        </form>
    </#if>
</@layout.registrationLayout>
