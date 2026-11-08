<#-- The access page (AccessPage): people by service roles, for a controller; a refusal for anyone
     else. A page of its own, not the login card: the table needs the width. No script: every
     tick and button is a form with the session's token. -->
<#macro post path user="" role="">
    <form class="access-inline" method="post" action="${pageUrl}/${path}">
        <input type="hidden" name="csrf" value="${csrf}">
        <#if user?has_content><input type="hidden" name="user" value="${user}"></#if>
        <#if role?has_content><input type="hidden" name="role" value="${role}"></#if>
        <#nested>
    </form>
</#macro>
<#macro tick person key label held implied=false>
    <#if implied>
        <span class="access-tick access-implied" title="${msg("accessViaController")}">✓</span>
    <#elseif person.status == "removed">
        <span class="access-tick access-off">–</span>
    <#elseif held>
        <@post "revoke" person.id key><button class="access-tick access-held" data-role="${label}" title="${msg("accessTake", label, person.email)}" aria-label="${msg("accessTake", label, person.email)}">✓</button></@post>
    <#else>
        <@post "grant" person.id key><button class="access-tick" data-role="${label}" title="${msg("accessGive", label, person.email)}" aria-label="${msg("accessGive", label, person.email)}">·</button></@post>
    </#if>
</#macro>
<!doctype html>
<html class="login-pf access-page" lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="robots" content="noindex, nofollow">
    <#-- Keycloak's header, no-referrer, would have browsers post Origin: null (AccessPage checks it). -->
    <meta name="referrer" content="same-origin">
    <title>${msg("accessTitle")}</title>
    <link rel="stylesheet" href="${url.resourcesPath}/css/sustenaut.css">
    <link rel="stylesheet" href="${url.resourcesPath}/css/team-access.css">
</head>
<body>
<main class="access-main">
    <header class="access-header">
        <h1>${msg("accessTitle")}</h1>
        <p>${msg("accessSignedInAs", signedInAs)} · <a id="access-sign-out" href="${signOutUrl}">${msg("accessSignOut")}</a></p>
    </header>
<#if refused>
    <p id="access-refused">${msg("accessRefused", signedInAs)}</p>
<#else>
    <#if done?has_content><p id="access-done" role="status">${msg("accessDone_" + done)}</p></#if>
    <div class="access-scroll">
    <table id="access-table">
        <thead><tr>
            <th scope="col">${msg("accessPerson")}</th>
            <th scope="col">${msg("accessStatus")}</th>
            <th scope="col" class="access-role" title="${msg("accessControllerNote")}">${msg("accessController")}</th>
            <#list columns as column><th scope="col" class="access-role" title="${column.domain}">${column.label}</th></#list>
        </tr></thead>
        <tbody>
        <#list people as person>
            <tr data-email="${person.email}" data-status="${person.status}">
                <th scope="row">${person.email}<#if person.name?has_content><br><span class="access-name">${person.name}</span></#if></th>
                <td><span class="access-status access-${person.status}">${msg("access" + person.status?cap_first)}</span><#if person.deleteOn?has_content><br><span class="access-name">${msg("accessDeleteOn", person.deleteOn)}</span></#if></td>
                <td class="access-cell"><#if person.id == me><span class="access-tick access-implied" data-role="controller" title="${msg("accessDone_notYourself")}">✓</span><#else><@tick person "controller" "controller" person.controller /></#if></td>
                <#list person.ticks as cell><td class="access-cell"><@tick person cell.key cell.label cell.held person.controller /></td></#list>
            </tr>
            <tr class="access-history-row" data-history="${person.email}"><td colspan="${columns?size + 3}"><div class="access-below">
                <div class="access-actions">
                    <#if person.status == "removed">
                        <@post "restore" person.id><button class="access-button" data-action="restore">${msg("accessPutBack")}</button></@post>
                    <#else>
                        <@post "resend" person.id><button class="access-button" data-action="resend">${msg("accessResend")}</button></@post>
                        <#if person.id != me><@post "remove" person.id><button class="access-button access-danger" data-action="remove" title="${msg("accessRemoveAllHint")}">${msg("accessRemoveAll")}</button></@post></#if>
                    </#if>
                </div>
                <details><summary>${msg("accessHistory")}</summary>
                <#if person.history?has_content>
                    <ul><#list person.history as line><li>${line.when}: ${line.what} (${line.by})</li></#list></ul>
                <#else><p>${msg("accessNoHistory")}</p></#if>
                </details>
            </div></td></tr>
        </#list>
        </tbody>
    </table>
    </div>

    <section class="access-forms">
    <form id="access-invite" class="access-form" method="post" action="${pageUrl}/invite">
        <h2>${msg("accessInviteTitle")}</h2>
        <input type="hidden" name="csrf" value="${csrf}">
        <label>${msg("accessEmail")} <input type="email" name="email" required autocomplete="off"></label>
        <label>${msg("accessFirstName")} <input type="text" name="first_name" maxlength="80" autocomplete="off"></label>
        <label>${msg("accessLastName")} <input type="text" name="last_name" maxlength="80" autocomplete="off"></label>
        <fieldset><#list columns as column><label class="access-check"><input type="checkbox" name="role" value="${column.key}"> ${column.label}</label></#list></fieldset>
        <button class="access-button">${msg("accessInviteSend")}</button>
        <p class="access-name">${msg("accessInviteHint")}</p>
    </form>
    <form id="access-declare" class="access-form" method="post" action="${pageUrl}/declare">
        <h2>${msg("accessDeclareTitle")}</h2>
        <input type="hidden" name="csrf" value="${csrf}">
        <#if domains?size == 1><input type="hidden" name="domain" value="${domains[0]}">
        <#else><label>Domain <select name="domain"><#list domains as domain><option>${domain}</option></#list></select></label></#if>
        <label>${msg("accessDeclareName")} <input type="text" name="name" required maxlength="64" pattern="[a-z][a-z0-9\-]*(:[a-z][a-z0-9\-]*)?" autocomplete="off"></label>
        <button class="access-button">${msg("accessDeclareSend")}</button>
        <p class="access-name">${msg("accessDeclareHint")}</p>
    </form>
    </section>

    <section id="access-registrants">
        <h2>${msg("accessRegistrants")}</h2>
        <p class="access-name">${msg("accessRegistrantsNote")}</p>
        <ul><#list registrants as person><li>${person.email}</li></#list></ul>
    </section>
</#if>
</main>
</body>
</html>
