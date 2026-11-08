<#-- Family: passkeys only as the browser's suggestion in the email field (conditional UI).
     Keycloak's own macro (base/login/passkeys.ftl) also adds a "Sign in with a passkey"
     button that opens the browser's modal chooser; here there is no button and never a
     modal: mediation is always "conditional". -->
<#macro conditionalUIData>
    <#if enableWebAuthnConditionalUI?has_content>
        <form id="webauth" action="${url.loginAction}" method="post">
            <input type="hidden" id="clientDataJSON" name="clientDataJSON"/>
            <input type="hidden" id="authenticatorData" name="authenticatorData"/>
            <input type="hidden" id="signature" name="signature"/>
            <input type="hidden" id="credentialId" name="credentialId"/>
            <input type="hidden" id="userHandle" name="userHandle"/>
            <input type="hidden" id="error" name="error"/>
        </form>
        <script type="module">
           <#outputformat "JavaScript">
           import { initAuthenticate } from "${url.resourcesPath}/js/passkeysConditionalAuth.js";

           const args = {
               isUserIdentified : ${isUserIdentified},
               challenge : ${challenge?c},
               userVerification : ${userVerification?c},
               rpId : ${rpId?c},
               createTimeout : ${createTimeout?c},
               mediation : "conditional",
               authenticatorAttachment : ${authenticatorAttachment?c},
           };

           document.addEventListener("DOMContentLoaded", (event) => initAuthenticate({errmsg : ${msg("passkey-unsupported-browser-text")?c}, ...args}));
           </#outputformat>
        </script>
    </#if>
</#macro>
