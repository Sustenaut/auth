<#-- Sustenaut's QR page for a wallet sign-in (replaces the plugin's): the same QR code and
     same-device link, plus a visible message when the wallet's answer is refused. -->
<#import "template.ftl" as layout>
<#global auth = {}>
<@layout.registrationLayout displayMessage=false displayInfo=false; section>
<!-- template: sustenaut login-oid4vp.ftl -->
    <#if section = "header">
        ${msg('oid4vpScanPageTitle')}
    <#elseif section = "form">
        <div id="sk-wallet-wait">
            <div class="pf-v5-u-p-md pf-v5-u-text-align-center">
                <img src="${oid4vp.authContext.authReqQrCode}" style="max-width: 300px;" id="kc-oid4vp-qrcode" alt="QR code for your wallet" />
            </div>
            <div class="pf-v5-u-text-align-center">
                <p>${msg('oid4vpSameDevicePrompt')}</p>
                <p><a href="${oid4vp.authContext.authReqLink}" id="kc-oid4vp-link">${msg('oid4vpSameDeviceLinkLbl')}</a></p>
            </div>
        </div>
        <div id="sk-wallet-refused" role="alert" style="display:none;border-left:4px solid #c9190b;background:#faeae8;padding:12px 16px;white-space:normal;overflow-wrap:anywhere;">
            <p style="font-weight:600;margin:0 0 8px;">${msg('sustenautWalletRefused')}</p>
            <p style="margin:0 0 12px;">${msg('sustenautWalletRefusedHelp')}</p>
            <button type="button" class="pf-v5-c-button pf-m-primary" onclick="location.reload()">${msg('sustenautWalletRetry')}</button>
        </div>
        <form action="${oid4vp.loginActionUrl}" id="kc-oid4vp-completion-form" method="post" style="display:none;">
            <input type="hidden" id="kc-oid4vp-code-input" name="code" value="" />
        </form>
        <script type="module">
            import { waitForWallet } from "${url.resourcesPath}/js/wallet-wait.js";
            waitForWallet({
                statusUrl: "${oid4vp.authContext.authStatusUrl}",
                redeemUrl: "${oid4vp.authContext.authCodeRedemptionUrl}",
                transactionId: "${oid4vp.authContext.transactionId!""}",
                codeVerifier: "${oid4vp.authContext.codeVerifier!""}",
            });
        </script>
    </#if>
</@layout.registrationLayout>
