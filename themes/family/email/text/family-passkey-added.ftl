<#ftl output_format="plainText">
<#-- A passkey added after the first (PasskeyNotice); see html/family-passkey-added.ftl. -->
<#assign contact = tenantHelp!((tenantName??)?then(msg("familyPasskeyContactDefault", tenantName!""), msg("familyPasskeyContactNeutral")))>
${msg("familyPasskeyBody", tenantName!realmName, email, addedReadable, addedUtc, device, contact)}
