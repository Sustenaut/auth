// Waits for the wallet's answer to the QR code on login-oid4vp.ftl: polls the plugin's status
// endpoint, redeems the code on success and completes the login, and shows a message when the
// presentation was refused or the request expired.

const PERIOD_MS = 2500;
const MAX_FAILURES = 30;

function refused() {
  document.getElementById("sk-wallet-wait").style.display = "none";
  document.getElementById("sk-wallet-refused").style.display = "";
}

async function redeem(redeemUrl, transactionId, codeVerifier) {
  const response = await fetch(redeemUrl, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ transaction_id: transactionId, code_verifier: codeVerifier }),
  });
  if (response.status !== 200) throw new Error("code redemption failed");
  return (await response.json()).authorization_code;
}

export async function waitForWallet({ statusUrl, redeemUrl, transactionId, codeVerifier }, failures = 0) {
  const again = (n) => setTimeout(() => waitForWallet({ statusUrl, redeemUrl, transactionId, codeVerifier }, n), PERIOD_MS);
  if (failures >= MAX_FAILURES) return refused();
  try {
    const response = await fetch(statusUrl);
    if (response.status === 404) return refused(); // the request expired
    if (response.status !== 200) return again(failures + 1);
    const data = await response.json();
    if (data.status === "pending") return again(0);
    if (data.status !== "success") return refused();
    document.getElementById("kc-oid4vp-code-input").value = await redeem(redeemUrl, transactionId, codeVerifier);
    document.getElementById("kc-oid4vp-completion-form").submit();
  } catch {
    again(failures + 1);
  }
}
