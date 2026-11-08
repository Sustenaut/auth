Source of the wallet sign-in plugin running on auth.sustenaut.eu
================================================================

The wallet sign-in uses keycloak-oid4vp-plugin by ADORSYS GIS, licensed under the
GNU Affero General Public License v3.0 (AGPL-3.0-only):

  https://github.com/ADORSYS-GIS/keycloak-oid4vp-plugin

We run commit a29bdc51b6d23071690caed03b60a33e928e5c8d (upstream pull request #210)
with the patches listed below applied, and no other change. Each patch is
published next to this file:

  0001-run-required-actions-after-wallet-sign-in.patch
      After a wallet sign-in, continue with the realm's required actions instead
      of redirecting straight back to the application.

  0002-record-the-wallet-profile-of-a-sign-in.patch
      Record which authentication profile the wallet answered (for example the
      PID or the Sustenaut member credential), so the login's required actions
      can tell them apart.

The complete corresponding source is that commit plus these patches.
