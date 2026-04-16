
# OctoPrint Passkeys

Passkey-first sign-in plugin for OctoPrint.

Developer: Robert Cole

## What this version changes

This build moves away from OctoPrint's MFA-only flow and adds a true **Sign in with a Passkey** button to the main login page. It keeps enrollment and management in **User Settings** and adds a clean **Settings → Passkeys** page for diagnostics, certificate import, and export.

## Features

- Passkey-first sign-in from the main login page
- Discoverable credential support so username can stay blank
- Username-assisted passkey sign-in when you want to narrow the prompt
- Enrollment and credential removal in User Settings
- Plugin Settings page with:
  - RP ID and origin overrides
  - HTTPS enforcement toggle
  - PEM certificate source path
  - public certificate import and `.cer` download
- Public certificate export helper for Windows trust workflows
- Python compatibility: 3.9 through 3.13

## Important setup notes

Passkeys require a secure browser context. In practice that means:

- `https://...` with a trusted certificate, or
- `http://localhost` for local development

If the browser reports a TLS certificate error, WebAuthn will be blocked even if the page still loads.

## Typical local HTTPS setup

If your HTTPS cert is stored in a PEM file such as:

- `/etc/ssl/snakeoil.pem`
- `/etc/haproxy/certs/octopi.pem`
- another HAProxy or reverse proxy PEM path

put that path into **Settings → Passkeys** and click **Import public certificate from source path**.

The plugin extracts only the public certificate and writes a safe downloadable copy into the plugin data folder.

## Windows trust workflow

1. Download the `.cer` from the plugin settings page.
2. Install it into **Local Computer → Trusted Root Certification Authorities**.
3. Fully restart Chrome or Edge.
4. Re-open your OctoPrint HTTPS URL and confirm the browser no longer shows a certificate warning.
5. Enroll a passkey, then use the main login page button.

## Linux trust workflow

The same public certificate can be used on Linux, but the system usually expects PEM/CRT format and trust-store installation steps. The plugin also exports a `.crt` PEM file if you prefer that path.

General pattern on Debian/Ubuntu style systems:

1. Copy the trusted public cert to a CA location.
2. Run `update-ca-certificates`.
3. Restart the browser.

## SSH and helper script

The zip includes `extras/setup_cert_helper.sh`.

What it does:

- checks common certificate locations
- inspects common web/proxy services
- can export a public `.cer` and `.crt` from a PEM source
- prints SSH status and the exact commands to enable SSH manually when needed

It does **not** silently enable SSH for the user.

## Enrolling a passkey

1. Log in normally once.
2. Open **User Settings → Passkeys**
3. Enter an optional friendly name.
4. Click **Enroll passkey**
5. Confirm with Windows Hello, Touch ID, security key, or another supported authenticator.

After that, the main login page button should work.

## Login behavior

- Leave username blank to try a discoverable passkey.
- Enter username if you want to narrow the browser prompt to one OctoPrint account.
- If normal login is still preferred, the standard OctoPrint username/password form remains untouched.

## Packaging

This plugin intentionally avoids storing private keys or serving the raw source PEM. It only stores a public certificate copy for download.

## Current repo placeholder

- GitHub release settings in the software update hook currently point at placeholder repo names and should be changed before public release.


## v0.2.4 notes

- Added more reliable login-page injection targeting OctoPrint's `#login-user` and `#login-password` fields.
- Changed the public-facing developer text to `Developer: Robert Cole`.
- Removed developer credit as an editable plugin setting.
- Expanded in-app certificate setup instructions, including SSH, PEM inspection, MMC, and certmgr guidance.
- Updated the helper script to guide the user interactively when no PEM path is supplied and to export into the invoking user's home directory by default.
