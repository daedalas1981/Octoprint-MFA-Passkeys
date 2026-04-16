#!/usr/bin/env bash
set -euo pipefail

SOURCE_PATH="${1:-}"

if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
  USER_HOME="$(getent passwd "$SUDO_USER" | cut -d: -f6)"
else
  USER_HOME="${HOME}"
fi

OUTPUT_DIR="${2:-$USER_HOME/octoprint-passkeys-export}"

echo "OctoPrint Passkeys helper"
echo

echo "Checking SSH or console access..."
if [ -n "${SSH_CONNECTION:-}" ] || [ -n "${SSH_TTY:-}" ]; then
  echo "  SSH session detected."
elif command -v systemctl >/dev/null 2>&1; then
  if systemctl list-unit-files 2>/dev/null | grep -Eq '^(ssh|sshd)\.service'; then
    echo "  SSH service appears to be installed."
  else
    echo "  SSH service was not detected."
    echo "  If you need remote access, common Raspberry Pi commands are:"
    echo "    sudo apt update && sudo apt install -y openssh-server"
    echo "    sudo systemctl enable --now ssh"
  fi
else
  echo "  Could not detect SSH status. Local prompt access is still fine."
fi

echo
echo "Trying to locate likely certificate sources..."
declare -a CANDIDATES=()
for candidate in \
  /etc/ssl/private/octopi.pem \
  /etc/ssl/snakeoil.pem \
  /etc/haproxy/haproxy.pem \
  /etc/haproxy/certs/octopi.pem
do
  if [ -f "$candidate" ]; then
    echo "  Found: $candidate"
    CANDIDATES+=("$candidate")
  fi
done

if [ -z "$SOURCE_PATH" ]; then
  echo
  if [ "${#CANDIDATES[@]}" -eq 1 ]; then
    SOURCE_PATH="${CANDIDATES[0]}"
    echo "Using the only detected certificate source:"
    echo "  $SOURCE_PATH"
  elif [ "${#CANDIDATES[@]}" -gt 1 ]; then
    echo "Choose the PEM source path to export from:"
    select choice in "${CANDIDATES[@]}"; do
      if [ -n "${choice:-}" ]; then
        SOURCE_PATH="$choice"
        break
      fi
      echo "Please pick one of the listed options."
    done
  else
    read -r -p "Enter the full path to the PEM file used for HTTPS: " SOURCE_PATH
  fi
fi

if [ ! -f "$SOURCE_PATH" ]; then
  echo "Source file not found: $SOURCE_PATH" >&2
  exit 1
fi

mkdir -p "$OUTPUT_DIR"

CRT_PATH="$OUTPUT_DIR/octoprint-passkeys.crt"
CER_PATH="$OUTPUT_DIR/octoprint-passkeys.cer"

awk '/BEGIN CERTIFICATE/,/END CERTIFICATE/' "$SOURCE_PATH" > "$CRT_PATH"

if ! grep -q "BEGIN CERTIFICATE" "$CRT_PATH"; then
  echo "No public certificate block found in $SOURCE_PATH" >&2
  exit 1
fi

openssl x509 -in "$CRT_PATH" -out "$CER_PATH" -outform DER

echo
echo "Exported:"
echo "  PEM/CRT: $CRT_PATH"
echo "  DER/CER: $CER_PATH"

echo
echo "Quick verification:"
openssl x509 -in "$CRT_PATH" -text -noout | grep -E "Subject:|DNS:|IP Address:" || true

echo
echo "What to do next:"
echo "  1. In the plugin Settings page, paste this PEM path:"
echo "       $SOURCE_PATH"
echo "  2. Click 'Import public certificate from source path'."
echo "  3. On Windows, import the .cer into Local Computer -> Trusted Root Certification Authorities."
echo "  4. Restart Chrome or Edge fully before testing passkeys."

echo
echo "Windows trust hint:"
echo "  Win + R -> mmc"
echo "  File -> Add/Remove Snap-in -> Certificates -> Computer account -> Local computer"
echo "  Trusted Root Certification Authorities -> Certificates -> All Tasks -> Import"

echo
echo "Linux trust hint:"
echo "  sudo cp \"$CRT_PATH\" /usr/local/share/ca-certificates/octoprint-passkeys.crt"
echo "  sudo update-ca-certificates"
