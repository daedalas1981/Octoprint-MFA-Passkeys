#!/usr/bin/env bash
set -euo pipefail

USER_HOME="${HOME}"
if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
  USER_HOME="$(getent passwd "$SUDO_USER" | cut -d: -f6)"
fi

OUTPUT_DIR="${USER_HOME}/.octoprint/data/mfa_passkeys"
mkdir -p "$OUTPUT_DIR"

echo "=========================================="
echo "OctoPrint Passkeys Setup & SSL Helper"
echo "=========================================="
echo "This script will help you find your existing SSL certificate,"
echo "or generate a new self-signed one if you don't have one."
echo "It will automatically place the certificates where the plugin"
echo "can access them, so you can easily download them from OctoPrint."
echo ""

# 3a. Check for SSL.
declare -a CANDIDATES=()
for candidate in \
  /etc/ssl/private/octopi.pem \
  /etc/ssl/snakeoil.pem \
  /etc/haproxy/haproxy.pem \
  /etc/haproxy/certs/octopi.pem \
  "$OUTPUT_DIR/octoprint-passkeys.pem"
do
  if [ -f "$candidate" ]; then
    CANDIDATES+=("$candidate")
  fi
done

SOURCE_PATH=""

# 3b. If SSL, check for .pem
if [ ${#CANDIDATES[@]} -gt 0 ]; then
  echo "Found the following existing SSL certificates:"
  for i in "${!CANDIDATES[@]}"; do
    echo "  $((i+1)). ${CANDIDATES[$i]}"
    if [[ "${CANDIDATES[$i]}" == *"/etc/ssl/snakeoil.pem"* ]] || [[ "${CANDIDATES[$i]}" == *"/etc/ssl/private/octopi.pem"* ]]; then
      echo "     ⚠️ NOTE: This is a default Pi certificate and likely LACKS a SAN. We highly recommend pressing 0 to generate a NEW one instead!"
    fi
  done
  echo ""
  read -r -p "Enter the number of the certificate you want to use (or 0 to generate a new one): " choice
  if [[ "$choice" -gt 0 && "$choice" -le "${#CANDIDATES[@]}" ]]; then
    SOURCE_PATH="${CANDIDATES[$((choice-1))]}"
  fi
fi

# 3c. If no SSL, Give a Yes / No to install SSL
if [ -z "$SOURCE_PATH" ]; then
  echo ""
  echo "No existing SSL certificate was selected or found."
  while true; do
    read -r -p "Would you like to generate a new self-signed SSL certificate now? [Y/n]: " yn
    case $yn in
      [Nn]* ) 
        echo "Exiting. You must have SSL configured to use passkeys securely."
        exit 1
        ;;
      * ) 
        break
        ;;
    esac
  done

  echo ""
  read -r -p "What hostname or IP do you use in Chrome? (Default: octopi.local): " USER_HOST
  if [ -z "$USER_HOST" ]; then
    USER_HOST="octopi.local"
  fi

  echo ""
  echo "Generating a new self-signed certificate for $USER_HOST..."
  
  # Note: Chrome requires Subject Alternative Names (SAN), not just CN.
  openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
    -keyout "$OUTPUT_DIR/octoprint-passkeys.key" \
    -out "$OUTPUT_DIR/octoprint-passkeys.crt" \
    -subj "/CN=$USER_HOST/O=OctoPrint Passkeys/C=US" \
    -addext "subjectAltName=DNS:$USER_HOST,DNS:octopi,DNS:localhost" 2>/dev/null

  # Combine into a .pem file for haproxy/octoprint
  cat "$OUTPUT_DIR/octoprint-passkeys.crt" "$OUTPUT_DIR/octoprint-passkeys.key" > "$OUTPUT_DIR/octoprint-passkeys.pem"
  
  SOURCE_PATH="$OUTPUT_DIR/octoprint-passkeys.pem"
  
  echo "✅ Certificate generated successfully at:"
  echo "  $SOURCE_PATH"
  echo ""
  
  if [ -f "/etc/haproxy/haproxy.cfg" ]; then
    read -r -p "We detected HAProxy. Do you want this script to automatically update your /etc/haproxy/haproxy.cfg to use the new cert? [Y/n]: " update_ha
    if [[ ! "$update_ha" =~ ^[Nn] ]]; then
      sudo cp /etc/haproxy/haproxy.cfg /etc/haproxy/haproxy.cfg.bak
      sudo sed -i "s|ssl crt /etc/ssl/snakeoil.pem|ssl crt $SOURCE_PATH|g" /etc/haproxy/haproxy.cfg
      sudo sed -i "s|ssl crt /etc/ssl/private/octopi.pem|ssl crt $SOURCE_PATH|g" /etc/haproxy/haproxy.cfg
      # Add a generic fallback catch-all for anything pointing to .pem or .crt if the above fail but do it safely by just warning if necessary.
      # Restarting HAProxy securely.
      sudo systemctl restart haproxy
      echo "✅ HAProxy updated and restarted! A backup was saved as haproxy.cfg.bak"
    else
      echo "Skipped HAProxy automatic update. If you use HAProxy, you may need to point your haproxy.cfg"
      echo "config manually to this new PEM file, then restart HAProxy."
    fi
  else
    echo "If you use HAProxy or another proxy, point it to this new PEM file."
  fi
  echo ""
fi

# 3d continued: get the .pem, and copy the .cer / .crt to where the plugin can access them.
CRT_PATH="$OUTPUT_DIR/trusted_origin_public.crt"
CER_PATH="$OUTPUT_DIR/trusted_origin_public.cer"

awk '/BEGIN CERTIFICATE/,/END CERTIFICATE/' "$SOURCE_PATH" > "$CRT_PATH"

if ! grep -q "BEGIN CERTIFICATE" "$CRT_PATH"; then
  echo "❌ Error: No public certificate block found in $SOURCE_PATH!" >&2
  exit 1
fi

# Extract .cer (DER format) using openssl
openssl x509 -in "$CRT_PATH" -out "$CER_PATH" -outform DER

echo "✅ Success! Certificates extracted and saved securely for the plugin."
echo "  PEM/CRT: $CRT_PATH"
echo "  DER/CER: $CER_PATH"
echo ""
echo "=========================================="
echo "Next Steps for the End-User:"
echo "=========================================="
echo "1. Go to the Passkeys Settings page in OctoPrint."
echo "2. Paste this exact path into 'Certificate source path':"
echo "     $SOURCE_PATH"
echo "3. Click 'Import public certificate'."
echo "4. Download the exported .cer via the provided link."
echo "5. On Windows, install the .cer into Trusted Root Certification Authorities."
echo "6. Fully restart your browser."
echo ""
