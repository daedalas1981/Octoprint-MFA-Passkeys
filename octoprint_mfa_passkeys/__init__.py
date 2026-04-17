
import base64
import datetime
import json
import os
import re
import ssl
import secrets
import threading
import time
from typing import Any, Dict, Optional, Tuple

import octoprint.plugin
import octoprint.server
import octoprint.util.net as util_net
from flask import abort, current_app, g, jsonify, make_response, request, send_file, session
from flask_babel import gettext
from flask_login import current_user, login_user
from octoprint.access import auth_log
from octoprint.access.permissions import Permissions
from octoprint.events import Events, eventManager
from octoprint.server.util import LoginMechanism
from octoprint.server.util.flask import (
    ensure_credentials_checked_recently,
    session_signature,
    to_api_credentials_seen,
)
from octoprint.vendor.flask_principal import Identity, identity_changed
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import (
    base64url_to_bytes,
    parse_authentication_credential_json,
    parse_registration_credential_json,
)
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

CEREMONY_TTL_SECONDS = 5 * 60
PUBLIC_CERT_DER_FILENAME = "trusted_origin_public.cer"
PUBLIC_CERT_PEM_FILENAME = "trusted_origin_public.crt"


class PasskeysPlugin(
    octoprint.plugin.AssetPlugin,
    octoprint.plugin.BlueprintPlugin,
    octoprint.plugin.SettingsPlugin,
    octoprint.plugin.TemplatePlugin,
):
    def __init__(self):
        self._data_lock = threading.RLock()
        self._data = {"users": {}}
        self._ceremonies = {}

    def initialize(self):
        self._load_data()

        try:
            import stat
            import shutil
            data_folder = self.get_plugin_data_folder()
            script_src = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scripts", "setup_cert_helper.sh")
            script_dst = os.path.join(data_folder, "setup_cert_helper.sh")
            if os.path.exists(script_src):
                shutil.copy2(script_src, script_dst)
                st = os.stat(script_dst)
                os.chmod(script_dst, st.st_mode | stat.S_IEXEC)
        except Exception as e:
            self._logger.warning(f"Could not deploy setup_cert_helper.sh: {e}")

        try:
            import ssl
            pem_text = ssl.get_server_certificate(("127.0.0.1", 443))
            if pem_text:
                cert_pem = self._extract_first_certificate_pem(pem_text)
                if cert_pem:
                    with open(self._public_cert_pem_file, "w", encoding="utf-8") as f:
                        f.write(cert_pem)
                    with open(self._public_cert_der_file, "wb") as f:
                        f.write(ssl.PEM_cert_to_DER_cert(cert_pem))
        except Exception:
            pass

        import octoprint.server
        @octoprint.server.app.after_request
        def inject_passkeys_login(response):
            from flask import request
            if request.path.rstrip("/") == "/login" and "text/html" in response.headers.get("Content-Type", ""):
                html = response.get_data(as_text=True)
                if 'id="login-user"' in html and 'passkeys-login-bootstrap' not in html:
                    plugin_url = self._plugin_url("")
                    injection = f"""
    <link rel="stylesheet" href="{plugin_url}/static/css/passkeys.css">
    <script src="{plugin_url}/static/js/passkeys.js"></script>
    <div id="passkeys-login-bootstrap" style="display:none"></div>
    <script>
    (function() {{
      function tryInject() {{
        try {{
          if (window.ensurePasskeyLoginButton) window.ensurePasskeyLoginButton();
          else if (window.OctoPrintMfaPasskeys && typeof window.OctoPrintMfaPasskeys.ensurePasskeyLoginButton === "function") window.OctoPrintMfaPasskeys.ensurePasskeyLoginButton();
        }} catch (e) {{}}
      }}
      document.addEventListener("DOMContentLoaded", tryInject);
      setTimeout(tryInject, 250);
      setTimeout(tryInject, 1000);
      setTimeout(tryInject, 2500);
    }})();
    </script>
"""
                    html = html.replace("</head>", injection + "</head>")
                    response.set_data(html)
            return response

    def get_assets(self):
        return {
            "js": ["js/passkeys.js"],
            "css": ["css/passkeys.css"],
        }

    def get_template_configs(self):
        return [
            dict(type="settings", name=gettext("Passkeys"), template="mfa_passkeys_settings.jinja2", custom_bindings=False),
            dict(type="usersettings", name=gettext("Passkeys"), template="mfa_passkeys_usersettings.jinja2", custom_bindings=False),
            dict(type="generic", template="mfa_passkeys_generic.jinja2", custom_bindings=False),
        ]

    def get_settings_defaults(self):
        return {
            "rp_id": "",
            "origin_override": "",
            "certificate_source_path": "",
            "resident_key_preference": "preferred",
            "force_https": True,
            "login_button_label": "Sign in with a Passkey",
        }

    def is_blueprint_protected(self):
        return False

    def is_blueprint_csrf_protected(self):
        return False

    @property
    def _data_file(self):
        return os.path.join(self.get_plugin_data_folder(), "mfa_passkeys_data.json")

    @property
    def _public_cert_der_file(self):
        return os.path.join(self.get_plugin_data_folder(), PUBLIC_CERT_DER_FILENAME)

    @property
    def _public_cert_pem_file(self):
        return os.path.join(self.get_plugin_data_folder(), PUBLIC_CERT_PEM_FILENAME)

    def _now(self) -> int:
        return int(time.time())

    def _b64url_encode(self, value: bytes) -> str:
        return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")

    def _b64url_decode(self, value: str) -> bytes:
        return base64url_to_bytes(value)

    def _load_data(self):
        with self._data_lock:
            os.makedirs(self.get_plugin_data_folder(), exist_ok=True)
            if not os.path.exists(self._data_file):
                self._data = {"users": {}}
                return
            try:
                with open(self._data_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if not isinstance(data, dict):
                    data = {"users": {}}
                data.setdefault("users", {})
                self._data = data
            except Exception:
                self._logger.exception("Failed to load passkey data")
                self._data = {"users": {}}
            self._cleanup_ceremonies_locked()

    def _save_data_locked(self):
        os.makedirs(self.get_plugin_data_folder(), exist_ok=True)
        tmp = self._data_file + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self._data, f, indent=2, sort_keys=True)
        os.replace(tmp, self._data_file)

    def _cleanup_ceremonies_locked(self):
        now = self._now()
        for state_id, state in list(self._ceremonies.items()):
            if state.get("expires", 0) < now:
                self._ceremonies.pop(state_id, None)

    def _get_or_create_user_record_locked(self, userid: str) -> Dict[str, Any]:
        user = self._data["users"].get(userid)
        if not user:
            user = {
                "created": self._now(),
                "active": False,
                "credentials": {},
            }
            self._data["users"][userid] = user
        user.setdefault("credentials", {})
        user.setdefault("active", False)
        user.setdefault("created", self._now())
        return user

    def _request_host(self):
        host = (request.host or "").split(":", 1)[0].strip().lower()
        if host in {"127.0.0.1", "::1"}:
            return "localhost"
        return host

    def _browser_origin(self, payload=None):
        payload = payload or {}
        origin = (payload.get("browser_origin") or "").strip()
        if origin:
            return origin.rstrip("/")
        return request.host_url.rstrip("/")

    def _browser_host(self, payload=None):
        payload = payload or {}
        host = (payload.get("browser_host") or "").strip().lower()
        if host:
            return host.split(":", 1)[0]
        return self._request_host()

    def _rp_id(self, payload=None):
        configured = (self._settings.get(["rp_id"]) or "").strip().lower()
        if configured:
            return configured
        return self._browser_host(payload)

    def _expected_origin(self, payload=None):
        configured = (self._settings.get(["origin_override"]) or "").strip()
        if configured:
            return configured.rstrip("/")
        return self._browser_origin(payload)

    def _is_secure_origin(self, payload=None):
        origin = self._expected_origin(payload).lower()
        return origin.startswith("https://") or origin.startswith("http://localhost")

    def _origin_warning(self, payload=None):
        origin = self._expected_origin(payload)
        if self._is_secure_origin(payload):
            return ""
        return gettext(
            "Passkeys require a secure origin. Browsers block WebAuthn on origins with TLS certificate errors and usually on plain HTTP. Current origin: %(origin)s",
            origin=origin,
        )

    def _detect_certificate_candidates(self):
        candidates = []
        for candidate in [
            "/etc/ssl/private/octopi.pem",
            "/etc/ssl/snakeoil.pem",
            "/etc/haproxy/haproxy.pem",
            "/etc/haproxy/certs/octopi.pem",
        ]:
            if os.path.exists(candidate):
                candidates.append(candidate)
        return candidates

    def _preferred_certificate_source(self):
        configured = (self._settings.get(["certificate_source_path"]) or "").strip()
        if configured:
            return configured
        candidates = self._detect_certificate_candidates()
        for candidate in candidates:
            if "octoprint-passkeys-export" in candidate or candidate.endswith("octoprint-passkeys.crt") or candidate.endswith("octoprint-passkeys.cer"):
                return candidate
        for candidate in candidates:
            if "octopi.pem" in candidate:
                return candidate
        return candidates[0] if candidates else ""

    def _public_status_payload(self, payload=None):
        payload = payload or {}
        detected_cert_path = self._preferred_certificate_source()
        login_button_label = (self._settings.get(["login_button_label"]) or "Sign in with a Passkey").strip() or "Sign in with a Passkey"
        rp_id = (self._settings.get(["rp_id"]) or "").strip() or self._rp_id(payload)
        origin = (self._settings.get(["origin_override"]) or "").strip() or self._expected_origin(payload)
        return {
            "developer_credit": "Daedalas1981",
            "login_button_label": login_button_label,
            "expected_origin": origin,
            "rp_id": rp_id,
            "secure_origin": self._is_secure_origin(payload),
            "origin_warning": self._origin_warning(payload),
            "can_download_cert": os.path.exists(self._public_cert_der_file),
            "cert_download_url": self._plugin_url("/download_cert") if os.path.exists(self._public_cert_der_file) else "",
            "detected_certificate_source_path": detected_cert_path,
            "certificate_candidates": self._detect_certificate_candidates(),
        }

    def _user_status_payload(self, userid: str, payload=None):
        with self._data_lock:
            user = self._data.get("users", {}).get(userid, {})
            credentials = []
            for credential_id, cred in user.get("credentials", {}).items():
                credentials.append(
                    {
                        "credential_id": credential_id,
                        "friendly_name": cred.get("friendly_name") or "",
                        "created": cred.get("created"),
                        "last_used": cred.get("last_used"),
                        "transports": cred.get("transports", []),
                        "device_type": cred.get("device_type") or "",
                        "backed_up": cred.get("backed_up"),
                    }
                )
        payload_out = self._public_status_payload(payload)
        payload_out.update(
            {
                "active": bool(credentials),
                "credentials": credentials,
            }
        )
        return payload_out

    def _admin_status_payload(self, payload=None):
        payload_out = self._public_status_payload(payload)
        payload_out.update(
            {
                "settings": {
                    "rp_id": self._settings.get(["rp_id"]) or payload_out.get("rp_id") or "",
                    "origin_override": self._settings.get(["origin_override"]) or payload_out.get("expected_origin") or "",
                    "certificate_source_path": self._settings.get(["certificate_source_path"]) or payload_out.get("detected_certificate_source_path") or "",
                    "resident_key_preference": self._settings.get(["resident_key_preference"]) or "preferred",
                    "force_https": self._settings.get_boolean(["force_https"]),
                    "login_button_label": self._settings.get(["login_button_label"]) or "Sign in with a Passkey",
                },
                "cert_source_exists": bool((self._settings.get(["certificate_source_path"]) or payload_out.get("detected_certificate_source_path")) and os.path.exists((self._settings.get(["certificate_source_path"]) or payload_out.get("detected_certificate_source_path")))),
            }
        )
        return payload_out

    def _plugin_url(self, suffix: str) -> str:
        return f"/plugin/{self._identifier}{suffix}"

    def _serialize_options(self, options):
        return json.loads(options_to_json(options))

    def _store_ceremony(self, ceremony_type: str, challenge: bytes, userid: Optional[str], metadata: Optional[Dict[str, Any]] = None) -> str:
        self._cleanup_ceremonies_locked()
        state_id = secrets.token_urlsafe(24)
        self._ceremonies[state_id] = {
            "type": ceremony_type,
            "userid": userid,
            "challenge": self._b64url_encode(challenge),
            "metadata": metadata or {},
            "expires": self._now() + CEREMONY_TTL_SECONDS,
        }
        return state_id

    def _pop_ceremony(self, state_id: str, ceremony_type: str) -> Dict[str, Any]:
        self._cleanup_ceremonies_locked()
        state = self._ceremonies.pop(state_id, None)
        if not state:
            raise ValueError("Passkey session expired. Please try again.")
        if state.get("type") != ceremony_type:
            raise ValueError("Invalid passkey session.")
        return state

    def _normalize_credential(self, credential):
        if not isinstance(credential, dict):
            return credential
        cleaned = {}
        for key, value in credential.items():
            if key in {"authenticatorAttachment", "clientExtensionResults"}:
                continue
            if isinstance(value, dict):
                cleaned[key] = self._normalize_credential(value)
            elif isinstance(value, list):
                cleaned[key] = [self._normalize_credential(item) if isinstance(item, dict) else item for item in value]
            else:
                cleaned[key] = value
        return cleaned

    def _parse_registration_credential(self, credential):
        return parse_registration_credential_json(self._normalize_credential(credential))

    def _parse_authentication_credential(self, credential):
        return parse_authentication_credential_json(self._normalize_credential(credential))

    def _build_allow_credentials_for_user_locked(self, userid: str):
        allow = []
        user = self._data.get("users", {}).get(userid)
        if not user:
            return allow
        for credential_id, cred in user.get("credentials", {}).items():
            try:
                allow.append(
                    PublicKeyCredentialDescriptor(
                        id=self._b64url_decode(credential_id),
                        transports=cred.get("transports") or None,
                    )
                )
            except Exception:
                self._logger.warning("Skipping invalid stored credential for %s", userid)
        return allow

    def _find_stored_credential_locked(self, credential_id: str, userid_hint: Optional[str] = None) -> Tuple[Optional[str], Optional[Dict[str, Any]]]:
        if userid_hint:
            user = self._data.get("users", {}).get(userid_hint, {})
            cred = user.get("credentials", {}).get(credential_id)
            if cred:
                return userid_hint, cred
        for userid, user in self._data.get("users", {}).items():
            cred = user.get("credentials", {}).get(credential_id)
            if cred:
                return userid, cred
        return None, None

    def _extract_first_certificate_pem(self, pem_text: str) -> str:
        match = re.search(
            r"(-----BEGIN CERTIFICATE-----\s+.*?\s+-----END CERTIFICATE-----)",
            pem_text,
            flags=re.DOTALL,
        )
        if not match:
            raise ValueError("No public certificate block was found in the source file.")
        return match.group(1).strip() + "\n"

    def _write_public_certificate_files(self, pem_text: str):
        pem_cert = self._extract_first_certificate_pem(pem_text)
        der_cert = base64.b64decode("".join(line.strip() for line in pem_cert.splitlines() if "CERTIFICATE" not in line))
        os.makedirs(self.get_plugin_data_folder(), exist_ok=True)
        with open(self._public_cert_pem_file, "w", encoding="utf-8") as f:
            f.write(pem_cert)
        with open(self._public_cert_der_file, "wb") as f:
            f.write(der_cert)

    def _require_authenticated_user(self):
        if not current_user or current_user.is_anonymous() or not getattr(current_user, "is_active", False):
            abort(403)

    def _require_admin(self):
        self._require_authenticated_user()
        from octoprint.access.permissions import Permissions
        if not current_user.has_permission(Permissions.ADMIN):
            abort(403)

    def _credential_transports_from_registration(self, credential: Dict[str, Any]):
        transports = (credential.get("response") or {}).get("transports")
        return transports or []

    def _begin_registration_options(self, userid: str, payload: Dict[str, Any]):
        with self._data_lock:
            self._get_or_create_user_record_locked(userid)
            exclude = self._build_allow_credentials_for_user_locked(userid)

        resident_pref = (self._settings.get(["resident_key_preference"]) or "preferred").strip().lower()
        if resident_pref not in {"preferred", "required", "discouraged"}:
            resident_pref = "preferred"

        rp_id = self._rp_id(payload)
        origin = self._expected_origin(payload)
        options = generate_registration_options(
            rp_id=rp_id,
            rp_name="OctoPrint",
            user_id=userid.encode("utf-8"),
            user_name=userid,
            exclude_credentials=exclude or None,
            authenticator_selection=AuthenticatorSelectionCriteria(
                resident_key=ResidentKeyRequirement(resident_pref),
                user_verification=UserVerificationRequirement.REQUIRED,
            ),
        )
        with self._data_lock:
            state_id = self._store_ceremony(
                "register",
                options.challenge,
                userid,
                metadata={
                    "rp_id": rp_id,
                    "expected_origin": origin,
                    "friendly_name": (payload.get("friendly_name") or "").strip()[:120],
                },
            )
        return state_id, options, rp_id, origin

    def _begin_authentication_options(self, userid: Optional[str], payload: Dict[str, Any]):
        rp_id = self._rp_id(payload)
        origin = self._expected_origin(payload)
        with self._data_lock:
            allow_credentials = None
            if userid:
                allow_credentials = self._build_allow_credentials_for_user_locked(userid) or None
            options = generate_authentication_options(
                rp_id=rp_id,
                allow_credentials=allow_credentials,
                user_verification=UserVerificationRequirement.REQUIRED,
            )
            state_id = self._store_ceremony(
                "authenticate",
                options.challenge,
                userid,
                metadata={
                    "rp_id": rp_id,
                    "expected_origin": origin,
                },
            )
        return state_id, options, rp_id, origin

    def _core_login_user(self, userid: str, remember: bool = False):
        user = octoprint.server.userManager.find_user(userid)
        if user is None:
            raise ValueError("The OctoPrint user attached to this passkey no longer exists.")
        if not user.is_active:
            raise ValueError("This OctoPrint user is deactivated.")

        remote_addr = request.remote_addr
        user = octoprint.server.userManager.login_user(user)
        session["usersession.id"] = user.session
        session["usersession.signature"] = session_signature(userid, user.session)
        g.user = user
        login_user(user, remember=remember)
        identity_changed.send(current_app._get_current_object(), identity=Identity(user.get_id()))
        session["login_mechanism"] = getattr(LoginMechanism, "PASSWORD", "password")
        session["credentials_seen"] = datetime.datetime.now().timestamp()
        eventManager().fire(Events.USER_LOGGED_IN, payload={"username": user.get_id()})
        auth_log(f"Logging in user {userid} from {remote_addr} via passkey")
        as_dict = user.as_dict()
        as_dict["_login_mechanism"] = session["login_mechanism"]
        as_dict["_credentials_seen"] = to_api_credentials_seen(session["credentials_seen"])
        as_dict["_is_external_client"] = self._is_external_client(remote_addr)
        return as_dict

    def _is_external_client(self, remote_addr: Optional[str]) -> bool:
        try:
            return self._settings.global_get_boolean(["server", "ipCheck", "enabled"]) and not util_net.is_lan_address(
                remote_addr,
                additional_private=self._settings.global_get(["server", "ipCheck", "trustedSubnets"]),
            )
        except Exception:
            return False

    @octoprint.plugin.BlueprintPlugin.route("/public_status", methods=["GET"])
    def public_status(self):
        payload = {
            "browser_origin": request.args.get("browser_origin", ""),
            "browser_host": request.args.get("browser_host", ""),
        }
        return jsonify(self._public_status_payload(payload))

    @octoprint.plugin.BlueprintPlugin.route("/user_status", methods=["GET"])
    def user_status(self):
        self._require_authenticated_user()
        payload = {
            "browser_origin": request.args.get("browser_origin", ""),
            "browser_host": request.args.get("browser_host", ""),
        }
        return jsonify(self._user_status_payload(current_user.get_id(), payload))

    @octoprint.plugin.BlueprintPlugin.route("/admin_status", methods=["GET"])
    def admin_status(self):
        self._require_admin()
        payload = {
            "browser_origin": request.args.get("browser_origin", ""),
            "browser_host": request.args.get("browser_host", ""),
        }
        return jsonify(self._admin_status_payload(payload))

    @octoprint.plugin.BlueprintPlugin.route("/save_config", methods=["POST"])
    def save_config(self):
        self._require_admin()
        ensure_credentials_checked_recently()
        data = request.get_json(silent=True) or {}
        resident_pref = (data.get("resident_key_preference") or "preferred").strip().lower()
        if resident_pref not in {"preferred", "required", "discouraged"}:
            resident_pref = "preferred"
        self._settings.set(["rp_id"], (data.get("rp_id") or "").strip())
        
        origin = (data.get("origin_override") or "").strip()
        force_https = bool(data.get("force_https", True))
        if force_https and origin.startswith("http://") and not origin.startswith("http://localhost"):
            origin = origin.replace("http://", "https://")
            
        self._settings.set(["origin_override"], origin)
        self._settings.set(["certificate_source_path"], (data.get("certificate_source_path") or "").strip())
        self._settings.set(["resident_key_preference"], resident_pref)
        self._settings.set_boolean(["force_https"], force_https)
        self._settings.set(["login_button_label"], (data.get("login_button_label") or "Sign in with a Passkey").strip()[:120])
        self._settings.save()
        return jsonify(self._admin_status_payload(data))

    @octoprint.plugin.BlueprintPlugin.route("/import_public_cert", methods=["POST"])
    def import_public_cert(self):
        self._require_admin()
        ensure_credentials_checked_recently()
        data = request.get_json(silent=True) or {}
        requested_path = (data.get("certificate_source_path") or self._settings.get(["certificate_source_path"]) or "").strip()

        candidate_paths = []
        if requested_path:
            normalized_path = os.path.abspath(requested_path)
            allowed_roots = [
                os.path.abspath("/etc/ssl/"),
                os.path.abspath("/etc/haproxy/"),
                os.path.abspath("/etc/nginx/"),
                os.path.abspath(self.get_plugin_data_folder())
            ]
            is_allowed = any(normalized_path.startswith(root) for root in allowed_roots)
            if not is_allowed:
                return make_response(jsonify({"error": "Configured certificate path is not in an allowed directory for security reasons."}), 400)
            candidate_paths.append(normalized_path)

        candidate_paths.extend(self._detect_certificate_candidates())

        pem_text = ""
        used_path = ""
        last_error = ""

        try:
            import ssl
            pem_text = ssl.get_server_certificate(("127.0.0.1", 443))
            used_path = "Active Server Certificate (127.0.0.1:443)"
        except Exception as exc:
            last_error += f"Could not fetch certificate over localhost TCP loopback: {exc}. "

        if not pem_text:
            for path in candidate_paths:
                if not path or not os.path.exists(path):
                    continue
                try:
                    if path.lower().endswith(".cer"):
                        with open(path, "rb") as f:
                            import ssl
                            pem_text = ssl.DER_cert_to_PEM_cert(f.read())
                    else:
                        with open(path, "r", encoding="utf-8", errors="ignore") as f:
                            pem_text = f.read()
                    used_path = path
                    break
                except PermissionError:
                    last_error += f"Permission denied reading {path}. "
                except Exception as exc:
                    last_error += f"Error reading {path}: {exc}. "

        if not pem_text:
            return make_response(
                jsonify(
                    {
                        "error": (
                            "OctoPrint could not read the configured certificate source path. "
                            "Use the helper script to export a readable .crt or .cer into your home directory, "
                            "then import that exported file instead. "
                            + (f"Last error: {last_error}" if last_error else "")
                        )
                    }
                ),
                400,
            )

        try:
            cert_pem = self._extract_first_certificate_pem(pem_text)
            if not cert_pem:
                raise ValueError("No public certificate block was found in the selected file.")
            with open(self._public_cert_pem_file, "w", encoding="utf-8") as f:
                f.write(cert_pem)
            with open(self._public_cert_der_file, "wb") as f:
                import ssl
                f.write(ssl.PEM_cert_to_DER_cert(cert_pem))
        except Exception as exc:
            return make_response(jsonify({"error": f"Could not extract a public certificate: {exc}"}), 400)

        return jsonify(
            {
                "message": "Public certificate imported successfully.",
                "imported_from": used_path,
                "download_url": self._plugin_url("/download_cert"),
                "pem_download_url": self._plugin_url("/download_cert_pem"),
            }
        )

    @octoprint.plugin.BlueprintPlugin.route("/download_cert", methods=["GET"])
    def download_cert(self):
        if not os.path.exists(self._public_cert_der_file):
            abort(404)
        return send_file(
            self._public_cert_der_file,
            as_attachment=True,
            download_name="octoprint-passkeys.cer",
            mimetype="application/pkix-cert",
        )

    @octoprint.plugin.BlueprintPlugin.route("/download_cert_pem", methods=["GET"])
    def download_cert_pem(self):
        if not os.path.exists(self._public_cert_pem_file):
            abort(404)
        return send_file(
            self._public_cert_pem_file,
            as_attachment=True,
            download_name="octoprint-passkeys.crt",
            mimetype="application/x-pem-file",
        )



    @octoprint.plugin.BlueprintPlugin.route("/begin_enroll", methods=["POST"])
    def begin_enroll(self):
        self._require_authenticated_user()
        ensure_credentials_checked_recently()
        data = request.get_json(silent=True) or {}
        if self._settings.get_boolean(["force_https"]) and not self._is_secure_origin(data):
            abort(400, description=self._origin_warning(data))
        userid = current_user.get_id()
        state_id, options, rp_id, origin = self._begin_registration_options(userid, data)
        return jsonify(
            {
                "state_id": state_id,
                "options": self._serialize_options(options),
                "rp_id": rp_id,
                "expected_origin": origin,
                "secure_origin": self._is_secure_origin(data),
                "origin_warning": self._origin_warning(data),
            }
        )

    @octoprint.plugin.BlueprintPlugin.route("/finish_enroll", methods=["POST"])
    def finish_enroll(self):
        self._require_authenticated_user()
        ensure_credentials_checked_recently()
        data = request.get_json(silent=True) or {}
        state_id = data.get("state_id")
        credential = data.get("credential")
        if not state_id or not credential:
            abort(400, description="Missing passkey enrollment data.")
        userid = current_user.get_id()
        try:
            with self._data_lock:
                state = self._pop_ceremony(state_id, "register")
            if state.get("userid") != userid:
                raise ValueError("Passkey enrollment session does not match the current user.")
            metadata = state.get("metadata", {})
            verification = verify_registration_response(
                credential=self._parse_registration_credential(credential),
                expected_challenge=self._b64url_decode(state["challenge"]),
                expected_rp_id=metadata.get("rp_id") or self._rp_id(data),
                expected_origin=metadata.get("expected_origin") or self._expected_origin(data),
                require_user_verification=True,
            )
            credential_id = self._b64url_encode(verification.credential_id)
            public_key = self._b64url_encode(verification.credential_public_key)
            with self._data_lock:
                user = self._get_or_create_user_record_locked(userid)
                user["credentials"][credential_id] = {
                    "credential_id": credential_id,
                    "public_key": public_key,
                    "sign_count": verification.sign_count,
                    "transports": self._credential_transports_from_registration(credential),
                    "created": self._now(),
                    "last_used": None,
                    "device_type": getattr(verification, "credential_device_type", None),
                    "backed_up": getattr(verification, "credential_backed_up", None),
                    "friendly_name": metadata.get("friendly_name") or "",
                }
                user["active"] = bool(user["credentials"])
                self._save_data_locked()
        except Exception as exc:
            self._logger.warning("Passkey enrollment failed for %s: %s", userid, exc)
            abort(400, description=f"Passkey enrollment failed: {exc}")
        return jsonify(self._user_status_payload(userid, data))

    @octoprint.plugin.BlueprintPlugin.route("/remove_credential", methods=["POST"])
    def remove_credential(self):
        self._require_authenticated_user()
        ensure_credentials_checked_recently()
        data = request.get_json(silent=True) or {}
        credential_id = (data.get("credential_id") or "").strip()
        if not credential_id:
            abort(400, description="Missing credential id.")
        userid = current_user.get_id()
        with self._data_lock:
            user = self._get_or_create_user_record_locked(userid)
            user.get("credentials", {}).pop(credential_id, None)
            user["active"] = bool(user.get("credentials"))
            self._save_data_locked()
        return jsonify(self._user_status_payload(userid, data))

    @octoprint.plugin.BlueprintPlugin.route("/begin_login", methods=["POST"])
    def begin_login(self):
        data = request.get_json(silent=True) or {}
        if self._settings.get_boolean(["force_https"]) and not self._is_secure_origin(data):
            abort(400, description=self._origin_warning(data))
        username = (data.get("username") or "").strip()
        userid = username or None
        with self._data_lock:
            if userid:
                user_data = self._data.get("users", {}).get(userid)
                if not user_data or not user_data.get("active") or not user_data.get("credentials"):
                    return jsonify({"available": False, **self._public_status_payload(data)})
            state_id, options, rp_id, origin = self._begin_authentication_options(userid, data)
        return jsonify(
            {
                "available": True,
                "state_id": state_id,
                "options": self._serialize_options(options),
                "rp_id": rp_id,
                "expected_origin": origin,
                "secure_origin": self._is_secure_origin(data),
                "origin_warning": self._origin_warning(data),
            }
        )

    @octoprint.plugin.BlueprintPlugin.route("/finish_login", methods=["POST"])
    def finish_login(self):
        data = request.get_json(silent=True) or {}
        state_id = data.get("state_id")
        credential = data.get("credential")
        if not state_id or not credential:
            abort(400, description="Missing passkey authentication data.")

        remember = bool(data.get("remember", False))
        try:
            with self._data_lock:
                state = self._pop_ceremony(state_id, "authenticate")
                metadata = state.get("metadata", {})
                credential_id = (credential.get("id") or "").strip()
                if not credential_id:
                    raise ValueError("Credential id missing from browser response.")
                userid, stored = self._find_stored_credential_locked(credential_id, userid_hint=state.get("userid"))
                if not userid or not stored:
                    raise ValueError("This passkey is not enrolled in OctoPrint.")
                verification = verify_authentication_response(
                    credential=self._parse_authentication_credential(credential),
                    expected_challenge=self._b64url_decode(state["challenge"]),
                    expected_rp_id=metadata.get("rp_id") or self._rp_id(data),
                    expected_origin=metadata.get("expected_origin") or self._expected_origin(data),
                    credential_public_key=self._b64url_decode(stored["public_key"]),
                    credential_current_sign_count=int(stored.get("sign_count", 0)),
                    require_user_verification=True,
                )
                stored["sign_count"] = verification.new_sign_count
                stored["last_used"] = self._now()
                user_data = self._get_or_create_user_record_locked(userid)
                user_data["active"] = bool(user_data.get("credentials"))
                self._save_data_locked()

            login_payload = self._core_login_user(userid, remember=remember)
        except Exception as exc:
            self._logger.warning("Passkey login failed: %s", exc)
            abort(400, description=f"Passkey login failed: {exc}")

        response = make_response(
            jsonify(
                {
                    "ok": True,
                    "redirect": request.script_root or "/",
                    "user": login_payload,
                }
            )
        )
        response.delete_cookie("active_logout")
        return response

    def get_update_information(self):
        return {
            "mfa_passkeys": {
                "displayName": self._plugin_name,
                "displayVersion": self._plugin_version,
                "type": "github_release",
                "user": "daedalas1981",
                "repo": "Octoprint-MFA-Passkeys",
                "current": self._plugin_version,
                "stable_branch": {
                    "name": "Stable",
                    "branch": "main",
                    "commitish": ["main"],
                },
                "pip": "https://github.com/daedalas1981/Octoprint-MFA-Passkeys/archive/{target_version}.zip",
            }
        }


__plugin_name__ = gettext("Passkeys for OctoPrint")
__plugin_version__ = "0.2.11"
__plugin_pythoncompat__ = ">=3.9,<4"
__plugin_implementation__ = PasskeysPlugin()
__plugin_hooks__ = {
    "octoprint.plugin.softwareupdate.check_config": __plugin_implementation__.get_update_information,
}
