#!/usr/bin/env python3
# mmb_debug_v6.py
# Debuggable Backpack Exchange client wrapper for signing REST requests.
# Supports both ED25519 (private-key) signing and HMAC-SHA256 (API Key + Secret) modes.
# Adds safe triple-quoted debug logging to avoid unterminated string issues.
import os
import time
import json
import logging
import base64
import hmac
import hashlib
from urllib.parse import urlencode, parse_qsl

import requests

# Try to import ed25519 signer from cryptography (if available)
try:
    from cryptography.hazmat.primitives.asymmetric import ed25519
    ED25519_AVAILABLE = True
except Exception:
    ED25519_AVAILABLE = False

# Configuration from environment
API_KEY = os.getenv("API_KEY") or os.getenv("PUBLIC_KEY")
SECRET_KEY = os.getenv("SECRET_KEY") or os.getenv("PRIVATE_KEY")
# AUTH_MODE: 'hmac' for API Key + Secret (HMAC-SHA256), 'ed25519' for ed25519 private key signing
AUTH_MODE = os.getenv("AUTH_MODE", "hmac").lower()

BASE_URL = os.getenv("BASE_URL", "https://api.backpack.exchange")
DEFAULT_WINDOW = os.getenv("REQUEST_WINDOW", "5000")

# Setup basic logging (user can override)
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
logger = logging.getLogger("mmb_debug_v6")

# Helper: ensure params is a dict. If string, try to parse query string into dict.
def ensure_params_dict(params):
    if params is None:
        return {}
    if isinstance(params, dict):
        return params
    if isinstance(params, str):
        # parse 'a=1&b=2' into dict with simple values (choose last value if repeat)
        parsed = dict(parse_qsl(params, keep_blank_values=True))
        return parsed
    # If it's another type (e.g., list/tuple), try to convert to dict if possible
    try:
        return dict(params)
    except Exception:
        # fallback to empty dict
        return {}

class BackpackAuthenticator:
    def __init__(self, api_key, secret_key, auth_mode="hmac", window=DEFAULT_WINDOW):
        self.api_key = api_key
        self.secret_key = secret_key
        self.auth_mode = auth_mode.lower()
        self.window = str(window)

        # If ed25519 mode but cryptography unavailable, warn
        if self.auth_mode == "ed25519" and not ED25519_AVAILABLE:
            logger.warning("ED25519 requested but cryptography not available. Falling back to HMAC.")
            self.auth_mode = "hmac"

        # If ed25519, try to construct private key object
        self._private_key_obj = None
        if self.auth_mode == "ed25519" and self.secret_key:
            try:
                # SECRET_KEY expected to be base64-encoded private key bytes
                decoded = base64.b64decode(self.secret_key)
                self._private_key_obj = ed25519.Ed25519PrivateKey.from_private_bytes(decoded)
            except Exception as e:
                logger.exception("Failed to decode ED25519 private key; will not use ed25519 signing: %s", e)
                self._private_key_obj = None
                self.auth_mode = "hmac"

    def _hmac_sign(self, message: bytes) -> str:
        # HMAC-SHA256, output base64
        key = self.secret_key.encode("utf-8")
        sig = hmac.new(key, message, digestmod=hashlib.sha256).digest()
        return base64.b64encode(sig).decode()

    def _ed25519_sign(self, message: bytes) -> str:
        sig = self._private_key_obj.sign(message)
        return base64.b64encode(sig).decode()

    def generate_signature(self, instruction, params=None, window=None):
        """
        Build sign string and produce headers.
        instruction: string like 'orderCancel' etc.
        params: dict or query-string. Will be sorted by key name.
        window: optional, overrides instance window (milliseconds as string/int)
        Returns: headers dict ready for requests
        """
        timestamp = str(int(time.time() * 1000))
        window = str(window) if window is not None else self.window

        params_dict = ensure_params_dict(params)

        # sort params by key name (alphabetical) and build param string
        param_pairs = []
        for k in sorted(params_dict.keys()):
            v = params_dict[k]
            # convert booleans and non-str to JSON-like representation conservatively
            if v is True:
                v_str = "true"
            elif v is False:
                v_str = "false"
            else:
                v_str = str(v)
            param_pairs.append(f"{k}={v_str}")
        params_str = "&".join(param_pairs)

        # construct signing string as per Backpack doc: instruction first, then params, then timestamp/window
        sign_string = f"instruction={instruction}"
        if params_str:
            sign_string += f"&{params_str}"
        sign_string += f"&timestamp={timestamp}&window={window}"

        # sign according to mode
        signature_b64 = ""
        if self.auth_mode == "ed25519" and self._private_key_obj is not None:
            try:
                signature_b64 = self._ed25519_sign(sign_string.encode("utf-8"))
            except Exception as e:
                logger.exception("Ed25519 signing failed: %s", e)
                raise
        else:
            # default to HMAC-SHA256
            signature_b64 = self._hmac_sign(sign_string.encode("utf-8"))

        headers = {
            "X-API-Key": self.api_key or "",
            "X-Timestamp": timestamp,
            "X-Window": window,
            "X-Signature": signature_b64,
            "Content-Type": "application/json",
        }

        # Safe triple-quoted debug block to avoid unterminated-string errors when pasted
        debug_block = f\"\"\"
===== Backpack Signature Debug =====
Instruction: {instruction}
Params: {json.dumps(params_dict, indent=2, ensure_ascii=False)}
Sign String: {sign_string}
Signature (Base64): {signature_b64}
Headers: {json.dumps(headers, indent=2, ensure_ascii=False)}
====================================
\"\"\"
        # Log at DEBUG level
        logger.debug(debug_block)

        return headers

# Wrapper REST request function with debug logging
def rest_request(method, path, instruction, params=None, is_public=False):
    """
    Send REST request. params can be dict or query-string. If is_public=True, no auth headers.
    """
    # Normalize params to dict for logging/requests usage
    params_for_request = params if isinstance(params, dict) else ensure_params_dict(params)

    logger.debug("REST Request → %s %s, instruction=%s, params=%s", method, path, instruction, params_for_request)

    if is_public:
        headers = {}
    else:
        auth = BackpackAuthenticator(API_KEY, SECRET_KEY, auth_mode=AUTH_MODE, window=DEFAULT_WINDOW)
        headers = auth.generate_signature(instruction, params_for_request)

    logger.debug("Headers generated: %s", json.dumps(headers, indent=2, ensure_ascii=False))

    url = f"{BASE_URL}{path}"
    try:
        if method == "GET":
            r = requests.get(url, headers=headers, params=params_for_request, timeout=10)
        elif method == "POST":
            r = requests.post(url, headers=headers, json=params_for_request, timeout=10)
        elif method == "DELETE":
            # Some APIs expect delete with params in body as JSON; adjust as needed
            r = requests.delete(url, headers=headers, json=params_for_request, timeout=10)
        else:
            raise ValueError(f"Unsupported HTTP method: {method}")
    except Exception as e:
        logger.exception("HTTP request failed: %s", e)
        raise

    if r.status_code != 200:
        logger.error("HTTP %s: %s", r.status_code, r.text)
        return None

    try:
        return r.json()
    except Exception:
        return r.text

# ------------------- Example usage (main) -------------------
if __name__ == "__main__":
    # Quick smoke test (does not send real request unless API_KEY and SECRET_KEY provided)
    logging.getLogger().setLevel(logging.DEBUG)
    test_instruction = "balanceQueryAll"
    test_params = {"symbol": "BTC_USDC_PERP"}

    auth = BackpackAuthenticator(API_KEY, SECRET_KEY, auth_mode=AUTH_MODE)
    headers = auth.generate_signature(test_instruction, test_params)
    print("Generated headers (preview):")
    print(json.dumps(headers, indent=2, ensure_ascii=False))
    # Do not perform actual network call in smoke test unless intentionally enabled
    # resp = rest_request("GET", "/api/v1/capital", test_instruction, params=test_params)
