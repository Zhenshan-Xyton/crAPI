#
# Licensed under the Apache License, Version 2.0 (the “License”);
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an “AS IS” BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


import logging
import re


_SENSITIVE_FIELDS = re.compile(
    r'(password|passwd|secret|token|api[_-]?key|auth|credential|credit[_-]?card'
    r'|cvv|cvc|ssn|pin|otp|access[_-]?key|private[_-]?key)',
    re.IGNORECASE,
)

_REDACTED = '***REDACTED***'


def sanitize_params(params):
    """
    Sanitize request parameters by redacting values of sensitive fields.

    Returns a copy with sensitive values replaced by ***REDACTED***.
    Non-dict params are returned unchanged.
    """
    if not isinstance(params, dict):
        return params

    sanitized = {}
    for key, value in params.items():
        if _SENSITIVE_FIELDS.search(str(key)):
            sanitized[key] = _REDACTED
        elif isinstance(value, dict):
            sanitized[key] = sanitize_params(value)
        elif isinstance(value, list):
            sanitized[key] = [
                sanitize_params(v) if isinstance(v, dict) else (
                    _REDACTED if isinstance(v, str) and _SENSITIVE_FIELDS.search(str(key)) else v
                )
                for v in value
            ]
        else:
            sanitized[key] = value
    return sanitized


def log_error(url, params, status_code, message):
    """
    :param url: The URL of the request API.
    :param params: Parameters of the request if any
    :param status_code: The return status code of the API
    :param message: The message of the error.
    :return:
    """
    safe_params = sanitize_params(params)
    logging.getLogger().error(f"{url} - {safe_params} - {status_code} -{message}")
