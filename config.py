import os
import secrets
import time
from collections import defaultdict, deque
import connexion
from flask import jsonify, request
from flask_sqlalchemy import SQLAlchemy
from connexion.exceptions import ProblemException

vuln_app = connexion.App(__name__, specification_dir="./openapi_specs")

# In-memory sliding-window limiter: no external dependency, no shared state
# across processes. Scoped to the credential-guessing endpoints only, so a
# brute-force burst there can never 429 unrelated traffic elsewhere in the app.
_request_log = defaultdict(deque)
_CRED_LIMIT, _CRED_WINDOW = 30, 60
_CRED_SUFFIXES = ("/login", "/register", "/password")


def _rate_limited(key, limit, window):
    now = time.time()
    log = _request_log[key]
    while log and now - log[0] > window:
        log.popleft()
    if len(log) >= limit:
        return True
    log.append(now)
    return False


@vuln_app.app.before_request
def _enforce_rate_limit():
    if not request.path.endswith(_CRED_SUFFIXES):
        return None
    ip = request.remote_addr or "unknown"
    key = f"{request.path}:{ip}"
    if _rate_limited(key, _CRED_LIMIT, _CRED_WINDOW):
        return (
            jsonify(
                {
                    "status": "fail",
                    "message": "Too many requests. Please try again later.",
                }
            ),
            429,
        )
    return None


SQLALCHEMY_DATABASE_URI = "sqlite:///" + os.path.join(
    vuln_app.app.root_path, "database/database.db"
)
vuln_app.app.config["SQLALCHEMY_DATABASE_URI"] = SQLALCHEMY_DATABASE_URI
vuln_app.app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Operator-supplied key when present, otherwise a strong per-process random key.
# A guessable constant let anyone recover the key and forge an admin token.
vuln_app.app.config["SECRET_KEY"] = os.environ.get(
    "SECRET_KEY"
) or secrets.token_urlsafe(64)
# start the db
db = SQLAlchemy(vuln_app.app)


def custom_problem_handler(error):
    # Custom error handler for clarity in structure
    response = jsonify(
        {
            "status": "fail",
            "message": getattr(error, "detail", "An error occurred"),
        }
    )
    response.status_code = error.status
    return response


vuln_app.add_error_handler(ProblemException, custom_problem_handler)

vuln_app.add_api("openapi3.yml")
