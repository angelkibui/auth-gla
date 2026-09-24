# ─────────────────────────────────────────────────────────────────────────────
# api/views.py — Authentication Gauntlet Lab
#
# Wrap-Up Comparison Table (Reporter fills this in at the end of the lab):
#
# +-------------------+------------+-----------+-------------------+----------+
# | Method            | Stateful?  | DB Lookup?| Credentials sent  | Safe on  |
# |                   |            |           | every request?    | HTTP?    |
# +-------------------+------------+-----------+-------------------+----------+
# | Basic Auth        |  No         |    No       |    Yes          |   No       |
# | Session Auth      |  Yes         |   Yes        |  No           |  No        |
# | Opaque Token Auth |   Yes        |   Yes        |  No           |  No        |
# | JWT               |  No          |   No        |   No           |  No        |
# +-------------------+------------+-----------+-------------------+----------+
#
# ─────────────────────────────────────────────────────────────────────────────

from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.authentication import (
    BasicAuthentication,
    SessionAuthentication,
    TokenAuthentication,
)
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.response import Response


# ─────────────────────────────────────────────────────────────────────────────
# PHASE 1 — Basic Authentication
# ─────────────────────────────────────────────────────────────────────────────

@api_view(["GET"])
@authentication_classes([BasicAuthentication])
@permission_classes([IsAuthenticated])
def basic_auth_view(request):
    # TODO: Extract and print the header
    auth_header = request.META.get('HTTP_AUTHORIZATION')
    print(f"Incoming Header: {auth_header}")

    # Reporter — Phase 1 challenge answers:
    # Q1 answer (header format for admin:admin123): "username:password" — Base64-encoded
    # Q2 answer (what happens without credentials): 401 Unauthorized — no Authorization header
    #   means DRF cannot authenticate the request, so IsAuthenticated denies access

    return Response({"message": "Check your terminal!"})


# ─────────────────────────────────────────────────────────────────────────────
# PHASE 2 — Session Authentication
# ─────────────────────────────────────────────────────────────────────────────

@api_view(["GET"])
@authentication_classes([SessionAuthentication])
@permission_classes([IsAuthenticated])
def session_auth_view(request):
    # Reporter — Phase 2 challenge answers:
    # Q1 answer (effect of deleting the session cookie): Deleting sessionid logs you out
    #   immediately — the browser no longer sends a session identifier, so Django can't match
    #   a request to the session record stored server-side, even though that record may still
    #   exist in the DB.
    # Synthesis answer (how session fixation / hijacking works): An attacker only needs to
    #   obtain the sessionid value (e.g. via network sniffing, XSS, or a shared/unsecured
    #   device) and set it as their own cookie — the server has no way to distinguish the
    #   attacker's browser from the legitimate user's, since the cookie itself IS the proof
    #   of identity. This is called "session hijacking" because the attacker takes over an
    #   already-authenticated session without ever needing the username or password.

    return Response({"message": "Session authenticated.", "user": request.user.username})


# ─────────────────────────────────────────────────────────────────────────────
# PHASE 3 — Token Authentication (Opaque)
# ─────────────────────────────────────────────────────────────────────────────

@api_view(["GET"])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def token_auth_view(request):
    # Reporter — Phase 3 challenge answers:
    # Q1 answer (status code when token is tampered): 401 Unauthorized
    # Q2 answer (algorithm used to hash admin's password in the DB): pbkdf2_sha256 —
    #   plaintext is never stored so a leaked DB doesn't expose real passwords; PBKDF2's
    #   iteration count also makes brute-force attacks computationally expensive.
    # Synthesis answer (revoking a stolen opaque token vs a stolen JWT): An opaque token is
    #   just a row in the server's database — the server (admin/backend) can delete that row
    #   at any moment, instantly invalidating it everywhere. A JWT has no database row to
    #   delete — it's self-contained and valid until its exp timestamp, so the server can't
    #   "unsign" it early; revoking a JWT early requires extra infrastructure like a
    #   blocklist checked on every request, which defeats the whole point of being stateless.

    return Response({"message": "Token authenticated.", "user": request.user.username})


# ─────────────────────────────────────────────────────────────────────────────
# PHASE 4 — JSON Web Tokens (JWT)
# ─────────────────────────────────────────────────────────────────────────────

@api_view(["GET"])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def jwt_protected_view(request):
        # Reporter — Phase 4 challenge answers:
    # Q1 answer (fields found in the decoded payload): user_id (also token_type, iat, jti)
    # Q2 answer (what happens when the signature is tampered): the server recomputes the
    #   signature from the header + payload using its secret key and compares it to the
    #   token's third segment — no DB lookup needed, since a valid signature alone proves
    #   the token hasn't been altered.

    return Response({"message": "JWT authenticated.", "user": request.user.username})