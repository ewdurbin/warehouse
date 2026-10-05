# SPDX-License-Identifier: Apache-2.0

from zope.interface import Interface


class IJWTVerifier(Interface):
    def verify(token: str) -> str | None:
        """Validate a JWT and return its associated Warehouse user ID.

        Implementations must validate the signature, configured algorithm and
        issuer/key binding, audience, token purpose, required claims, and time
        bounds before resolving the subject to a local user ID. An unverified
        subject must never be used as an identity. Invalid credentials return
        None; infrastructure and configuration failures must raise.

        Bind the service to its intended recipient using trusted server-side
        route configuration. Token claims must not select the expected issuer
        or audience.

        This establishes identity only. Callers must also enforce token
        restrictions with permits(), account status, and the resource ACL.
        """

    def permits(token: str, request, context, permission) -> bool:
        """Return whether the JWT allows this request, resource, and permission.

        Enforce token validity and all token-specific restrictions, including
        scopes, resource restrictions, and revocation where applicable. Missing
        or unsupported authorization claims must not imply unrestricted access.
        The request identity must correspond to the token's verified subject.
        Invalid credentials or insufficient scope return False; infrastructure
        and configuration failures must raise.

        A True result does not grant access by itself: the policy must also
        enforce its authentication-method allowlist and the resource ACL.
        """
