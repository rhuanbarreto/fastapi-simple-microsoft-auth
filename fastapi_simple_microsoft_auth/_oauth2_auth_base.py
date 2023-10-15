from os import getenv
from typing import Any

from fastapi import HTTPException, Request
from fastapi.security import OAuth2AuthorizationCodeBearer
from httpx import AsyncClient, HTTPStatusError
from jose import JWTError, jwt

env_client_id = getenv("OAUTH_CLIENT_ID")
env_tenant_id = getenv("OAUTH_TENANT_ID")


class Oauth2AuthBase(OAuth2AuthorizationCodeBearer):
    """Implement Microsoft Entra ID Token Authentication.

    This class extends the OAuth2AuthorizationCodeBearer class to provide authentication for Microsoft Entra ID.

    It validates the token received against the tenant keys and the `User.Read` scope. It also adds two state variables
     to the request object: `decoded_token` and `raw_token`.

    `decoded_token` is the decoded token which can be used to get more info about the user.

    `raw_token` is the raw token which can be used for OBO flows or anything else you want to do with it.
    """

    def __init__(
        self,
        *,
        tenant_id: str | None = env_tenant_id,
        client_id: str | None = env_client_id,
        url_tenant_id: str | None = env_tenant_id or "common",
        auto_error: bool = True,
    ) -> None:
        if not tenant_id:
            raise HTTPException(status_code=500, detail="Missing tenant_id")
        if not client_id:
            raise HTTPException(status_code=500, detail="Missing client_id")
        super().__init__(
            authorizationUrl=f"https://login.microsoftonline.com/{url_tenant_id}/oauth2/authorize",
            tokenUrl=f"https://login.microsoftonline.com/{url_tenant_id}/oauth2/token",
            description="Graph API Token Authentication. `Leave client_secret blank`",
            scheme_name="GraphAPITokenAuth",
            scopes={"User.Read": "User.Read"},
            auto_error=auto_error,
        )
        self.scope = "User.Read"
        self.keys_url = f"https://login.microsoftonline.com/{url_tenant_id}/discovery/keys?appid={client_id}"
        self.tenant_keys: dict | None = None
        self.client_id = client_id
        self.tenant_id = tenant_id

    async def __call__(self, request: Request) -> str | None:
        """Validate the token received.

        Validate the token against the tenant keys and the `User.Read` scope.

        It also adds two state variables to the request object. `decoded_token` and `raw_token`.

        `decoded_token` is the decoded token which can be used to get more info about the user.

        `raw_token` is the raw token which can be used for OBO flows or anything else you want to do with it.

        Args
        ----
            request (Request): The request object.

        Returns
        -------
            str | None: The validated token or None if validation fails.

        Raises
        ------
            HTTPException: If self.auto_error is True and the token is invalid or missing required scopes.
        """
        token = await super().__call__(request)
        if token is not None:
            try:
                validated_token = await self._validate_token(token)
                # This decoded token can be used for getting more info about the user
                request.state.decoded_token = validated_token
                # This token can be used for OBO flows
                request.state.raw_token = token
                return token
            except Exception as e:
                if self.auto_error:
                    raise e
                return None
        return None

    async def load_keys(self) -> None:
        """Load the tenant keys from Microsoft."""
        try:
            async with AsyncClient(timeout=10) as client:
                jwks_response = await client.get(self.keys_url)
                jwks_response.raise_for_status()
                self.tenant_keys = jwks_response.json()
        except HTTPStatusError:
            raise HTTPException(status_code=500, detail="Failure loading signing keys")

    async def _validate_token(self, token: str) -> dict[str, Any]:
        """Validate the token against the tenant keys and the `User.Read` scope.

        Args
        ----
            token (str): The token to validate.

        Returns
        -------
            dict[str, Any]: The decoded token.

        Raises
        ------
            HTTPException: If the token is invalid or missing required scopes.
        """
        if self.tenant_keys is None:
            await self.load_keys()
        if not self.tenant_keys:
            raise HTTPException(status_code=500, detail="Missing signing keys")

        try:
            decoded_token = jwt.decode(
                token=token,
                key=self.tenant_keys,
                audience="00000002-0000-0000-c000-000000000000",
                issuer=f"https://sts.windows.net/{self.tenant_id}/",
                options={
                    "require_aud": True,
                    "require_iat": True,
                    "require_exp": True,
                    "require_nbf": True,
                    "require_iss": True,
                    "require_sub": True,
                },
            )
        except JWTError as e:
            raise HTTPException(status_code=401, detail=f"Invalid Token. {e}")

        token_scope_string: str | None = decoded_token.get("scp")
        if token_scope_string is None:
            raise HTTPException(
                status_code=401, detail="Invalid Token. Missing Scopes."
            )
        token_scopes = token_scope_string.split(" ")
        if self.scope not in token_scopes:
            raise HTTPException(
                status_code=401,
                detail="Invalid Token. Scope `User.Read` must be present.",
            )
        return decoded_token
