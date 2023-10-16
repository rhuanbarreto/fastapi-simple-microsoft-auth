from os import getenv
from typing import Any

from fastapi import HTTPException, Request
from fastapi.security import OAuth2AuthorizationCodeBearer
from httpx import get
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
        url_tenant_id: str | None = "common",
        auto_error: bool = True,
    ) -> None:
        assert tenant_id, "Missing tenant_id"
        assert client_id, "Missing client_id"
        self.client_id = client_id
        self.tenant_id = tenant_id
        self.url_tenant_id = url_tenant_id
        self._fetch_tenant_config()
        super().__init__(
            authorizationUrl=self.authorizationUrl,
            tokenUrl=self.tokenUrl,
            description="Microsoft Token Authentication. `Leave client_secret blank`",
            scheme_name="MicrosoftTokenAuth",
            scopes={"User.Read": "User.Read"},
            auto_error=auto_error,
        )
        self.scope = "User.Read"

    def _fetch_tenant_config(self) -> None:
        # Graph API Tokens are V1 always
        r = get(
            f"https://login.microsoftonline.com/{self.url_tenant_id}/.well-known/openid-configuration?appid={self.client_id}"
        )
        r.raise_for_status()
        config = r.json()
        self.authorizationUrl = config["authorization_endpoint"]
        self.tokenUrl = config["token_endpoint"]
        self.issuer = config["issuer"].replace("{tenantid}", self.tenant_id)
        jwks_response = get(config["jwks_uri"])
        jwks_response.raise_for_status()
        self.tenant_keys = jwks_response.json()

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
        if token is None:
            return None
        else:
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
        try:
            decoded_token = jwt.decode(
                token=token,
                key=self.tenant_keys,
                audience="00000002-0000-0000-c000-000000000000",
                issuer=self.issuer,
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
