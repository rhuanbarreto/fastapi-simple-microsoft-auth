from ._oauth2_auth_base import Oauth2AuthBase, env_client_id, env_tenant_id


class OAuth2MultiTenantAuth(Oauth2AuthBase):
    """Implement Microsoft Authentication for Multi-Tenant Applications.

    It validates the token received against the tenant keys and the `User.Read` scope. It also adds two state variables
     to the request object: `decoded_token` and `raw_token`.

    `decoded_token` is the decoded token which can be used to get more info about the user.

    `raw_token` is the raw token which can be used for OBO flows or anything else you want to do with it.
    """

    def __init__(
        self,
        *,
        client_id: str | None = env_client_id,
        tenant_id: str | None = env_tenant_id,
        auto_error: bool = True,
    ) -> None:
        super().__init__(
            client_id=client_id,
            tenant_id=tenant_id,
            url_tenant_id=tenant_id,
            auto_error=auto_error,
        )
