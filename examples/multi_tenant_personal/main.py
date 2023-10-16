from fastapi import FastAPI, Request, Security

from fastapi_simple_microsoft_auth import OAuth2MultiTenantPersonalAuth


_azure_scheme = OAuth2MultiTenantPersonalAuth(
    tenant_id="add_your_tenant_id_here",
    client_id="add_your_client_id_here",
)

app = FastAPI(
    title="Multi Tenant Personal Microsoft Auth",
    description="Multi Tenant Personal Microsoft Auth",
    version="1.0.0",
    swagger_ui_init_oauth={
        "clientId": _azure_scheme.client_id,
        "usePkceWithAuthorizationCodeGrant": True,
        "scopes": "User.Read",
    },
    dependencies=[Security(_azure_scheme)],
)


@app.get("/", tags=["Test"])
async def main(req: Request) -> str:
    return f"Hello {req.state.decoded_token['given_name']}!"
