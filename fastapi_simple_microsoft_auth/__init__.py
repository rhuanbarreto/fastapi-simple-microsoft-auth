from .oauth2_single_tenant_auth import OAuth2SingleTenantAuth
from .oauth2_multi_tenant_auth import OAuth2MultiTenantAuth
from .oauth2_multi_tenant_personal_auth import OAuth2MultiTenantPersonalAuth

__all__ = ["OAuth2SingleTenantAuth", "OAuth2MultiTenantAuth", "OAuth2MultiTenantPersonalAuth"]
__version__ = "0.0.1"
