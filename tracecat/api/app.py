from contextlib import asynccontextmanager

import jwt
from fastapi import APIRouter, Depends, FastAPI, HTTPException, Query, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import ORJSONResponse
from fastapi_users import models
from fastapi_users.authentication import AuthenticationBackend, Strategy
from fastapi_users.exceptions import UserAlreadyExists
from fastapi_users.jwt import SecretType
from fastapi_users.manager import BaseUserManager, UserManagerDependency
from fastapi_users.router.oauth import (
    STATE_TOKEN_AUDIENCE,
    ErrorCode,
    ErrorModel,
    OAuth2AuthorizeResponse,
    decode_jwt,
    generate_state_token,
)
from httpx_oauth.clients.google import GoogleOAuth2
from httpx_oauth.clients.openid import OpenID
from httpx_oauth.integrations.fastapi import (
    OAuth2AuthorizeCallback,
    OAuth2AuthorizeCallbackError,
)
from pydantic import BaseModel
from pydantic_core import to_jsonable_python
from sqlalchemy.exc import IntegrityError
from sqlmodel.ext.asyncio.session import AsyncSession

from tracecat import __version__ as APP_VERSION
from tracecat import config
from tracecat.api.common import (
    add_temporal_search_attributes,
    bootstrap_role,
    custom_generate_unique_id,
    generic_exception_handler,
    tracecat_exception_handler,
)
from tracecat.auth.dependencies import require_auth_type_enabled
from tracecat.auth.enums import AuthType
from tracecat.auth.models import UserCreate, UserRead, UserUpdate
from tracecat.auth.router import router as users_router
from tracecat.auth.saml import router as saml_router
from tracecat.auth.users import (
    FastAPIUsersException,
    InvalidEmailException,
    auth_backend,
    fastapi_users,
)
from tracecat.cases.router import case_fields_router as case_fields_router
from tracecat.cases.router import cases_router as cases_router
from tracecat.contexts import ctx_role
from tracecat.db.dependencies import AsyncDBSession
from tracecat.db.engine import get_async_session_context_manager
from tracecat.editor.router import router as editor_router
from tracecat.logger import logger
from tracecat.middleware import AuthorizationCacheMiddleware, RequestLoggingMiddleware
from tracecat.middleware.security import SecurityHeadersMiddleware
from tracecat.organization.router import router as org_router
from tracecat.registry.actions.router import router as registry_actions_router
from tracecat.registry.common import reload_registry
from tracecat.registry.repositories.router import router as registry_repos_router
from tracecat.secrets.router import org_router as org_secrets_router
from tracecat.secrets.router import router as secrets_router
from tracecat.settings.router import router as org_settings_router
from tracecat.settings.service import SettingsService, get_setting_override
from tracecat.tables.router import router as tables_router
from tracecat.tags.router import router as tags_router
from tracecat.types.auth import Role
from tracecat.types.exceptions import TracecatException
from tracecat.webhooks.router import router as webhook_router
from tracecat.workflow.actions.router import router as workflow_actions_router
from tracecat.workflow.executions.router import router as workflow_executions_router
from tracecat.workflow.management.folders.router import (
    router as workflow_folders_router,
)
from tracecat.workflow.management.router import router as workflow_management_router
from tracecat.workflow.schedules.router import router as schedules_router
from tracecat.workflow.tags.router import router as workflow_tags_router
from tracecat.workspaces.router import router as workspaces_router
from tracecat.workspaces.service import WorkspaceService


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Temporal
    await add_temporal_search_attributes()

    # App
    role = bootstrap_role()
    async with get_async_session_context_manager() as session:
        # Org
        await setup_org_settings(session, role)
        await reload_registry(session, role)
        await setup_workspace_defaults(session, role)
    yield


async def setup_org_settings(session: AsyncSession, admin_role: Role):
    settings_service = SettingsService(session, role=admin_role)
    await settings_service.init_default_settings()


async def setup_workspace_defaults(session: AsyncSession, admin_role: Role):
    ws_service = WorkspaceService(session, role=admin_role)
    workspaces = await ws_service.admin_list_workspaces()
    n_workspaces = len(workspaces)
    logger.info(f"{n_workspaces} workspaces found")
    if n_workspaces == 0:
        # Create default workspace if there are no workspaces
        try:
            default_workspace = await ws_service.create_workspace("Default Workspace")
            logger.info("Default workspace created", workspace=default_workspace)
        except IntegrityError:
            logger.info("Default workspace already exists, skipping")


# Catch-all exception handler to prevent stack traces from leaking
def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Improves visiblity of 422 errors."""
    errors = exc.errors()
    ser_errors = to_jsonable_python(errors, fallback=str)
    logger.error(
        "API Model Validation error",
        request=request,
        errors=ser_errors,
    )
    return ORJSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"detail": ser_errors},
    )


def fastapi_users_auth_exception_handler(request: Request, exc: FastAPIUsersException):
    msg = str(exc)
    logger.warning(
        "Handling FastAPI Users exception",
        msg=msg,
        role=ctx_role.get(),
        params=request.query_params,
        path=request.url.path,
    )
    match exc:
        case InvalidEmailException():
            status_code = status.HTTP_400_BAD_REQUEST
        case _:
            status_code = status.HTTP_401_UNAUTHORIZED
    return ORJSONResponse(status_code=status_code, content={"detail": msg})


def get_oidc_oauth_router(
    oauth_client: OpenID,
    backend: AuthenticationBackend[models.UP, models.ID],
    get_user_manager: UserManagerDependency[models.UP, models.ID],
    state_secret: SecretType,
    redirect_url: str,
    associate_by_email: bool = True,
    is_verified_by_default: bool = True,
) -> APIRouter:
    """OAuth router with custom error handling for OIDC."""

    router = APIRouter(prefix="")
    callback_route_name = f"oauth:{oauth_client.name}.{backend.name}.callback"
    oauth2_authorize_callback = OAuth2AuthorizeCallback(
        oauth_client,
        redirect_url=redirect_url,
    )

    def _maybe_exc(e: Exception | None) -> dict[str, Exception]:
        """Return exc data only in development."""
        if e is not None and config.TRACECAT__APP_ENV == "development":
            return {"exc": e}
        return {}

    @router.get(
        "/authorize",
        name=f"oauth:{oauth_client.name}.{backend.name}.authorize",
        response_model=OAuth2AuthorizeResponse,
    )
    async def authorize(
        request: Request, scopes: list[str] = Query(None)
    ) -> OAuth2AuthorizeResponse:
        request_id = request.headers.get("X-Request-ID")
        logger.info(
            "OIDC login flow started",
            event="oidc_login_started",
            client_id=oauth_client.client_id,
            issuer=oauth_client.openid_configuration.get("issuer"),
            scopes=scopes,
            request_id=request_id,
        )

        state_data: dict[str, str] = {}
        try:
            state = generate_state_token(state_data, state_secret)
            authorization_url = await oauth_client.get_authorization_url(
                redirect_url,
                state,
                scopes,
            )
        except Exception as e:  # pragma: no cover - network errors
            log_data = {
                "event": "oidc_redirect_to_idp_failed",
                "client_id": oauth_client.client_id,
                "issuer": oauth_client.openid_configuration.get("issuer"),
                "scopes": scopes,
                "request_id": request_id,
                **_maybe_exc(e),
            }
            if getattr(e, "response", None) is not None:
                resp = e.response
                log_data["provider_status"] = resp.status_code
                log_data["provider_url"] = str(resp.url)
                try:
                    data = resp.json()
                    log_data["error_description"] = data.get("error_description")
                except Exception:  # pragma: no cover - not JSON
                    log_data["provider_response"] = resp.text
            logger.error("Failed to create OIDC authorization URL", **log_data)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Login failed, please try again.",
            ) from e

        logger.info(
            "Redirecting user to the Identity Provider",
            event="oidc_redirect_to_idp",
            client_id=oauth_client.client_id,
            issuer=oauth_client.openid_configuration.get("issuer"),
            scopes=scopes,
            request_id=request_id,
        )
        logger.debug(
            "OIDC authorization URL generated",
            url=authorization_url,
            client=oauth_client.name,
        )
        return OAuth2AuthorizeResponse(authorization_url=authorization_url)

    @router.get(
        "/callback",
        name=callback_route_name,
        description="The response varies based on the authentication backend used.",
        responses={
            status.HTTP_400_BAD_REQUEST: {
                "model": ErrorModel,
                "content": {
                    "application/json": {
                        "examples": {
                            "INVALID_STATE_TOKEN": {
                                "summary": "Invalid state token.",
                                "value": None,
                            },
                            ErrorCode.LOGIN_BAD_CREDENTIALS: {
                                "summary": "User is inactive.",
                                "value": {"detail": ErrorCode.LOGIN_BAD_CREDENTIALS},
                            },
                        }
                    }
                },
            },
        },
    )
    async def callback(
        request: Request,
        code: str | None = None,
        code_verifier: str | None = None,
        state: str | None = None,
        error: str | None = None,
        user_manager: BaseUserManager[models.UP, models.ID] = Depends(get_user_manager),
        strategy: Strategy[models.UP, models.ID] = Depends(backend.get_strategy),
    ):
        request_id = request.headers.get("X-Request-ID")
        logger.info(
            "Callback received from IdP",
            event="oidc_callback_received",
            client_id=oauth_client.client_id,
            issuer=oauth_client.openid_configuration.get("issuer"),
            request_id=request_id,
        )
        if error is not None:
            log_data = {
                "event": "oidc_error_response",
                "client_id": oauth_client.client_id,
                "issuer": oauth_client.openid_configuration.get("issuer"),
                "request_id": request_id,
                "error": error,
            }
            logger.error("Error returned from IdP", **log_data)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Login failed, please try again.",
            )

        if not code or not state:
            logger.error(
                "OIDC callback missing parameters",
                event="oidc_invalid_callback_parameters",
                client_id=oauth_client.client_id,
                issuer=oauth_client.openid_configuration.get("issuer"),
                request_id=request_id,
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Login failed, please try again.",
            )
        if code:
            logger.info(
                "Authorization code received",
                event="oidc_authorization_code_received",
                request_id=request_id,
            )
        logger.info(
            "Token exchange initiated",
            event="oidc_token_exchange_started",
            request_id=request_id,
        )
        try:
            token, state_value = await oauth2_authorize_callback(
                request=request,
                code=code,
                code_verifier=code_verifier,
                state=state,
                error=error,
            )
            logger.info(
                "Token exchange succeeded",
                event="oidc_token_exchange_succeeded",
                request_id=request_id,
            )
        except OAuth2AuthorizeCallbackError as e:
            log_data = {
                **_maybe_exc(e),
                "detail": e.detail,
                "status_code": e.status_code,
                "client_id": oauth_client.client_id,
                "issuer": oauth_client.openid_configuration.get("issuer"),
                "request_id": request_id,
            }
            if error:
                log_data["error"] = error
            if e.response is not None:
                log_data["provider_status"] = e.response.status_code
                log_data["provider_url"] = str(e.response.url)
                try:
                    data = e.response.json()
                    log_data["provider_response"] = data
                    if isinstance(data, dict):
                        log_data["error_description"] = data.get("error_description")
                except Exception:
                    log_data["provider_response"] = e.response.text
            log_data["event"] = "oidc_token_exchange_failed"
            logger.error("OIDC token exchange failed", **log_data)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Login failed, please try again.",
            ) from e
        except Exception as e:  # pragma: no cover - unexpected errors
            log_data = {
                **_maybe_exc(e),
                "client_id": oauth_client.client_id,
                "issuer": oauth_client.openid_configuration.get("issuer"),
                "request_id": request_id,
            }
            if getattr(e, "response", None) is not None:
                resp = e.response
                log_data["provider_status"] = resp.status_code
                log_data["provider_url"] = str(resp.url)
                try:
                    data = resp.json()
                    log_data["provider_response"] = data
                    if isinstance(data, dict):
                        log_data["error_description"] = data.get("error_description")
                except Exception:
                    log_data["provider_response"] = resp.text
            log_data["event"] = "oidc_token_exchange_failed"
            logger.error("OIDC token exchange unexpected error", **log_data)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Login failed, please try again.",
            ) from e

        try:
            account_id, account_email = await oauth_client.get_id_email(
                token["access_token"]
            )
        except Exception as e:
            log_data = {
                **_maybe_exc(e),
                "client_id": oauth_client.client_id,
                "issuer": oauth_client.openid_configuration.get("issuer"),
                "request_id": request_id,
            }
            if getattr(e, "response", None) is not None:
                resp = e.response
                log_data["provider_status"] = resp.status_code
                log_data["provider_url"] = str(resp.url)
                try:
                    data = resp.json()
                    log_data["provider_response"] = data
                    if isinstance(data, dict):
                        log_data["error_description"] = data.get("error_description")
                except Exception:
                    log_data["provider_response"] = resp.text
            log_data["event"] = "oidc_user_info_failed"
            logger.error("OIDC provider user info retrieval failed", **log_data)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Login failed, please try again.",
            ) from e

        if account_email is None or account_id is None:
            logger.error(
                "OIDC sign-in failed: required claims missing",
                event="oidc_signin_failed",
                sub=account_id,
                client_id=oauth_client.client_id,
                issuer=oauth_client.openid_configuration.get("issuer"),
                request_id=request_id,
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Login failed, please try again.",
            )

        try:
            decode_jwt(state_value, state_secret, [STATE_TOKEN_AUDIENCE])
        except jwt.DecodeError as e:
            logger.error(
                "OIDC sign-in failed: state token invalid",
                event="oidc_signin_failed",
                request_id=request_id,
                **_maybe_exc(e),
            )
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST) from e

        try:
            user = await user_manager.oauth_callback(
                oauth_client.name,
                token["access_token"],
                account_id,
                account_email,
                token.get("expires_at"),
                token.get("refresh_token"),
                request,
                associate_by_email=associate_by_email,
                is_verified_by_default=is_verified_by_default,
            )
        except UserAlreadyExists as e:
            logger.error(
                "OIDC sign-in failed: user already exists",
                event="oidc_signin_failed",
                email=account_email,
                sub=account_id,
                request_id=request_id,
                **_maybe_exc(e),
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Login failed, please try again.",
            ) from e

        if not user.is_active:
            logger.error(
                "OIDC sign-in failed: inactive user",
                event="oidc_signin_failed",
                email=account_email,
                sub=account_id,
                request_id=request_id,
                **_maybe_exc(None),
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Login failed, please try again.",
            )

        response = await backend.login(strategy, user)
        await user_manager.on_after_login(user, request, response)
        logger.info(
            "OIDC sign-in succeeded",
            event="oidc_signin_succeeded",
            email=account_email,
            sub=account_id,
            client_id=oauth_client.client_id,
            issuer=oauth_client.openid_configuration.get("issuer"),
            request_id=request_id,
        )
        return response

    return router


def create_app(**kwargs) -> FastAPI:
    if config.TRACECAT__ALLOW_ORIGINS is not None:
        allow_origins = config.TRACECAT__ALLOW_ORIGINS.split(",")
    else:
        allow_origins = ["*"]
    app = FastAPI(
        title="Tracecat API",
        description=(
            "Tracecat is the open source Tines / Splunk SOAR alternative."
            " You can operate Tracecat in headless mode by using the API to create, manage, and run workflows."
        ),
        summary="Tracecat API",
        version="1",
        terms_of_service="https://docs.google.com/document/d/e/2PACX-1vQvDe3SoVAPoQc51MgfGCP71IqFYX_rMVEde8zC4qmBCec5f8PLKQRdxa6tsUABT8gWAR9J-EVs2CrQ/pub",
        contact={"name": "Tracecat Founders", "email": "founders@tracecat.com"},
        license_info={
            "name": "AGPL-3.0",
            "url": "https://www.gnu.org/licenses/agpl-3.0.html",
        },
        openapi_tags=[
            {"name": "public", "description": "Public facing endpoints"},
            {"name": "workflows", "description": "Workflow management"},
            {"name": "actions", "description": "Action management"},
            {"name": "triggers", "description": "Workflow triggers"},
            {"name": "secrets", "description": "Secret management"},
        ],
        generate_unique_id_function=custom_generate_unique_id,
        lifespan=lifespan,
        default_response_class=ORJSONResponse,
        root_path=config.TRACECAT__API_ROOT_PATH,
        **kwargs,
    )
    app.logger = logger  # type: ignore

    # Routers
    app.include_router(webhook_router)
    app.include_router(workspaces_router)
    app.include_router(workflow_management_router)
    app.include_router(workflow_executions_router)
    app.include_router(workflow_actions_router)
    app.include_router(workflow_tags_router)
    app.include_router(secrets_router)
    app.include_router(schedules_router)
    app.include_router(tags_router)
    app.include_router(users_router)
    app.include_router(org_router)
    app.include_router(editor_router)
    app.include_router(registry_repos_router)
    app.include_router(registry_actions_router)
    app.include_router(org_settings_router)
    app.include_router(org_secrets_router)
    app.include_router(tables_router)
    app.include_router(cases_router)
    app.include_router(case_fields_router)
    app.include_router(workflow_folders_router)
    app.include_router(
        fastapi_users.get_users_router(UserRead, UserUpdate),
        prefix="/users",
        tags=["users"],
    )

    if AuthType.BASIC in config.TRACECAT__AUTH_TYPES:
        app.include_router(
            fastapi_users.get_auth_router(auth_backend),
            prefix="/auth",
            tags=["auth"],
        )
        app.include_router(
            fastapi_users.get_register_router(UserRead, UserCreate),
            prefix="/auth",
            tags=["auth"],
        )
        app.include_router(
            fastapi_users.get_reset_password_router(),
            prefix="/auth",
            tags=["auth"],
        )
        app.include_router(
            fastapi_users.get_verify_router(UserRead),
            prefix="/auth",
            tags=["auth"],
        )

    oauth_client = GoogleOAuth2(
        client_id=config.OAUTH_CLIENT_ID, client_secret=config.OAUTH_CLIENT_SECRET
    )
    # This is the frontend URL that the user will be redirected to after authenticating
    redirect_url = f"{config.TRACECAT__PUBLIC_APP_URL}/auth/oauth/callback"
    logger.info("OAuth redirect URL", url=redirect_url)
    app.include_router(
        fastapi_users.get_oauth_router(
            oauth_client,
            auth_backend,
            config.USER_AUTH_SECRET,
            # XXX(security): See https://fastapi-users.github.io/fastapi-users/13.0/configuration/oauth/#existing-account-association
            associate_by_email=True,
            is_verified_by_default=True,
            # Points the user back to the login page
            redirect_url=redirect_url,
        ),
        prefix="/auth/oauth",
        tags=["auth"],
        dependencies=[require_auth_type_enabled(AuthType.GOOGLE_OAUTH)],
    )
    if config.OIDC_DISCOVERY_URL:
        oidc_client = OpenID(
            client_id=config.OIDC_CLIENT_ID,
            client_secret=config.OIDC_CLIENT_SECRET,
            openid_configuration_endpoint=config.OIDC_DISCOVERY_URL,
        )
        oidc_redirect_url = f"{config.TRACECAT__PUBLIC_APP_URL}/auth/oidc/callback"
        app.include_router(
            get_oidc_oauth_router(
                oidc_client,
                auth_backend,
                fastapi_users.get_user_manager,
                config.USER_AUTH_SECRET,
                redirect_url=oidc_redirect_url,
                associate_by_email=True,
                is_verified_by_default=True,
            ),
            prefix="/auth/oidc",
            tags=["auth"],
            dependencies=[require_auth_type_enabled(AuthType.OIDC)],
        )
    app.include_router(
        saml_router,
        dependencies=[require_auth_type_enabled(AuthType.SAML)],
    )

    if AuthType.BASIC not in config.TRACECAT__AUTH_TYPES:
        # Need basic auth router for `logout` endpoint
        app.include_router(
            fastapi_users.get_logout_router(auth_backend),
            prefix="/auth",
            tags=["auth"],
        )

    # Exception handlers
    app.add_exception_handler(Exception, generic_exception_handler)
    app.add_exception_handler(TracecatException, tracecat_exception_handler)  # type: ignore  # type: ignore
    app.add_exception_handler(RequestValidationError, validation_exception_handler)  # type: ignore
    app.add_exception_handler(
        FastAPIUsersException,
        fastapi_users_auth_exception_handler,  # type: ignore
    )

    # Middleware
    # Add authorization cache middleware first so it's available for all requests
    app.add_middleware(AuthorizationCacheMiddleware)
    app.add_middleware(RequestLoggingMiddleware)
    if config.TRACECAT__APP_ENV != "development":
        app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allow_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    logger.info(
        "App started",
        env=config.TRACECAT__APP_ENV,
        origins=allow_origins,
        auth_types=config.TRACECAT__AUTH_TYPES,
    )
    return app


app = create_app()


@app.get("/", include_in_schema=False)
def root() -> dict[str, str]:
    return {"message": "Hello world. I am the API."}


class AppInfo(BaseModel):
    version: str
    public_app_url: str
    auth_allowed_types: list[AuthType]
    auth_basic_enabled: bool
    oauth_google_enabled: bool
    saml_enabled: bool
    oidc_enabled: bool


@app.get("/info", include_in_schema=False)
async def info(session: AsyncDBSession) -> AppInfo:
    """Non-sensitive information about the platform, for frontend configuration."""

    keys = {
        "auth_basic_enabled",
        "oauth_google_enabled",
        "saml_enabled",
        "oidc_enabled",
    }

    service = SettingsService(session, role=bootstrap_role())
    settings = await service.list_org_settings(keys=keys)
    keyvalues = {s.key: service.get_value(s) for s in settings}
    for key in keys:
        keyvalues[key] = get_setting_override(key) or keyvalues[key]
    return AppInfo(
        version=APP_VERSION,
        public_app_url=config.TRACECAT__PUBLIC_APP_URL,
        auth_allowed_types=list(config.TRACECAT__AUTH_TYPES),
        auth_basic_enabled=keyvalues["auth_basic_enabled"],
        oauth_google_enabled=keyvalues["oauth_google_enabled"],
        saml_enabled=keyvalues["saml_enabled"],
        oidc_enabled=keyvalues["oidc_enabled"],
    )


@app.get("/health", tags=["public"])
def check_health() -> dict[str, str]:
    return {"message": "Hello world. I am the API. This is the health endpoint."}
