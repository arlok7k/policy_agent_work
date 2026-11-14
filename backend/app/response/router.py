"""Legacy-role-protected response catalog and action endpoints."""

from typing import Annotated

from fastapi import APIRouter, Depends, Response

from app.auth.roles import require_operation
from app.auth.session import SessionIdentity
from app.core.http import private_json
from app.response.catalog import CatalogPage, catalog_page

router = APIRouter(prefix="/api/response", tags=["response"])
ResponseReader = Annotated[SessionIdentity, Depends(require_operation("response_read"))]


@router.get("/catalog", response_model=CatalogPage)
def catalog(response: Response, identity: ResponseReader) -> CatalogPage:
    private_json(response)
    return catalog_page()
