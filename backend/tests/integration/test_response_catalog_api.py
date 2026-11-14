"""Response catalog access follows the existing legacy role boundary."""

from tests.integration.conftest import PB2API


def test_catalog_is_read_only_and_available_to_every_active_role(pb2_api: PB2API) -> None:
    for role in ("analyst", "senior", "admin"):
        headers = pb2_api.login(role)
        pb2_api.client.cookies.clear()
        response = pb2_api.client.get("/api/response/catalog", headers=headers)
        assert response.status_code == 200
        assert response.headers["Cache-Control"] == "no-store"
        items = {item["action_type"]: item for item in response.json()["items"]}
        assert items["firewall_drop"]["ttl_required"] is True
        assert items["isolate_host"]["execution_modes"] == ["manual"]
        assert items["release_host"]["requestable"] is False
    pb2_api.client.cookies.clear()
    assert pb2_api.client.get("/api/response/catalog").status_code == 401
