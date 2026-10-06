"""Integration tests against the FastAPI app. Requires a real Postgres +
Redis (see conftest.py / CI). Not run as part of the offline unit-test
sanity pass, but wired up for `docker-compose run api pytest`."""
import io

import pytest


@pytest.mark.asyncio
async def test_health(client):
    resp = await client.get("/api/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


@pytest.mark.asyncio
async def test_upload_rejects_bad_type(client):
    files = {"file": ("cat.png", io.BytesIO(b"\x89PNG\r\n\x1a\n"), "image/png")}
    resp = await client.post("/api/upload", files=files)
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_upload_and_status(client):
    # A minimal, inert PE header. Static analysis is safe (no execution);
    # this exercises the full pipeline without any real sample.
    files = {"file": ("test.exe", io.BytesIO(b"MZ" + b"\x00" * 62), "application/x-msdownload")}
    resp = await client.post("/api/upload", files=files)
    assert resp.status_code == 200
    analysis_id = resp.json()["analysis_id"]

    status_resp = await client.get(f"/api/status/{analysis_id}")
    assert status_resp.status_code == 200
    assert status_resp.json()["analysis_id"] == analysis_id


@pytest.mark.asyncio
async def test_status_404_for_unknown_id(client):
    resp = await client.get("/api/status/00000000-0000-0000-0000-000000000000")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_dashboard_returns_stats(client):
    resp = await client.get("/api/dashboard")
    assert resp.status_code == 200
    body = resp.json()
    assert "total_analyses" in body
