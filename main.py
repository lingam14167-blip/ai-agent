from contextlib import asynccontextmanager
from collections.abc import AsyncIterator
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
from typing import Literal

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

load_dotenv()

import agent
import auditlog
import currency
import mandate
import paypal
import report

BASE_DIR = Path(__file__).resolve().parent
auditlog.init_db()


def initialize_app():
    auditlog.init_db()
    if mandate.get_current() is None:
        expires_at = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
        mandate.create_and_store(
            {
                "user": "Demo User",
                "budget": 50,
                "currency": "INR",
                "allowed_categories": ["accessories"],
                "allowed_merchants": ["Demo Accessories Shop", "Flipkart"],
                "expires_at": expires_at,
            }
        )


def tamper_enabled():
    return os.getenv("ENABLE_TAMPER", "true").strip().lower() not in {
        "0",
        "false",
        "no",
        "off",
    }


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    initialize_app()
    print("AgentProof AI started", flush=True)
    yield


app = FastAPI(title="AgentProof AI", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")


class MandateInput(BaseModel):
    budget: float
    currency: Literal["INR", "USD"] = "INR"
    allowed_categories: list[str]
    allowed_merchants: list[str]
    expires_at: str


class AgentInput(BaseModel):
    request: str
    rogue: bool = False
    currency: Literal["INR", "USD"] = "INR"


@app.get("/")
def home():
    return FileResponse(
        BASE_DIR / "static" / "index.html",
        headers={"Cache-Control": "no-store"},
    )


@app.get("/health")
def health():
    configured_port = os.getenv("PORT") or os.getenv("APP_PORT")
    port = int(configured_port) if configured_port and configured_port.isdigit() else None
    return {"app": "AgentProof AI", "port": port, "status": "ok"}


@app.get("/config")
def get_config():
    return {"enable_tamper": tamper_enabled()}


@app.post("/mandate")
def create_mandate(payload: MandateInput):
    try:
        return mandate.create_and_store(payload.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@app.get("/mandate")
def get_mandate():
    return mandate.get_current()


@app.post("/agent/run")
def run_agent(payload: AgentInput):
    return agent.run_agent(payload.request, payload.rogue, payload.currency)


@app.post("/paypal/capture/{order_id}")
def capture_paypal_order(order_id: str):
    events = auditlog.get_log()
    order_event = next(
        (
            event
            for event in reversed(events)
            if event["event_type"] == "paypal_order_created"
            and event["data"].get("order_id") == order_id
        ),
        None,
    )
    if order_event is None:
        raise HTTPException(
            status_code=404,
            detail="PayPal order was not authorized by AgentProof.",
        )
    if not auditlog.verify_chain()[0]:
        raise HTTPException(
            status_code=409,
            detail="The audit chain is broken; payment capture is blocked.",
        )

    purchase_events = [
        event for event in events if event["purchase_id"] == order_event["purchase_id"]
    ]
    mandate_event = next(
        (
            event
            for event in purchase_events
            if event["event_type"] == "mandate_used"
        ),
        None,
    )
    decision_event = next(
        (
            event
            for event in purchase_events
            if event["event_type"] == "policy_decision"
        ),
        None,
    )
    if mandate_event is None or decision_event is None:
        raise HTTPException(
            status_code=409,
            detail="The order is missing its mandate or policy evidence.",
        )

    signed_mandate = mandate_event["data"].get("mandate")
    signature = mandate_event["data"].get("signature")
    legacy_currency = "currency" not in order_event["data"]
    if not signature and legacy_currency:
        current_mandate = mandate.get_current()
        if current_mandate and current_mandate["mandate"] == signed_mandate:
            signature = current_mandate["signature"]
    if not mandate.verify_mandate(signed_mandate, signature):
        raise HTTPException(
            status_code=409,
            detail="The order's signed mandate could not be verified.",
        )
    try:
        signed_currency = currency.mandate_currency(signed_mandate)
        order_currency = order_event["data"].get("currency")
        if order_currency is None and legacy_currency:
            order_currency = signed_currency
        currency.validate_currency(order_currency)
    except (AttributeError, ValueError):
        raise HTTPException(status_code=409, detail="The order currency is invalid.") from None
    purchase = decision_event["data"].get("purchase")
    purchase_currency = (
        purchase.get("currency")
        if isinstance(purchase, dict)
        else None
    )
    if purchase_currency is None and legacy_currency:
        purchase_currency = signed_currency
    if (
        decision_event["data"].get("decision") != "ALLOW"
        or not isinstance(purchase, dict)
        or purchase_currency != signed_currency
        or order_currency != signed_currency
        or order_event["purchase_id"] != decision_event["purchase_id"]
    ):
        raise HTTPException(
            status_code=409,
            detail="The order does not match its signed mandate.",
        )
    order_amount = order_event["data"].get("amount")
    if order_amount is None and legacy_currency and isinstance(purchase, dict):
        order_amount = purchase.get("amount")
    if order_amount is None or str(purchase.get("amount")) != str(order_amount):
        raise HTTPException(
            status_code=409,
            detail="The order amount does not match its authorized purchase.",
        )

    try:
        access_token = paypal.get_access_token()
        capture = paypal.capture_order(
            access_token,
            order_id,
            expected_currency=signed_currency,
            expected_amount=order_amount,
        )
    except paypal.PayPalError as exc:
        auditlog.append_event(
            order_event["purchase_id"],
            "paypal_capture_failed",
            {"name": exc.name, "issue": exc.issue},
        )
        raise HTTPException(
            status_code=502,
            detail={
                "message": str(exc),
                "name": exc.name,
                "issue": exc.issue,
            },
        ) from exc
    auditlog.append_event(
        order_event["purchase_id"],
        "paypal_captured",
        {
            "capture_id": capture["capture_id"],
            "status": capture["status"],
            "amount": capture["amount"],
            "currency": capture["currency"],
        },
    )
    return {"order_id": order_id, **capture}


@app.get("/log")
def get_log():
    return auditlog.get_log()


@app.get("/log/verify")
def verify_log():
    valid, broken_entry_id = auditlog.verify_chain()
    return {"valid": valid, "broken_entry_id": broken_entry_id}


@app.post("/log/tamper")
def tamper_log():
    if not tamper_enabled():
        raise HTTPException(status_code=403, detail="Audit log tampering is disabled.")
    try:
        return auditlog.tamper_oldest_entry()
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/dispute/{purchase_id}")
def dispute_report(purchase_id: str):
    return report.build_report(purchase_id)
