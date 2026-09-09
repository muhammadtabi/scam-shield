from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
from app.core.config import settings
from app.db.database import connect_db, close_db
from app.ml.predictor import load_models
from app.api.routes import auth, detection, reports, dashboard

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    await connect_db()
    load_models()
    yield
    # Shutdown
    await close_db()

app = FastAPI(
    title="Scam Shield API",
    description="AI-Powered Scam Detection and Awareness Dashboard",
    version="1.0.0",
    lifespan=lifespan
)


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    messages = []

    for error in exc.errors():
        loc = error.get("loc", [])
        field = loc[-1] if loc else "field"
        message = error.get("msg", "Invalid input")

        if isinstance(message, str) and message.lower().startswith("value error,"):
            message = message.split(",", 1)[1].strip()

        field_name = field.replace("_", " ").capitalize() if isinstance(field, str) else "Field"
        messages.append(f"{field_name}: {message}")

    # Keep output compact while preserving all unique messages.
    unique_messages = list(dict.fromkeys(messages))
    summary = "; ".join(unique_messages) if unique_messages else "Invalid request payload"

    return JSONResponse(
        status_code=422,
        content={
            "detail": summary,
            "errors": unique_messages,
        },
    )

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Routers
app.include_router(auth.router,       prefix="/api/auth",      tags=["Auth"])
app.include_router(detection.router,  prefix="/api/detect",    tags=["Detection"])
app.include_router(reports.router,    prefix="/api/reports",   tags=["Reports"])
app.include_router(dashboard.router,  prefix="/api/dashboard", tags=["Dashboard"])

@app.get("/")
async def root():
    return {"message": "Scam Shield API is running 🛡️", "version": "1.0.0"}

@app.get("/health")
async def health():
    return {"status": "healthy", "timestamp": __import__("datetime").datetime.utcnow()}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
