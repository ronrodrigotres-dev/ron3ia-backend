"""
main.py - RON3IA Backend PATCHED
Versión: 6.0.0 - SECURITY HARDENED

CONTROLES IMPLEMENTADOS:
- CONTROL 6: Secrets desde variables de entorno
- CONTROL 7: Autenticación con token + rate limiting
- CONTROL 8: Error handling sin stack traces
- CONTROL 9: Logging sanitizado
"""
import os
import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, Request, HTTPException, status, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from remediation_router import router as remediation_router

from dotenv import load_dotenv

# Cargar variables desde .env
load_dotenv()

# ────────────────────────────────────────────────────────────────
# CONTROL 9: Logging seguro
# ────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/ron3ia.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# ────────────────────────────────────────────────────────────────
# CONTROL 6: Secrets Management
# ────────────────────────────────────────────────────────────────

SECRET_TOKEN = os.getenv("RON3IA_SECRET_TOKEN")
if not SECRET_TOKEN:
    raise RuntimeError(
        "RON3IA_SECRET_TOKEN no encontrado. "
        "Ejecuta: .\\05_New-SecureEnvFile.ps1"
    )

ALLOWED_ORIGINS = os.getenv(
    "ALLOWED_ORIGINS",
    "https://ron3ia.cl,https://ronrodrigo3.com"
).split(",")

API_HOST = os.getenv("API_HOST", "0.0.0.0")
API_PORT = int(os.getenv("API_PORT", "8000"))
ENVIRONMENT = os.getenv("ENVIRONMENT", "production")

# ────────────────────────────────────────────────────────────────
# CONTROL 7: Rate Limiting
# ────────────────────────────────────────────────────────────────

limiter = Limiter(key_func=get_remote_address)

app = FastAPI(
    title="RON3IA Remediation API",
    version="6.0.0",
    docs_url="/docs" if ENVIRONMENT == "development" else None,
    redoc_url="/redoc" if ENVIRONMENT == "development" else None,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ────────────────────────────────────────────────────────────────
# CONTROL 7: CORS Hardened
# ────────────────────────────────────────────────────────────────

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,  # NO más ["*"]
    allow_credentials=True,
    allow_methods=["GET", "POST"],  # Solo métodos necesarios
    allow_headers=["Content-Type", "X-RON3IA-Token"],
)

# ────────────────────────────────────────────────────────────────
# CONTROL 7: Authentication Middleware
# ────────────────────────────────────────────────────────────────

async def verify_token(request: Request):
    """Valida el token de autenticación en header X-RON3IA-Token."""
    
    # Excluir health check de autenticación
    if request.url.path == "/health":
        return
    
    token = request.headers.get("X-RON3IA-Token")
    
    if not token:
        logger.warning(f"Intento de acceso sin token desde {request.client.host}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token de autenticación requerido",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    if token != SECRET_TOKEN:
        logger.warning(f"Token inválido desde {request.client.host}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token inválido",
        )
    
    logger.info(f"Acceso autorizado desde {request.client.host}")

@app.middleware("http")
async def authentication_middleware(request: Request, call_next):
    """Middleware global de autenticación."""
    await verify_token(request)
    response = await call_next(request)
    return response

# ────────────────────────────────────────────────────────────────
# CONTROL 8: Global Exception Handler
# ────────────────────────────────────────────────────────────────

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Maneja excepciones sin exponer stack traces en producción."""
    
    logger.error(
        f"Error no manejado: {type(exc).__name__} en {request.url.path}",
        exc_info=True if ENVIRONMENT == "development" else False
    )
    
    # En producción, no exponer detalles internos
    if ENVIRONMENT == "production":
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "detail": "Error interno del servidor",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )
    else:
        # En desarrollo, mostrar más detalles
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "detail": str(exc),
                "type": type(exc).__name__,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )

# ────────────────────────────────────────────────────────────────
# Routers
# ────────────────────────────────────────────────────────────────

app.include_router(remediation_router)

# ────────────────────────────────────────────────────────────────
# Health Check
# ────────────────────────────────────────────────────────────────

@app.get("/health")
@limiter.limit("60/minute")
async def health(request: Request):
    """Health check endpoint (sin autenticación)."""
    return {
        "status": "ok",
        "service": "ron3ia-remediation",
        "version": "6.0.0",
        "environment": ENVIRONMENT,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

# ────────────────────────────────────────────────────────────────
# Startup Event
# ────────────────────────────────────────────────────────────────

@app.on_event("startup")
async def startup_event():
    logger.info("=" * 60)
    logger.info("[SHIELD]  RON3IA Backend v6.0.0 - SECURITY HARDENED")
    logger.info("=" * 60)
    logger.info(f"Environment: {ENVIRONMENT}")
    logger.info(f"Host: {API_HOST}:{API_PORT}")
    logger.info(f"CORS Origins: {ALLOWED_ORIGINS}")
    logger.info(f"Authentication: ENABLED (X-RON3IA-Token)")
    logger.info(f"Rate Limiting: ENABLED")
    logger.info("=" * 60)

if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        "main:app",
        host=API_HOST,
        port=API_PORT,
        reload=(ENVIRONMENT == "development"),
        log_level="info",
    )


