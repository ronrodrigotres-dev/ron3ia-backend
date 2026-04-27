from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from remediation_router import router as remediation_router

app = FastAPI(title="RON3IA Remediation API", version="5.0.0")

app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

app.include_router(remediation_router)

@app.get("/health")
async def health():
    return {"status": "ok", "service": "ron3ia-remediation"}
