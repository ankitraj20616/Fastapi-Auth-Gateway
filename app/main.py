from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .routes import router
from .otel_config import setup_opentelemetry
from .metrices_middleware import MetricsMiddleware

app = FastAPI(title= "Supabase Auth Gateway")

setup_opentelemetry(app, service_name="fastapi-auth-gateway")
app.add_middleware(MetricsMiddleware, service_name="fastapi-auth-gateway")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)