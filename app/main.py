from fastapi import FastAPI
from .routes import router

app = FastAPI(title= "Supabase Auth Gateway")
app.include_router(router)