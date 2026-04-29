from services.gateway.main import app
print([r.path for r in app.routes])
