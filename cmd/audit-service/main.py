import os
import logging
import dotenv
import uvicorn
from fastapi import FastAPI

from internal.api.handlers import router

# Load environment variables from .env if present
dotenv.load_dotenv()

# Set up clean logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize FastAPI application
app = FastAPI(
    title="Zero-Trust Kubernetes Policy Audit Engine",
    description="API for auditing and evaluating Kubernetes NetworkPolicies",
    version="1.0.0"
)

# Include the endpoints router
app.include_router(router)

@app.get("/")
def root():
    """
    Root endpoint returning basic service information.
    """
    return {
        "service": "Zero-Trust Kubernetes Policy Audit Engine",
        "version": "1.0.0",
        "status": "running"
    }

if __name__ == "__main__":
    port = int(os.environ.get("AUDIT_SERVICE_PORT", 8080))
    logger.info(f"Starting server on port {port}")
    uvicorn.run(app, host="0.0.0.0", port=port)
