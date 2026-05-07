from motor.motor_asyncio import AsyncIOMotorClient
from app.core.config import settings
from pymongo.errors import ConfigurationError

client: AsyncIOMotorClient = None

async def connect_db():
    global client
    mongo_kwargs = {
        # Fail faster on invalid/unreachable servers at startup.
        "serverSelectionTimeoutMS": 8000,
    }

    if settings.MONGODB_URL.startswith("mongodb+srv://"):
        mongo_kwargs["tls"] = True

    try:
        client = AsyncIOMotorClient(settings.MONGODB_URL, **mongo_kwargs)
        await client.admin.command("ping")
        print("Connected to MongoDB")
    except ConfigurationError as exc:
        raise RuntimeError(
            "MongoDB DNS/SRV resolution failed. If you are using an Atlas mongodb+srv URL, "
            "check your internet/DNS and cluster hostname, or switch to a local mongodb:// URL. "
            f"Original error: {exc}"
        ) from exc

async def close_db():
    global client
    if client:
        client.close()
        print("Disconnected from MongoDB")

def get_db():
    if client is None:
        raise RuntimeError("Database client is not connected")
    return client[settings.DATABASE_NAME]
