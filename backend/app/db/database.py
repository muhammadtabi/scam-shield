import re
from types import SimpleNamespace

from bson import ObjectId
from motor.motor_asyncio import AsyncIOMotorClient
from pymongo.errors import ConfigurationError

from app.core.config import settings


class InMemoryCursor:
    def __init__(self, collection, query=None):
        self.collection = collection
        self.query = query or {}
        self.skip_count = 0
        self.limit_count = None
        self.sort_key = None
        self.sort_direction = -1

    def sort(self, key, direction=-1):
        self.sort_key = key
        self.sort_direction = direction
        return self

    def skip(self, count):
        self.skip_count = count
        return self

    def limit(self, count):
        self.limit_count = count
        return self

    def _documents(self):
        documents = [
            dict(document) for document in self.collection._documents if _matches_query(document, self.query)
        ]
        if self.sort_key:
            documents = sorted(
                documents,
                key=lambda doc: doc.get(self.sort_key) or ObjectId(),
                reverse=self.sort_direction == -1,
            )
        if self.skip_count:
            documents = documents[self.skip_count:]
        if self.limit_count is not None:
            documents = documents[: self.limit_count]
        return documents

    def __aiter__(self):
        self._iterator = iter(self._documents())
        return self

    async def __anext__(self):
        try:
            return next(self._iterator)
        except StopIteration as exc:
            raise StopAsyncIteration from exc


class InMemoryCollection:
    def __init__(self, name):
        self.name = name
        self._documents = []

    async def insert_one(self, document):
        doc = dict(document)
        if "_id" not in doc:
            doc["_id"] = ObjectId()
        self._documents.append(doc)
        return SimpleNamespace(inserted_id=doc["_id"])

    async def find_one(self, query):
        for document in self._documents:
            if _matches_query(document, query):
                return dict(document)
        return None

    async def delete_one(self, query):
        for index, document in enumerate(self._documents):
            if _matches_query(document, query):
                del self._documents[index]
                return SimpleNamespace(deleted_count=1)
        return SimpleNamespace(deleted_count=0)

    async def delete_many(self, query):
        initial_len = len(self._documents)
        self._documents = [d for d in self._documents if not _matches_query(d, query)]
        return SimpleNamespace(deleted_count=initial_len - len(self._documents))

    async def count_documents(self, query):
        return sum(1 for document in self._documents if _matches_query(document, query))

    async def create_index(self, keys, **kwargs):
        return "index_created"

    def find(self, query=None):
        return InMemoryCursor(self, query)

    async def update_one(self, query, update, upsert=False):
        for document in self._documents:
            if _matches_query(document, query):
                _apply_update(document, update)
                return SimpleNamespace(matched_count=1, modified_count=1, upserted_id=None)

        if upsert:
            new_doc = dict(query)
            new_doc['_id'] = ObjectId()
            _apply_update(new_doc, update, is_insert=True)
            self._documents.append(new_doc)
            return SimpleNamespace(matched_count=0, modified_count=0, upserted_id=new_doc['_id'])

        return SimpleNamespace(matched_count=0, modified_count=0, upserted_id=None)

    async def update_many(self, query, update):
        modified = 0
        for document in self._documents:
            if _matches_query(document, query):
                _apply_update(document, update)
                modified += 1
        return SimpleNamespace(matched_count=modified, modified_count=modified, upserted_id=None)


class InMemoryDatabase:
    def __init__(self, name):
        self.name = name
        self._collections = {}

    def __getattr__(self, name):
        if name not in self._collections:
            self._collections[name] = InMemoryCollection(name)
        return self._collections[name]


class InMemoryMongoClient:
    def __init__(self):
        self._databases = {}

    def __getitem__(self, name):
        if name not in self._databases:
            self._databases[name] = InMemoryDatabase(name)
        return self._databases[name]

    def close(self):
        self._databases.clear()



def _apply_update(document, update, is_insert=False):
    """Apply MongoDB-style update operators to a document in-place."""
    for op, fields in update.items():
        if op == '$set':
            document.update(fields)
        elif op == '$setOnInsert' and is_insert:
            for k, v in fields.items():
                document.setdefault(k, v)
        elif op == '$unset':
            for k in fields:
                document.pop(k, None)

def _matches_query(document, query):
    if not query:
        return True

    for key, expected in query.items():
        if key == "$or" and isinstance(expected, list):
            if not any(_matches_query(document, sub_q) for sub_q in expected):
                return False
            continue

        value = document.get(key)
        if isinstance(expected, dict):
            for operator, operator_value in expected.items():
                if operator == "$gte" and (value is None or value < operator_value):
                    return False
                if operator == "$lt" and (value is None or value >= operator_value):
                    return False
                if operator == "$lte" and (value is None or value > operator_value):
                    return False
                if operator == "$gt" and (value is None or value <= operator_value):
                    return False
                if operator == "$ne" and value == operator_value:
                    return False
                if operator == "$regex":
                    flags = 0
                    if expected.get("$options") and "i" in expected.get("$options"):
                        flags |= re.IGNORECASE
                    if not re.search(operator_value, str(value or ""), flags):
                        return False
        else:
            if value != expected:
                return False
    return True


client = None


async def init_indexes(db):
    try:
        # Unique index on user email
        await db.users.create_index("email", unique=True)
        # Compound index on detections for user history and dashboard queries
        await db.detections.create_index([("user_id", 1), ("timestamp", -1)])
        # Unique index on gmail_connections by user
        await db.gmail_connections.create_index("user_id", unique=True)
        # Compound index on sms_messages by user and received timestamp
        await db.sms_messages.create_index([("user_id", 1), ("received_at", -1)])
    except Exception as exc:
        print(f"Warning: Failed to initialize database indexes: {exc}")


async def connect_db():
    global client
    mongo_kwargs = {
        "serverSelectionTimeoutMS": 15000,
        "connectTimeoutMS": 15000,
        "socketTimeoutMS": 15000,
    }

    if settings.MONGODB_URL.startswith("mongodb+srv://"):
        mongo_kwargs["tls"] = True

    # Try connecting to Atlas with up to 3 retries
    max_retries = 3
    for attempt in range(1, max_retries + 1):
        try:
            print(f"Connecting to MongoDB Atlas (attempt {attempt}/{max_retries})...")
            test_client = AsyncIOMotorClient(settings.MONGODB_URL, **mongo_kwargs)
            await test_client.admin.command("ping")
            client = test_client
            print(f"Connected to MongoDB Atlas: {settings.DATABASE_NAME}")
            await init_indexes(client[settings.DATABASE_NAME])
            return
        except Exception as exc:
            print(f"MongoDB connection attempt {attempt} failed ({exc})")
            if attempt < max_retries:
                import asyncio
                await asyncio.sleep(2)

    print("Warning: MongoDB Atlas unreachable after retries. Falling back to in-memory development database.")
    client = InMemoryMongoClient()
    await init_indexes(client[settings.DATABASE_NAME])


async def close_db():
    global client
    if client:
        if hasattr(client, "close"):
            client.close()
        print("Disconnected from MongoDB")
    client = None


def get_db():
    if client is None:
        raise RuntimeError("Database client is not connected")
    return client[settings.DATABASE_NAME]
