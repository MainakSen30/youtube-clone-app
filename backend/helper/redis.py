import redis as redis_sync
from secret_keys import SecretKeys

secret_keys = SecretKeys()

redis_client = redis_sync.Redis.from_url(
    secret_keys.REDIS_URL,
    decode_responses=True,
)


def get_redis():
    return redis_client
