import aiohttp
import logging
from urllib.parse import urlencode, urlparse, quote
import hashlib

from django.core.cache import cache
from asgiref.sync import sync_to_async

logger = logging.getLogger(__name__)

BASE_PUBLIC_API_URL = "https://cloud-api.yandex.net/v1/disk/public/resources"
CACHE_TTL = 300

def extract_public_key(url: str) -> str | None:
    try:
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        parsed_url = urlparse(url)
        if parsed_url.netloc in ('disk.yandex.ru', 'disk.yandex.com', 'yadi.sk'):
            path_parts = [part for part in parsed_url.path.split('/') if part]
            if len(path_parts) >= 2 and path_parts[0] in ('d', 'i'):
                return url
            elif len(path_parts) == 1 and parsed_url.netloc == 'yadi.sk':
                 return url
        logger.warning(f"Не удалось извлечь public_key из URL-адреса: {url}")
        return None
    except Exception as e:
        logger.error(f"Ошибка при извлечении публичного ключа из URL {url}: {e}")
        return None

def generate_cache_key(prefix: str, *args) -> str:
    key_string = f"{prefix}:{':'.join(map(str, args))}"
    return hashlib.md5(key_string.encode()).hexdigest()

sync_cache_get = sync_to_async(cache.get)
sync_cache_set = sync_to_async(cache.set)

async def get_public_resource_meta(public_key: str, path: str = None, limit: int = 50, offset: int = 0, session: aiohttp.ClientSession = None) -> dict | None:
    current_path = path or '/'
    cache_key = generate_cache_key("yd_meta_v2", public_key, current_path, limit, offset)
    logger.debug(f"Checking cache for key: {cache_key} (public_key={public_key}, path={current_path}, limit={limit}, offset={offset})")

    cached_data = await sync_cache_get(cache_key)
    if cached_data is not None:
        logger.info(f"Поиск ключа в кэше: {cache_key}")
        return cached_data
    else:
        logger.info(f"Ошибка кэширования ключа: {cache_key}")

    params = {
        'public_key': public_key,
        'limit': limit,
        'offset': offset,
        'sort': 'type,name'
    }
    if path:
        params['path'] = path

    url = f"{BASE_PUBLIC_API_URL}?{urlencode(params, quote_via=quote)}"
    close_session = False
    if session is None:
        session = aiohttp.ClientSession()
        close_session = True

    try:
        async with session.get(url) as response:
            logger.debug(f"Запрашивающие метаданные: URL={url}, Статус={response.status}")
            if response.status == 200:
                data = await response.json()
                if isinstance(data, dict) and 'error' not in data:
                    logger.info(f"Настройка кэша для ключа: {cache_key} с TTL: {CACHE_TTL}")
                    await sync_cache_set(cache_key, data, timeout=CACHE_TTL)
                elif 'error' in data:
                     logger.warning(f"Получена ошибка API, не кэшируется ответ для ключа {cache_key}. Ошибка: {data.get('message')}")
                return data
            elif response.status == 404:
                logger.warning(f"Страница не найдена (404) для {url}")
                return {'error': 'not_found', 'message': 'Resource not found'}
            else:
                logger.error(f"Ошибка Yandex API ({response.status}) for {url}: {await response.text()}")
                return None
    except aiohttp.ClientError as e:
        logger.error(f"Сетевая ошибка при запросе метаданных {public_key}: {e}")
        return None
    except Exception as e:
        logger.exception(f"Непредвиденная ошибка при запросе метаданных {public_key}: {e}")
        return None
    finally:
        if close_session and session:
            await session.close()


async def get_public_resource_download_link(public_key: str, path: str = None, session: aiohttp.ClientSession = None) -> str | None:
    params = {'public_key': public_key}
    if path:
        params['path'] = path

    url = f"{BASE_PUBLIC_API_URL}/download?{urlencode(params, quote_via=quote)}"
    close_session = False
    if session is None:
        session = aiohttp.ClientSession()
        close_session = True
    try:
        async with session.get(url) as response:
            logger.debug(f"Запрашиваю ссылку для скачивания: URL={url}, Status={response.status}")
            if response.status == 200:
                data = await response.json()
                return data.get('href')
            else:
                logger.error(f"Ошибка при получении ссылки из API Яндекса ({response.status}): {await response.text()}")
                return None
    except aiohttp.ClientError as e:
        logger.error(f"Сетевая ошибка при запросе ссылки для скачивания {public_key} ({path}): {e}")
        return None
    except Exception as e:
        logger.exception(f"Непредвиденная ошибка при запросе ссылки для скачивания {public_key} ({path}): {e}")
        return None
    finally:
        if close_session and session:
            await session.close()