import aiohttp
import asyncio
import logging
from urllib.parse import urlencode, urlparse, quote

logger = logging.getLogger(__name__)

BASE_PUBLIC_API_URL = "https://cloud-api.yandex.net/v1/disk/public/resources"

#extractingPublicKey 
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

        logger.warning(f"Не удалось извлечь public_key из URL: {url}")
        return None
    except Exception as e:
        logger.error(f"Ошибка при извлечении public_key из {url}: {e}")
        return None

#metadata
async def get_public_resource_meta(public_key: str, path: str = None, session: aiohttp.ClientSession = None) -> dict | None:
    params = {'public_key': public_key, 'limit': 1000}
    if path:
        params['path'] = path

    url = f"{BASE_PUBLIC_API_URL}?{urlencode(params, quote_via=quote)}"
    close_session = False
    if session is None:
        session = aiohttp.ClientSession()
        close_session = True

    try:
        async with session.get(url) as response:
            logger.debug(f"Запрос метаданных: URL={url}, Статус={response.status}")
            if response.status == 200:
                return await response.json()
            else:
                logger.error(f"Ошибка API Яндекса ({response.status}): {await response.text()}")
                return None
    except aiohttp.ClientError as e:
        logger.error(f"Ошибка сети при запросе метаданных {public_key}: {e}")
        return None
    except Exception as e:
        logger.error(f"Непредвиденная ошибка при запросе метаданных {public_key}: {e}")
        return None
    finally:
        if close_session and session:
            await session.close()


#getDownloadLink
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
            logger.debug(f"Запрос ссылки на скачивание: URL={url}, Статус={response.status}")
            if response.status == 200:
                data = await response.json()
                return data.get('href')
            else:
                logger.error(f"Ошибка API Яндекса при получении ссылки ({response.status}): {await response.text()}")
                return None
    except aiohttp.ClientError as e:
        logger.error(f"Ошибка сети при запросе ссылки на скачивание {public_key} ({path}): {e}")
        return None
    except Exception as e:
        logger.error(f"Непредвиденная ошибка при запросе ссылки на скачивание {public_key} ({path}): {e}")
        return None
    finally:
        if close_session and session:
            await session.close()