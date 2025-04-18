import aiohttp, asyncio, logging, mimetypes, zipfile, os, tempfile, aiofiles
from urllib.parse import quote, unquote
from pathlib import PurePath, Path
from typing import AsyncGenerator, List, Dict, Any, Set, Tuple
import math

# Django Imports
from django.shortcuts import render, redirect
from django.http import (
    HttpRequest, HttpResponse, StreamingHttpResponse,
    Http404, HttpResponseRedirect, HttpResponseServerError
)
from django.views.decorators.http import require_GET, require_POST
from django.utils.text import slugify
from django.utils.timezone import now
from django.conf import settings
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger

# Local Imports
from .yadisk_api import (
    get_public_resource_meta, get_public_resource_download_link,
    extract_public_key
)

# Async Helpers
from asgiref.sync import sync_to_async

logger = logging.getLogger(__name__)

# --- Constants ---
DEFAULT_PAGE_SIZE = 50
ALLOWED_PAGE_SIZES = [25, 50, 100]
DOWNLOAD_CONCURRENCY_LIMIT = 5 
FILE_CHUNK_SIZE = 8192


# --- Helper Functions ---

def get_file_category(item: Dict[str, Any]) -> str:
    if item.get('type') != 'file':
        return 'dir' 

    mime_type, _ = mimetypes.guess_type(item.get('name', ''))
    if not mime_type:
        return 'other'

    major_type = mime_type.split('/')[0]
    if major_type == 'image': return 'image'
    if major_type == 'video': return 'video'
    if major_type == 'audio': return 'audio'

    # Broaden document category
    if major_type == 'text' or mime_type in (
        'application/pdf', 'application/msword',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'application/vnd.ms-excel',
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        'application/vnd.ms-powerpoint',
        'application/vnd.openxmlformats-officedocument.presentationml.presentation',
        'application/rtf', 'application/vnd.oasis.opendocument.text',
        'application/vnd.oasis.opendocument.spreadsheet',
        'application/vnd.oasis.opendocument.presentation'
    ):
        return 'document'

    # Archive types
    if mime_type in (
        'application/zip', 'application/x-rar-compressed', 'application/vnd.rar',
        'application/x-7z-compressed', 'application/gzip', 'application/x-tar',
        'application/x-bzip2', 'application/x-xz'
    ):
        return 'archive'

    return 'other'

def filter_items(items: List[Dict[str, Any]], filter_type: str) -> List[Dict[str, Any]]:
    if filter_type == 'all':
        return items
    return [
        item for item in items
        if item.get('type') == 'file' and get_file_category(item) == filter_type
    ]

def generate_breadcrumbs(path_str: str) -> List[Dict[str, str]]:
    breadcrumbs = [{'name': 'Корень', 'path': '/'}]
    normalized_path = Path(path_str.replace('\\', '/')).as_posix().strip('/')
    parts = [part for part in normalized_path.split('/') if part]
    current_crumb_path = ''
    for part in parts:
        current_crumb_path += f'/{part}'
        breadcrumbs.append({'name': part, 'path': current_crumb_path})
    return breadcrumbs

def process_api_items(items_list_raw: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], Set[str]]:
    processed_items = []
    available_types = set()
    for item in items_list_raw:
        item_copy = item.copy()
        item_type = item_copy.get('type')

        if item_type == 'file':
            category = get_file_category(item_copy)
            available_types.add(category)
            api_path_str = item_copy.get('path', '')

            if api_path_str.startswith('disk:'):
                 public_root_prefix_len = api_path_str.find('/', 6) + 1
                 relative_path = api_path_str[public_root_prefix_len:] if public_root_prefix_len > 0 else ''
            else:
                 relative_path = api_path_str

            item_copy['url_path'] = Path(relative_path.replace('\\', '/')).as_posix()
            item_copy['normalized_api_path'] = f"/{item_copy['url_path'].lstrip('/')}"

        elif item_type == 'dir':
            dir_path = item_copy.get('path', '/')
            if dir_path.startswith('disk:'):
                 public_root_prefix_len = dir_path.find('/', 6) + 1
                 relative_path = dir_path[public_root_prefix_len:] if public_root_prefix_len > 0 else ''
                 item_copy['path_param'] = f"/{relative_path}".replace('//','/')
            else:
                item_copy['path_param'] = f"/{dir_path.lstrip('/')}".replace('//','/')

        processed_items.append(item_copy)

    logger.debug(f"process_api_items обнаружил типы файлов: {available_types}")
    return processed_items, available_types

# --- Async Session Helpers ---
async def get_session_value(request: HttpRequest, key: str, default: Any = None):
    return await sync_to_async(request.session.get)(key, default)

async def set_session_value(request: HttpRequest, key: str, value: Any):
    await sync_to_async(request.session.__setitem__)(key, value)
    await sync_to_async(request.session.save)()

async def pop_session_value(request: HttpRequest, key: str, default: Any = None):
    val = await sync_to_async(request.session.pop)(key, default)
    await sync_to_async(request.session.save)()
    return val

async def clear_session_keys(request: HttpRequest, keys: List[str]):
    changed = False
    for key in keys:
        if key in request.session:
            await pop_session_value(request, key)
            changed = True
    if changed:
        await sync_to_async(request.session.save)()


# --- Main View ---

async def index(request: HttpRequest) -> HttpResponse:
    context = {
        'error': None,
        'data': None,
        'items': None,
        'public_url': '',
        'filter_type': 'all',
        'resource_type': None,
        'available_file_types': set(),
        'current_path': '/',
        'breadcrumbs': [],
        'pagination': None,
        'current_page_size': DEFAULT_PAGE_SIZE,
        'allowed_page_sizes': ALLOWED_PAGE_SIZES,
    }

    # Get parameters from GET request
    public_url_from_query = request.GET.get('public_url', '').strip()
    current_path_param = request.GET.get('path', '/')
    filter_from_get = request.GET.get('filter', 'all')
    try:
        page_num = int(request.GET.get('page', '1'))
        page_num = max(1, page_num)
    except ValueError:
        page_num = 1
    try:
        page_size = int(request.GET.get('limit', str(DEFAULT_PAGE_SIZE)))
        page_size = page_size if page_size in ALLOWED_PAGE_SIZES else DEFAULT_PAGE_SIZE
    except ValueError:
        page_size = DEFAULT_PAGE_SIZE

    public_url_from_post = request.POST.get('public_url', '').strip() if request.method == 'POST' else ''
    session_public_key = await get_session_value(request, 'public_key')

    public_url = public_url_from_post or public_url_from_query or session_public_key
    context['public_url'] = public_url
    context['current_page_size'] = page_size
    context['filter_type'] = filter_from_get

    if not public_url:
        logger.info("Нет public_url. Очистка сессии.")
        await clear_session_keys(request, ['public_key', 'resource_type', 'resource_name'])
        return render(request, 'viewer/index.html', context)

    # --- Process Public URL ---
    public_key = extract_public_key(public_url)
    if not public_key:
        context['error'] = "Некорректный URL или не удалось извлечь ключ."
        await clear_session_keys(request, ['public_key', 'resource_type', 'resource_name'])
        return render(request, 'viewer/index.html', context)

    if public_key != session_public_key or public_url_from_post:
        await set_session_value(request, 'public_key', public_key)
        await clear_session_keys(request, ['resource_type', 'resource_name'])
        logger.info(f"Установлен/Обновлен public_key в сессии: {public_key}")
        if request.method == 'POST':
             query_params = request.GET.copy()
             query_params['public_url'] = public_key
             query_params['path'] = '/'
             return redirect(f"{request.path}?{query_params.urlencode()}")


    # --- Fetch and Process Data ---
    normalized_path_param = Path(current_path_param.replace('\\', '/')).as_posix()
    api_path = normalized_path_param if normalized_path_param != '/' else None
    offset = (page_num - 1) * page_size
    context['current_path'] = normalized_path_param
    context['breadcrumbs'] = generate_breadcrumbs(normalized_path_param)

    logger.info(f"Запрос данных: key='{public_key}', path='{api_path}', limit={page_size}, offset={offset}")

    async with aiohttp.ClientSession() as session:
        meta_data = await get_public_resource_meta(
            public_key, path=api_path, limit=page_size, offset=offset, session=session
        )

    # --- Handle API Response ---
    if meta_data is None:
        context['error'] = "Ошибка сети при получении данных от API Яндекс.Диска."
    elif meta_data.get('error') == 'not_found':
        context['error'] = f"Ресурс не найден по пути: {normalized_path_param}"
    elif 'error' in meta_data:
        context['error'] = f"Ошибка API Яндекс.Диска: {meta_data.get('message', 'Неизвестная ошибка')}"
        await clear_session_keys(request, ['public_key', 'resource_type', 'resource_name'])
    else:
        # --- Process Successful Response ---
        resource_type = meta_data.get('type') 
        resource_name = meta_data.get('name', 'yadisk-item')

        session_resource_type = await get_session_value(request, 'resource_type')
        if not session_resource_type:
             async with aiohttp.ClientSession() as session:
                 root_meta = await get_public_resource_meta(public_key, path=None, limit=1, offset=0, session=session)
                 if root_meta and 'error' not in root_meta:
                     base_type = root_meta.get('type')
                     base_name = root_meta.get('name', 'yadisk-archive')
                     await set_session_value(request, 'resource_type', base_type)
                     await set_session_value(request, 'resource_name', base_name)
                     logger.info(f"Тип корневого ресурса ({base_type}) и имя ({base_name}) сохранены в сессии.")
                 else:
                      logger.warning("Не удалось получить метаданные корневого ресурса для сохранения в сессии.")


        context['data'] = meta_data

        items_list_processed = []
        total_items = 0

        if resource_type == 'file':
            processed_single, available_types_single = process_api_items([meta_data])
            if processed_single:
                context['data'] = processed_single[0]
                items_list_processed = processed_single
            total_items = 1
            context['available_file_types'] = available_types_single
            context['items'] = items_list_processed

        elif resource_type == 'dir' and '_embedded' in meta_data:
            raw_items = meta_data['_embedded']['items']
            all_items_processed, available_types = process_api_items(raw_items)
            context['available_file_types'] = available_types
            total_items = meta_data['_embedded'].get('total', len(all_items_processed))

            context['items'] = filter_items(all_items_processed, filter_from_get) if filter_from_get != 'all' else all_items_processed
        else:
            context['items'] = []
            context['available_file_types'] = set()
            total_items = 0

        # --- Setup Pagination ---
        if resource_type == 'dir' and total_items > page_size:
            total_pages = math.ceil(total_items / page_size)
            if total_pages > 1:
                 context['pagination'] = {
                    'current_page': page_num,
                    'total_pages': total_pages,
                    'total_items': total_items,
                    'has_previous': page_num > 1,
                    'has_next': page_num < total_pages,
                    'page_range': range(max(1, page_num - 3), min(total_pages + 1, page_num + 4)),
                    'needs_first_ellipses': page_num > 4,
                    'needs_last_ellipses': page_num < total_pages - 3,
                }

    return render(request, 'viewer/index.html', context)


# --- Download Views ---

@require_GET
async def download_file(request: HttpRequest, file_path: str) -> HttpResponse:
    logger.info(f"Запрос на скачивание одного файла: '{file_path}'")

    public_key = await get_session_value(request, 'public_key')
    base_resource_type = await get_session_value(request, 'resource_type')

    if not public_key:
        logger.warning("Попытка скачать файл без public_key в сессии.")
        raise Http404("Сессия истекла или не найдена. Пожалуйста, введите URL заново.")

    try:
        clean_path_str = Path(unquote(file_path).replace('\\', '/')).as_posix().lstrip('/')
        logger.debug(f"Очищенный путь файла для скачивания: '{clean_path_str}'")
    except Exception as e:
         logger.error(f"Ошибка декодирования/очистки file_path: '{file_path}'. Ошибка: {e}")
         raise Http404("Некорректный путь файла в URL.")

    path_to_request = f"/{clean_path_str}" if base_resource_type == 'dir' and clean_path_str else None

    file_name = PurePath(clean_path_str).name or "downloaded_file"

    async with aiohttp.ClientSession() as session:
        logger.debug(f"Запрос ссылки для скачивания: key={public_key}, path='{path_to_request}', file_name='{file_name}', base_resource_type={base_resource_type}")
        download_url = await get_public_resource_download_link(public_key, path=path_to_request, session=session)

        if download_url:
            logger.info(f"Получена ссылка для '{file_name}', РЕДИРЕКТ на: {download_url[:80]}...")
            return HttpResponseRedirect(download_url)
        else:
            logger.error(f"Не удалось получить ссылку для скачивания: key={public_key}, path='{path_to_request}'. Ошибка 404.")
            raise Http404(f"Не удалось получить ссылку для скачивания файла '{file_name}' от API Яндекса.")


# --- ZIP Download Helpers ---

async def _fetch_download_links(public_key: str, api_paths: List[str], session: aiohttp.ClientSession) -> Tuple[List[Dict[str, str]], List[str]]:
    link_tasks = []
    for api_path in api_paths:
        path_param = api_path if api_path != '/' else None
        link_tasks.append(
            get_public_resource_download_link(public_key, path=path_param, session=session)
        )

    logger.info(f"Запрос {len(link_tasks)} ссылок на скачивание...")
    download_links_results = await asyncio.gather(*link_tasks, return_exceptions=True)

    files_to_download = []
    failed_links = []
    for i, result in enumerate(download_links_results):
        api_path = api_paths[i]
        if isinstance(result, Exception) or result is None:
            logger.warning(f"Не удалось получить ссылку для '{api_path}': {result}")
            failed_links.append(api_path)
        else:
            files_to_download.append({'api_path': api_path, 'url': result})

    return files_to_download, failed_links

async def _download_file_to_temp(file_info: Dict[str, str], temp_dir: str, session: aiohttp.ClientSession, semaphore: asyncio.Semaphore) -> Tuple[str, str] | None:
    async with semaphore:
        api_path = file_info['api_path']
        url = file_info['url']
        original_filename = PurePath(api_path.lstrip('/')).name or f"file_{hash(api_path)}"
        temp_file_path = os.path.join(temp_dir, f"{original_filename}.{abs(hash(api_path))}.tmp")
        logger.debug(f"Начало скачивания '{api_path}' в '{temp_file_path}'")

        try:
            timeout = aiohttp.ClientTimeout(total=600, connect=30, sock_read=600)
            headers = {'User-Agent': 'YadiskViewerApp/1.0 (+https://github.com/anpain/yadisk_viewer_project)'}

            async with session.get(url, timeout=timeout, headers=headers, allow_redirects=True) as resp:
                resp.raise_for_status() 
                async with aiofiles.open(temp_file_path, mode='wb') as f:
                    file_size = 0
                    async for chunk in resp.content.iter_chunked(FILE_CHUNK_SIZE):
                        await f.write(chunk)
                        file_size += len(chunk)
                logger.info(f"Успешно скачан '{api_path}' ({file_size} байт) в '{temp_file_path}'")
                return api_path, temp_file_path
        except asyncio.TimeoutError:
            logger.error(f"Тайм-аут при скачивании файла '{api_path}' с {url[:80]}...")
        except aiohttp.ClientResponseError as e:
             logger.error(f"Ошибка HTTP {e.status} при скачивании файла '{api_path}' с {url[:80]}...: {e.message}")
        except Exception as e:
            logger.error(f"Ошибка скачивания файла '{api_path}' с {url[:80]}...: {e}")

        if os.path.exists(temp_file_path):
            try:
                await sync_to_async(os.remove)(temp_file_path)
            except OSError:
                logger.warning(f"Не удалось удалить временный файл '{temp_file_path}' после ошибки скачивания.")
        return None

async def _download_selected_files(
    files_to_download: List[Dict[str, str]],
    temp_dir: str,
    session: aiohttp.ClientSession
) -> Tuple[Dict[str, str], List[str]]:
    semaphore = asyncio.Semaphore(DOWNLOAD_CONCURRENCY_LIMIT)
    download_tasks = [
        asyncio.create_task(_download_file_to_temp(file_info, temp_dir, session, semaphore))
        for file_info in files_to_download
    ]

    logger.info(f"Запуск {len(download_tasks)} задач скачивания (лимит {DOWNLOAD_CONCURRENCY_LIMIT})...")
    download_results = await asyncio.gather(*download_tasks)

    downloaded_files_map = {}
    failed_downloads = []

    original_api_paths = {info['api_path'] for info in files_to_download}
    processed_api_paths = set()

    for result in download_results:
        if result:
            api_path, temp_path = result
            downloaded_files_map[api_path] = temp_path
            processed_api_paths.add(api_path)

    failed_downloads = list(original_api_paths - processed_api_paths)

    return downloaded_files_map, failed_downloads


def _create_zip_archive_sync(zip_filepath: str, files_to_archive: Dict[str, str]):
    logger.info(f"Начало создания ZIP-архива '{zip_filepath}'...")
    try:
        with zipfile.ZipFile(zip_filepath, 'w', compression=zipfile.ZIP_STORED) as zf:
            for api_path, temp_file_path in files_to_archive.items():
                arcname = api_path.lstrip('/')
                if not arcname:
                    arcname = f"file_{hash(api_path)}"
                logger.debug(f"Добавление в ZIP: '{temp_file_path}' как '{arcname}'")
                zf.write(temp_file_path, arcname=arcname)
        logger.info(f"ZIP-архив '{zip_filepath}' ({os.path.getsize(zip_filepath)} байт) успешно создан.")
        return True
    except Exception as e:
        logger.exception(f"Ошибка при создании ZIP-архива '{zip_filepath}': {e}")
        if os.path.exists(zip_filepath):
            try: os.remove(zip_filepath)
            except OSError: pass
        return False


async def _zip_file_stream_generator(filepath_to_stream: str, zip_filename_for_log: str) -> AsyncGenerator[bytes, None]:
    f = None
    try:
        f = await aiofiles.open(filepath_to_stream, mode='rb')
        while True:
            chunk = await f.read(FILE_CHUNK_SIZE)
            if not chunk:
                break
            yield chunk
        logger.info(f"Завершена отправка потока для ZIP '{zip_filename_for_log}'")
    except Exception as e:
        logger.exception(f"Ошибка при стриминге ZIP файла '{filepath_to_stream}': {e}")
        if f and not f.closed:
            try: await f.close()
            except Exception: pass
        raise
    finally:
        # --- Cleanup ---
        if f and not f.closed:
            await f.close()
            logger.debug(f"aiofiles объект закрыт для: {filepath_to_stream}")

        logger.debug(f"Удаление временного ZIP файла: {filepath_to_stream}")
        try:
            await sync_to_async(os.remove)(filepath_to_stream)
            logger.info(f"Временный ZIP файл '{filepath_to_stream}' успешно удален.")
        except FileNotFoundError:
             logger.warning(f"Временный ZIP файл '{filepath_to_stream}' не найден для удаления (возможно, уже удален).")
        except OSError as e:
            logger.error(f"Не удалось удалить временный ZIP файл '{filepath_to_stream}': {e}")


@require_POST
async def download_zip(request: HttpRequest) -> HttpResponse:
    logger.info("Запуск скачивания ZIP-архива (используя временные файлы + zipfile)")
    public_key = await get_session_value(request, 'public_key')
    resource_type = await get_session_value(request, 'resource_type')
    resource_name = await get_session_value(request, 'resource_name', 'yadisk-archive')

    if not public_key:
        logger.warning("Попытка скачать ZIP без public_key в сессии.")
        return redirect('viewer:index')

    if resource_type != 'dir':
        logger.warning(f"Попытка скачать ZIP для ресурса не-папки: key={public_key}, type={resource_type}")
        return redirect('viewer:index')

    selected_paths = request.POST.getlist('selected_files')
    if not selected_paths:
        logger.warning("Попытка скачать ZIP без выбранных файлов.")
        return redirect('viewer:index')

    safe_name = slugify(resource_name) or 'archive'
    zip_filename = f"{safe_name}-{now().strftime('%Y%m%d_%H%M%S')}.zip"
    logger.info(f"Генерация ZIP '{zip_filename}' для {len(selected_paths)} выбранных элементов.")

    temp_dir_obj = tempfile.TemporaryDirectory()
    temp_dir_path = temp_dir_obj.name
    logger.debug(f"Создана временная директория для скачивания: {temp_dir_path}")

    downloaded_files_map: Dict[str, str] = {}
    failed_files: List[str] = []
    zip_temp_filepath: str | None = None

    try:
        async with aiohttp.ClientSession() as session:
            files_ready_for_download, failed_links = await _fetch_download_links(public_key, selected_paths, session)
            failed_files.extend(failed_links)

            if not files_ready_for_download:
                logger.error("Не удалось получить ни одной ссылки для скачивания.")
                temp_dir_obj.cleanup()

                return HttpResponse("Не удалось получить ссылки для скачивания выбранных файлов.", status=500)

            downloaded_files_map, failed_downloads = await _download_selected_files(
                files_ready_for_download, temp_dir_path, session
            )
            failed_files.extend(failed_downloads)

        if not downloaded_files_map:
            logger.error("Не удалось скачать ни одного файла.")
            temp_dir_obj.cleanup()
            return HttpResponse("Не удалось скачать ни одного из выбранных файлов.", status=500)

        logger.info(f"Скачано {len(downloaded_files_map)} файлов во временную директорию '{temp_dir_path}'.")
        if failed_files:
             logger.warning(f"Не удалось получить ссылку или скачать {len(failed_files)} файлов: {failed_files}")

        zip_temp_file = await sync_to_async(tempfile.NamedTemporaryFile)(delete=False, suffix='.zip')
        
        zip_temp_filepath = zip_temp_file.name
        await sync_to_async(zip_temp_file.close)()
        logger.debug(f"Временный файл для ZIP (системный temp): {zip_temp_filepath}")



        loop = asyncio.get_running_loop()
        zip_success = await loop.run_in_executor(
            None,
            _create_zip_archive_sync,
            zip_temp_filepath,
            downloaded_files_map
        )

        logger.debug(f"Удаление временной директории со скачанными файлами: {temp_dir_path}")
        try:
            temp_dir_obj.cleanup()
            logger.info(f"Временная директория '{temp_dir_path}' успешно очищена.")
        except Exception as e:
             logger.error(f"Ошибка при очистке временной директории '{temp_dir_path}': {e}")


        if not zip_success:
             logger.error(f"Создание ZIP архива '{zip_temp_filepath}' не удалось.")
             return HttpResponseServerError("Ошибка при создании ZIP-архива на сервере.")

        response = StreamingHttpResponse(
            _zip_file_stream_generator(zip_temp_filepath, zip_filename),
            content_type='application/zip'
        )

        try:
            ascii_name = zip_filename.encode('ascii').decode('ascii')
            response['Content-Disposition'] = f'attachment; filename="{ascii_name}"'
        except UnicodeEncodeError:
            encoded_name = quote(zip_filename)
            response['Content-Disposition'] = f"attachment; filename*=UTF-8''{encoded_name}"

        logger.info(f"Отправка StreamingHttpResponse для ZIP: {zip_filename}")
        return response

    except Exception as e:
        logger.exception(f"Критическая ошибка в обработчике download_zip: {e}")

        # --- Cleanup on critical error ---
        if 'temp_dir_obj' in locals() and hasattr(temp_dir_obj, 'name') and os.path.exists(temp_dir_obj.name):
            try:
                temp_dir_obj.cleanup()
                logger.debug("Временная директория скачивания очищена из-за критической ошибки.")
            except Exception as cleanup_err:
                logger.error(f"Ошибка при очистке временной директории скачивания во время обработки ошибки: {cleanup_err}")

        if zip_temp_filepath and os.path.exists(zip_temp_filepath):
             try:
                 os.remove(zip_temp_filepath)
                 logger.debug("Временный ZIP файл удален из-за критической ошибки.")
             except OSError as remove_err:
                 logger.error(f"Ошибка при удалении временного ZIP файла во время обработки ошибки: {remove_err}")

        return HttpResponseServerError("Внутренняя ошибка сервера при обработке запроса на ZIP-архив.")