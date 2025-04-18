import aiohttp
import asyncio
import logging
import mimetypes
import zipfile
import os
import tempfile
import aiofiles
from urllib.parse import quote, unquote, urlencode as standard_urlencode
from pathlib import PurePath, Path
from typing import AsyncGenerator
import math

from django.shortcuts import render, redirect
from django.http import HttpRequest, HttpResponse, StreamingHttpResponse, Http404, HttpResponseRedirect
from django.views.decorators.http import require_GET, require_POST
from django.utils.text import slugify
from django.utils.timezone import now
from django.conf import settings

from asgiref.sync import sync_to_async

from .yadisk_api import get_public_resource_meta, get_public_resource_download_link, extract_public_key

logger = logging.getLogger(__name__)

DEFAULT_PAGE_SIZE = 50
ALLOWED_PAGE_SIZES = [25, 50, 100]
DOWNLOAD_CONCURRENCY_LIMIT = 5
FILE_CHUNK_SIZE = 8192

def get_file_category(item: dict) -> str:
    if item.get('type') != 'file': return 'dir'
    mime_type, _ = mimetypes.guess_type(item.get('name', ''))
    category = 'other'
    if mime_type:
        major_type = mime_type.split('/')[0]
        if major_type == 'image': category = 'image'
        elif major_type == 'video': category = 'video'
        elif major_type == 'audio': category = 'audio'
        elif mime_type.startswith('text/') or mime_type in ('application/pdf', 'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', 'application/vnd.ms-excel', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', 'application/vnd.ms-powerpoint', 'application/vnd.openxmlformats-officedocument.presentationml.presentation'): category = 'document'
        elif mime_type in ('application/zip', 'application/x-rar-compressed', 'application/x-7z-compressed', 'application/gzip', 'application/x-tar', 'application/x-bzip2', 'application/vnd.rar'): category = 'archive'
    return category

def filter_items(items: list, filter_type: str) -> list:
    if filter_type == 'all': return items
    filtered = []
    for item in items:
        if item['type'] == 'dir': continue
        category = get_file_category(item)
        if filter_type == category or (filter_type == 'other' and category == 'other'): filtered.append(item)
    return filtered

async def index(request: HttpRequest) -> HttpResponse:
    context = {'error': None, 'data': None, 'items': None, 'public_url': '',
               'filter_type': 'all', 'resource_type': None, 'available_file_types': set(),
               'current_path': '/', 'breadcrumbs': [],
               'pagination': None, 'current_page_size': DEFAULT_PAGE_SIZE,
               'allowed_page_sizes': ALLOWED_PAGE_SIZES}

    get_session_value = sync_to_async(request.session.get)
    set_session_value = sync_to_async(request.session.__setitem__)
    pop_session_value = sync_to_async(request.session.pop)

    public_url_from_query = request.GET.get('public_url')
    current_path_param = request.GET.get('path', '/')
    filter_from_get = request.GET.get('filter', 'all')
    try: page_num = int(request.GET.get('page', '1')); page_num = max(1, page_num)
    except ValueError: page_num = 1
    try: page_size = int(request.GET.get('limit', str(DEFAULT_PAGE_SIZE))); page_size = page_size if page_size in ALLOWED_PAGE_SIZES else DEFAULT_PAGE_SIZE
    except ValueError: page_size = DEFAULT_PAGE_SIZE

    public_url = request.POST.get('public_url', '').strip() or public_url_from_query or await get_session_value('public_key')
    context['public_url'] = public_url
    context['current_page_size'] = page_size
    context['filter_type'] = filter_from_get

    def generate_breadcrumbs(path_str):
        breadcrumbs = [{'name': 'Корень', 'path': '/'}]
        normalized_path = Path(path_str.replace('\\', '/')).as_posix().strip('/')
        parts = [part for part in normalized_path.split('/') if part]
        current_crumb_path = ''
        for part in parts:
            current_crumb_path += f'/{part}'
            breadcrumbs.append({'name': part, 'path': current_crumb_path})
        return breadcrumbs

    def process_items(items_list_raw):
        processed_items = []
        available_types = set()
        for item in items_list_raw:
            item_copy = item.copy()
            if item_copy['type'] == 'file':
                category = get_file_category(item_copy)
                available_types.add(category)
                if 'path' in item_copy:
                    original_path = item_copy['path']
                    item_copy['url_path'] = Path(original_path.replace('\\', '/')).as_posix().lstrip('/')
                    item_copy['normalized_api_path'] = f"/{item_copy['url_path']}" if item_copy['url_path'] else "/"

            elif item_copy['type'] == 'dir':
                 item_copy['path_param'] = Path(item_copy.get('path', '/').replace('\\','/')).as_posix()
            processed_items.append(item_copy)
        logger.debug(f"process_items found types: {available_types}")
        return processed_items, available_types

    if public_url:
        public_key = extract_public_key(public_url)
        if not public_key:
            context['error'] = "Некорректный URL или не удалось извлечь ключ."
            await pop_session_value('public_key', None)
        else:
            session_public_key = await get_session_value('public_key')
            if public_key != session_public_key:
                await set_session_value('public_key', public_key)
                logger.info(f"Set/Update public_key in session: {public_key}")

            normalized_path_param = Path(current_path_param.replace('\\', '/')).as_posix()
            api_path = normalized_path_param if normalized_path_param != '/' else None
            offset = (page_num - 1) * page_size
            context['current_path'] = normalized_path_param
            context['breadcrumbs'] = generate_breadcrumbs(normalized_path_param)

            logger.info(f"Fetching data for key='{public_key}', path='{api_path}', limit={page_size}, offset={offset}")
            async with aiohttp.ClientSession() as session:
                meta_data = await get_public_resource_meta(
                    public_key, path=api_path, limit=page_size, offset=offset, session=session
                )

            if meta_data is None: context['error'] = "Ошибка сети при получении данных."
            elif meta_data.get('error') == 'not_found': context['error'] = f"Ресурс не найден по пути: {normalized_path_param}"
            elif 'error' in meta_data: context['error'] = f"Ошибка API Яндекса: {meta_data.get('message', 'Неизвестная ошибка')}"; await pop_session_value('public_key', None)
            else:
                resource_type = meta_data.get('type')
                resource_name = meta_data.get('name', 'yadisk-archive')
                await set_session_value('resource_type', resource_type)
                await set_session_value('resource_name', resource_name)
                context['data'] = meta_data; context['resource_type'] = resource_type

                items_list_raw = []
                total_items = 0
                if resource_type == 'file':
                    processed_single, available_types_single = process_items([meta_data])
                    if processed_single:
                        context['data'] = processed_single[0] 
                    items_list_raw = processed_single
                    total_items = 1
                    context['available_file_types'] = available_types_single
                elif resource_type == 'dir' and '_embedded' in meta_data:
                    all_items_processed, available_types = process_items(meta_data['_embedded']['items'])
                    context['available_file_types'] = available_types
                    total_items = meta_data['_embedded'].get('total', len(all_items_processed))

                    context['items'] = filter_items(all_items_processed, filter_from_get) if filter_from_get != 'all' else all_items_processed
                else:
                    context['items'] = []
                    context['available_file_types'] = set()
                    total_items = 0

                total_pages = math.ceil(total_items / page_size)
                if total_pages > 1:
                    context['pagination'] = {
                        'current_page': page_num,
                        'total_pages': total_pages,
                        'total_items': total_items,
                        'has_previous': page_num > 1,
                        'has_next': page_num < total_pages,
                        'page_range': range(1, total_pages + 1)
                    }
    else:
        logger.info("No public_url found. Clearing session.")
        await pop_session_value('public_key', None); await pop_session_value('resource_type', None); await pop_session_value('resource_name', None)

    if 'available_file_types' not in context: context['available_file_types'] = set()
    return render(request, 'viewer/index.html', context)


@require_GET
async def download_file(request: HttpRequest, file_path: str) -> HttpResponse:
    logger.info(f"Запрос на скачивание одного файла: {file_path}")
    get_session_value = sync_to_async(request.session.get)
    public_key = await get_session_value('public_key')
    resource_type = await get_session_value('resource_type')
    if not public_key:
        logger.warning("Попытка скачать файл без public_key в сессии.")
        raise Http404("Сессия истекла или не найдена. Пожалуйста, введите URL заново.")
    try:
        clean_path_str = Path(unquote(file_path).replace('\\', '/')).as_posix().lstrip('/')
        logger.debug(f"Очищенный путь файла для скачивания: '{clean_path_str}'")
    except Exception as e:
         logger.error(f"Ошибка декодирования/очистки file_path: '{file_path}'. Ошибка: {e}")
         raise Http404("Некорректный путь файла в URL.")

    path_to_request = f"/{clean_path_str}" if resource_type == 'dir' and clean_path_str else None
    file_name = PurePath(clean_path_str).name or "downloaded_file"

    async with aiohttp.ClientSession() as session:
        logger.debug(f"Запрос ссылки для скачивания: key={public_key}, path='{path_to_request}', file_name='{file_name}', resource_type={resource_type}")
        download_url = await get_public_resource_download_link(public_key, path=path_to_request, session=session)

        if download_url:
            logger.info(f"Получена ссылка (попытка 1), РЕДИРЕКТ на: {download_url}")
            return HttpResponseRedirect(download_url)
        else:
            logger.warning(f"Не удалось получить ссылку (1): key={public_key}, path='{path_to_request}', type={resource_type}. Повтор без path...")
            download_url_retry = await get_public_resource_download_link(public_key, path=None, session=session)
            if download_url_retry:
                 logger.info(f"Получена ссылка (попытка 2, без path), РЕДИРЕКТ на: {download_url_retry}")
                 return HttpResponseRedirect(download_url_retry)
            else:
                 logger.error(f"Не удалось получить ссылку (2 попытки): key={public_key}. Ошибка 404.")
                 raise Http404(f"Не удалось получить ссылку для скачивания файла '{file_name}' от API Яндекса.")


@require_POST
async def download_zip(request: HttpRequest) -> HttpResponse:
    logger.info("Запуск скачивания ZIP-архива (используя временные файлы + zipfile)")
    get_session_value = sync_to_async(request.session.get)
    public_key = await get_session_value('public_key')
    resource_type = await get_session_value('resource_type')
    resource_name = await get_session_value('resource_name', 'yadisk-archive')

    if not public_key:
        logger.warning("Попытка скачать ZIP без public_key в сессии.")
        raise Http404("Сессия истекла или не найдена. Пожалуйста, введите URL заново.")

    if resource_type != 'dir':
        logger.warning(f"Попытка скачать ZIP для ресурса не-папки: key={public_key}, type={resource_type}")
        return redirect('viewer:index')

    selected_paths = request.POST.getlist('selected_files')
    if not selected_paths:
        logger.warning("Попытка скачать ZIP без выбранных файлов.")
        return redirect('viewer:index')

    safe_name = slugify(resource_name) or 'archive'
    zip_filename = f"{safe_name}-{now().strftime('%Y%m%d%H%M%S')}.zip"
    logger.info(f"Генерация ZIP '{zip_filename}' для {len(selected_paths)} файлов.")

    temp_dir_obj = tempfile.TemporaryDirectory()
    temp_dir_path = temp_dir_obj.name
    logger.debug(f"Создана временная директория: {temp_dir_path}")

    downloaded_files_map = {}
    failed_files = []
    zip_temp_filepath = None

    try:
        async with aiohttp.ClientSession() as session:
            link_tasks = []
            for api_path in selected_paths:
                path_param = api_path if api_path != '/' else None
                link_tasks.append(get_public_resource_download_link(public_key, path=path_param, session=session))

            logger.info(f"Запрос {len(link_tasks)} ссылок на скачивание...")
            download_links_results = await asyncio.gather(*[asyncio.create_task(t) for t in link_tasks], return_exceptions=True)

            files_to_download = []
            for i, result in enumerate(download_links_results):
                api_path = selected_paths[i]
                if isinstance(result, Exception) or result is None:
                    logger.warning(f"Не удалось получить ссылку для '{api_path}': {result}")
                    failed_files.append(api_path)
                else:
                    files_to_download.append({'api_path': api_path, 'url': result})

            if not files_to_download:
                logger.error("Не удалось получить ни одной ссылки для скачивания.")
                temp_dir_obj.cleanup()
                return HttpResponse("Не удалось получить ссылки для скачивания выбранных файлов.", status=500)

            semaphore = asyncio.Semaphore(DOWNLOAD_CONCURRENCY_LIMIT)
            download_tasks = []

            async def download_to_temp(file_info):
                async with semaphore:
                    api_path = file_info['api_path']
                    url = file_info['url']
                    original_filename = PurePath(api_path.lstrip('/')).name or f"file_{len(downloaded_files_map)}"
                    temp_file_path = os.path.join(temp_dir_path, f"{original_filename}.{hash(api_path)}.tmp")
                    logger.debug(f"Начало скачивания '{api_path}' в '{temp_file_path}'")
                    try:
                        timeout = aiohttp.ClientTimeout(total=600, connect=30, sock_read=60)
                        headers = {'User-Agent': 'Mozilla/5.0'}
                        async with session.get(url, timeout=timeout, headers=headers, allow_redirects=True) as resp:
                            resp.raise_for_status()
                            async with aiofiles.open(temp_file_path, mode='wb') as f:
                                file_size = 0
                                async for chunk in resp.content.iter_chunked(FILE_CHUNK_SIZE):
                                    await f.write(chunk)
                                    file_size += len(chunk)
                            downloaded_files_map[api_path] = temp_file_path
                            logger.info(f"Успешно скачан '{api_path}' ({file_size} байт) в '{temp_file_path}'")
                            return True
                    except Exception as e:
                        logger.error(f"Ошибка скачивания файла '{api_path}' с {url}: {e}")
                        failed_files.append(api_path)
                        if os.path.exists(temp_file_path):
                            try: os.remove(temp_file_path)
                            except OSError: pass
                        return False

            for file_info in files_to_download:
                download_tasks.append(asyncio.create_task(download_to_temp(file_info)))

            logger.info(f"Запуск {len(download_tasks)} задач скачивания (лимит {DOWNLOAD_CONCURRENCY_LIMIT})...")
            await asyncio.gather(*download_tasks)

        if not downloaded_files_map:
            logger.error("Не удалось скачать ни одного файла.")
            temp_dir_obj.cleanup()
            return HttpResponse("Не удалось скачать ни одного из выбранных файлов.", status=500)

        logger.info(f"Скачано {len(downloaded_files_map)} файлов во временную директорию.")
        if failed_files:
             logger.warning(f"Не удалось скачать/получить ссылку для {len(failed_files)} файлов: {failed_files}")

        zip_temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.zip')
        zip_temp_filepath = zip_temp_file.name
        zip_temp_file.close()
        logger.debug(f"Временный файл для ZIP: {zip_temp_filepath}")

        def create_zip_sync():
            logger.info(f"Начало создания ZIP-архива '{zip_temp_filepath}'...")
            try:
                with zipfile.ZipFile(zip_temp_filepath, 'w', compression=zipfile.ZIP_STORED) as zf:
                    for api_path, temp_file_path in downloaded_files_map.items():
                        arcname = api_path.lstrip('/')
                        if not arcname:
                            arcname = f"file_{hash(api_path)}"
                        logger.debug(f"Добавление в ZIP: '{temp_file_path}' как '{arcname}'")
                        zf.write(temp_file_path, arcname=arcname)
                logger.info(f"ZIP-архив '{zip_temp_filepath}' успешно создан.")
                return True
            except Exception as e:
                logger.exception(f"Ошибка при создании ZIP-архива: {e}")
                if os.path.exists(zip_temp_filepath):
                    try: os.remove(zip_temp_filepath)
                    except OSError: pass
                return False

        loop = asyncio.get_running_loop()
        zip_success = await loop.run_in_executor(None, create_zip_sync)

        logger.debug(f"Удаление временной директории со скачанными файлами: {temp_dir_path}")
        temp_dir_obj.cleanup()

        if not zip_success:
             if zip_temp_filepath and os.path.exists(zip_temp_filepath):
                  try: os.remove(zip_temp_filepath)
                  except OSError: pass
             return HttpResponse("Ошибка при создании ZIP-архива на сервере.", status=500)

        async def zip_file_stream_generator(filepath_to_stream: str) -> AsyncGenerator[bytes, None]:
            f = None
            try:
                f = await aiofiles.open(filepath_to_stream, mode='rb')
                while True:
                    try:
                        chunk = await f.read(FILE_CHUNK_SIZE)
                        if not chunk:
                            break
                        yield chunk
                    except StopAsyncIteration:
                        break
                logger.info(f"Завершена отправка потока для ZIP '{zip_filename}'")
            except Exception as e:
                logger.exception(f"Ошибка при стриминге ZIP файла '{filepath_to_stream}': {e}")
            finally:
                if f:
                    await f.close()
                    logger.debug(f"aiofiles объект закрыт для: {filepath_to_stream}")

                logger.debug(f"Удаление временного ZIP файла: {filepath_to_stream}")
                try:
                    await sync_to_async(os.remove)(filepath_to_stream)
                except OSError as e:
                    logger.error(f"Не удалось удалить временный ZIP файл '{filepath_to_stream}': {e}")

        response = StreamingHttpResponse(zip_file_stream_generator(zip_temp_filepath), content_type='application/zip')
        try:
            ascii_name = zip_filename.encode('ascii').decode('ascii')
            response['Content-Disposition'] = f'attachment; filename="{ascii_name}"'
        except UnicodeEncodeError:
            encoded_name = quote(zip_filename)
            response['Content-Disposition'] = f"attachment; filename*=UTF-8''{encoded_name}"
        logger.info(f"Отправка StreamingHttpResponse для ZIP: {zip_filename}")
        return response

    except Exception as e:
        logger.exception(f"Критическая ошибка в download_zip: {e}")
        if 'temp_dir_obj' in locals() and hasattr(temp_dir_obj, 'name') and os.path.exists(temp_dir_obj.name):
            try:
                temp_dir_obj.cleanup()
                logger.debug("Временная директория очищена из-за ошибки.")
            except Exception as cleanup_err:
                logger.error(f"Ошибка при очистке временной директории: {cleanup_err}")

        if zip_temp_filepath and os.path.exists(zip_temp_filepath):
             try:
                 os.remove(zip_temp_filepath)
                 logger.debug("Временный ZIP файл удален из-за ошибки.")
             except OSError as remove_err:
                 logger.error(f"Ошибка при удалении временного ZIP файла: {remove_err}")
        return HttpResponse("Внутренняя ошибка сервера при обработке запроса на ZIP-архив.", status=500)