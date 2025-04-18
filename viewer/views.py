import aiohttp
import asyncio
import logging
import mimetypes
import zipfile
import io
from urllib.parse import quote, unquote, urlencode as standard_urlencode
from pathlib import PurePath, Path
import math

from django.shortcuts import render, redirect
from django.http import HttpRequest, HttpResponse, StreamingHttpResponse, Http404, HttpResponseRedirect
from django.views.decorators.http import require_GET, require_POST
from django.utils.text import slugify
from django.utils.timezone import now
from django.urls import reverse

from asgiref.sync import sync_to_async

from .yadisk_api import get_public_resource_meta, get_public_resource_download_link, extract_public_key

logger = logging.getLogger(__name__)

DEFAULT_PAGE_SIZE = 50
ALLOWED_PAGE_SIZES = [25, 50, 100]

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
                if resource_type == 'file': items_list_raw = [meta_data]; total_items = 1
                elif resource_type == 'dir' and '_embedded' in meta_data:
                    all_items_processed, available_types = process_items(meta_data['_embedded']['items'])
                    context['available_file_types'] = available_types
                    total_items = meta_data['_embedded'].get('total', len(all_items_processed))
                    context['items'] = filter_items(all_items_processed, filter_from_get) if filter_from_get != 'all' else all_items_processed
                else: context['items'] = []; context['available_file_types'] = set(); total_items = 0

                total_pages = math.ceil(total_items / page_size)
                if total_pages > 1: context['pagination'] = {'current_page': page_num, 'total_pages': total_pages, 'total_items': total_items, 'has_previous': page_num > 1, 'has_next': page_num < total_pages, 'page_range': range(1, total_pages + 1)}

    else:
        logger.info("No public_url found. Clearing session.")
        await pop_session_value('public_key', None); await pop_session_value('resource_type', None); await pop_session_value('resource_name', None); await pop_session_value('base_path', None)

    if 'available_file_types' not in context: context['available_file_types'] = set()
    return render(request, 'viewer/index.html', context)


@require_GET
async def download_file(request: HttpRequest, file_path: str) -> HttpResponse:
    logger.critical("RUNNING download_file WITH REDIRECT LOGIC!")
    get_session_value = sync_to_async(request.session.get)
    public_key = await get_session_value('public_key')
    resource_type = await get_session_value('resource_type')
    if not public_key:
        logger.warning("Attempting to download file without public_key in session.")
        raise Http404("Session expired or not found. Please enter the URL again.")
    try:
        clean_path_str = Path(unquote(file_path).replace('\\', '/')).as_posix().lstrip('/')
        logger.debug(f"Cleaned file path for download: '{clean_path_str}'")
    except Exception as e:
         logger.error(f"Error decoding/cleaning file_path: '{file_path}'. Error: {e}")
         raise Http404("Invalid file path in URL.")

    path_for_api = f"/{clean_path_str}" if clean_path_str else None
    path_to_request = path_for_api if resource_type == 'dir' else None

    file_name = PurePath(clean_path_str).name or "downloaded_file"

    async with aiohttp.ClientSession() as session:
        logger.debug(f"Requesting download link for redirect: key={public_key}, path='{path_to_request}', file_name='{file_name}', resource_type={resource_type}")
        download_url = await get_public_resource_download_link(public_key, path=path_to_request, session=session)

        if download_url:
            logger.info(f"Obtained download link (attempt 1), REDIRECTING to: {download_url}")
            return HttpResponseRedirect(download_url)
        else:
            logger.warning(f"Failed to get download link (1): key={public_key}, path='{path_to_request}', type={resource_type}. Retrying without path...")
            download_url_retry = await get_public_resource_download_link(public_key, path=None, session=session)
            if download_url_retry:
                 logger.info(f"Obtained download link (attempt 2, no path), REDIRECTING to: {download_url_retry}")
                 return HttpResponseRedirect(download_url_retry)
            else:
                 logger.error(f"Failed to get download link (2 attempts): key={public_key}. Raising 404.")
                 raise Http404(f"Не удалось получить ссылку для скачивания файла '{file_name}' от API Яндекса.")


@require_POST
async def download_zip(request: HttpRequest) -> HttpResponse:
    logger.info("Запущен процесс скачивания ZIP-архива (используется zipfile)")
    get_session_value = sync_to_async(request.session.get)
    public_key = await get_session_value('public_key')
    resource_type = await get_session_value('resource_type')
    resource_name = await get_session_value('resource_name', 'yadisk-archive')
    if not public_key: logger.warning("Attempting ZIP download without public_key in session."); raise Http404("Session expired...")
    if resource_type != 'dir': logger.warning(f"Attempting ZIP download for non-directory: key={public_key}"); return redirect('viewer:index')

    selected_paths = request.POST.getlist('selected_files')
    if not selected_paths: logger.warning("Attempting ZIP download with no files selected."); return redirect('viewer:index')
    safe_name = slugify(resource_name); safe_name = safe_name or 'archive'
    zip_filename = f"{safe_name}.zip"
    logger.info(f"Generating ZIP archive (zipfile) with name: {zip_filename} for {len(selected_paths)} files")

    async def zip_generator():
        zip_buffer = io.BytesIO()
        compression = zipfile.ZIP_STORED
        async with aiohttp.ClientSession() as session:
            tasks_get_links = []
            for path in selected_paths:
                 logger.debug(f"ZIP: Запрос ссылки для path='{path}'")
                 tasks_get_links.append(get_public_resource_download_link(public_key, path=path, session=session))

            logger.info(f"ZIP: Запрос {len(tasks_get_links)} ссылок на скачивание...")
            download_links_results = await asyncio.gather(*tasks_get_links, return_exceptions=True)
            path_link_pairs = []
            failed_links_count = 0
            for path, result in zip(selected_paths, download_links_results):
                if isinstance(result, Exception) or result is None: logger.warning(f"ZIP: Ошибка или нет ссылки для path='{path}': {result}"); failed_links_count += 1
                else: path_link_pairs.append({'path': path, 'url': result})
            if not path_link_pairs: logger.error("ZIP: Не удалось получить ни одной ссылки для скачивания."); yield b''; return
            logger.info(f"ZIP: Начинаем скачивание и упаковку {len(path_link_pairs)} файлов (пропущено {failed_links_count})...")
            download_tasks = []
            zip_write_lock = asyncio.Lock()
            async def download_and_write(file_info, zip_file_obj):
                original_path = file_info['path']
                download_url = file_info['url']
                archive_name = original_path.lstrip('/')
                if not archive_name: archive_name = PurePath(original_path).name
                try:
                    timeout = aiohttp.ClientTimeout(total=600, connect=30, sock_read=60); headers = {'User-Agent': 'Mozilla/5.0'}
                    async with session.get(download_url, timeout=timeout, headers=headers) as resp:
                        if resp.status == 200:
                            file_content = await resp.read()
                            async with zip_write_lock: zip_file_obj.writestr(archive_name, file_content)
                            logger.debug(f"ZIP: Добавлен файл: {archive_name} ({len(file_content)} байт)"); return True
                        else: error_body = await resp.text(); logger.warning(f"ZIP: Не удалось скачать файл {archive_name} ({resp.status}): {error_body[:100]}"); return False
                except Exception as e: logger.exception(f"ZIP: Ошибка при скачивании/записи файла {archive_name}: {e}"); return False
            with zipfile.ZipFile(zip_buffer, 'w', compression=compression) as zip_file_sync:
                 for file_info in path_link_pairs: download_tasks.append(download_and_write(file_info, zip_file_sync))
                 results = await asyncio.gather(*download_tasks)
                 successful_files = sum(1 for r in results if r is True)
                 logger.info(f"ZIP: Успешно обработано {successful_files} из {len(path_link_pairs)} файлов.")
            zip_buffer.seek(0)
            logger.info(f"ZIP: Отправка архива '{zip_filename}' клиенту...")
            while True:
                chunk = zip_buffer.read(8192)
                if not chunk:
                    break
                yield chunk
            logger.info(f"ZIP: Отправка архива '{zip_filename}' завершена.")
    response = StreamingHttpResponse(zip_generator(), content_type='application/zip')
    try: ascii_name = zip_filename.encode('ascii').decode('ascii'); response['Content-Disposition'] = f'attachment; filename="{ascii_name}"'
    except UnicodeEncodeError: encoded_name = quote(zip_filename); response['Content-Disposition'] = f"attachment; filename*=UTF-8''{encoded_name}"
    return response
