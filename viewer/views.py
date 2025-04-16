# viewer/views.py
import aiohttp
import asyncio
import logging
import mimetypes
import zipfile
import io
from urllib.parse import quote, unquote
from pathlib import PurePath

from django.shortcuts import render, redirect
from django.http import HttpRequest, HttpResponse, StreamingHttpResponse, Http404, HttpResponseRedirect
from django.views.decorators.http import require_GET, require_POST
from django.utils.text import slugify
from django.utils.timezone import now

from asgiref.sync import sync_to_async

from .yadisk_api import get_public_resource_meta, get_public_resource_download_link, extract_public_key

logger = logging.getLogger(__name__)


def get_file_category(item: dict) -> str:
    if item.get('type') != 'file':
        return 'dir'
    mime_type, _ = mimetypes.guess_type(item.get('name', ''))
    category = 'other'
    if mime_type:
        major_type = mime_type.split('/')[0]
        if major_type == 'image': category = 'image'
        elif major_type == 'video': category = 'video'
        elif major_type == 'audio': category = 'audio'
        elif mime_type.startswith('text/') or mime_type in (
            'application/pdf', 'application/msword',
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            'application/vnd.ms-excel',
            'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            'application/vnd.ms-powerpoint',
            'application/vnd.openxmlformats-officedocument.presentationml.presentation'
        ): category = 'document'
        elif mime_type in (
            'application/zip', 'application/x-rar-compressed',
            'application/x-7z-compressed', 'application/gzip', 'application/x-tar',
            'application/x-bzip2', 'application/vnd.rar'
        ): category = 'archive'
    return category


def filter_items(items: list, filter_type: str) -> list:
    if filter_type == 'all':
        return items
    filtered = []
    for item in items:
        if item['type'] == 'dir':
            continue
        category = get_file_category(item)
        if filter_type == category or (filter_type == 'other' and category == 'other'):
            filtered.append(item)
    return filtered


async def index(request: HttpRequest) -> HttpResponse:
    context = {'error': None, 'data': None, 'items': None, 'public_url': '',
               'filter_type': 'all', 'resource_type': None, 'available_file_types': set()}

    get_session_value = sync_to_async(request.session.get)
    set_session_value = sync_to_async(request.session.__setitem__)
    pop_session_value = sync_to_async(request.session.pop)

    def process_metadata_and_get_types(meta_data):
        items_list = []
        available_types = set()
        resource_type = meta_data.get('type')
        if resource_type == 'file':
            original_path = meta_data.get('path', meta_data.get('name', ''))
            relative_path = str(PurePath(original_path)).lstrip('/')
            meta_data['url_path'] = relative_path or meta_data.get('name')
            items_list = [meta_data]
            category = get_file_category(meta_data)
            if category != 'dir': available_types.add(category)
            logger.debug(f"INDEX/process (FILE): name='{meta_data.get('name')}', url_path='{meta_data['url_path']}', category='{category}'")
        elif resource_type == 'dir' and '_embedded' in meta_data:
            items_list = sorted(meta_data['_embedded']['items'], key=lambda x: (x['type'] != 'dir', x['name'].lower()))
            for item in items_list:
                if item['type'] == 'file':
                    category = get_file_category(item)
                    available_types.add(category)
                    if 'path' in item:
                         original_path = item['path']
                         relative_path = str(PurePath(original_path)).lstrip('/')
                         item['url_path'] = relative_path
                         logger.debug(f"INDEX/process (DIR): name='{item['name']}', url_path='{item['url_path']}', category='{category}'")
                elif item['type'] == 'dir':
                     item['url_path'] = None
        elif resource_type == 'dir':
             items_list = []
        logger.info(f"INDEX/process: Found available types: {available_types}")
        return items_list, available_types

    filter_from_get = request.GET.get('filter')

    if request.method == 'POST':
        public_url = request.POST.get('public_url', '').strip()
        context['public_url'] = public_url

        await pop_session_value('public_key', None)
        await pop_session_value('resource_type', None)
        await pop_session_value('resource_name', None)
        await pop_session_value('base_path', None)

        if not public_url:
            context['error'] = "Пожалуйста, введите URL."
        else:
            public_key = extract_public_key(public_url)
            if not public_key:
                context['error'] = "Некорректный URL или не удалось извлечь ключ."
            else:
                logger.info(f"POST request processing for key: {public_key}")
                async with aiohttp.ClientSession() as session:
                    meta_data = await get_public_resource_meta(public_key, session=session)

                if meta_data is None:
                    context['error'] = "Не удалось получить информацию по ссылке."
                elif 'error' in meta_data:
                    context['error'] = f"Ошибка API Яндекса: {meta_data.get('message', 'Неизвестная ошибка')}"
                else:
                    resource_type = meta_data.get('type')
                    resource_name = meta_data.get('name', 'yadisk-archive')
                    await set_session_value('public_key', public_key)
                    await set_session_value('resource_type', resource_type)
                    await set_session_value('resource_name', resource_name)
                    await set_session_value('base_path', meta_data.get('path', ''))
                    context['data'] = meta_data
                    context['resource_type'] = resource_type

                    all_items_list, available_types = process_metadata_and_get_types(meta_data)
                    context['available_file_types'] = available_types

                    current_filter = filter_from_get or 'all'
                    context['filter_type'] = current_filter
                    if current_filter != 'all':
                        context['items'] = filter_items(all_items_list, current_filter)
                    else:
                        context['items'] = all_items_list

    elif request.method == 'GET':
        public_key = await get_session_value('public_key')

        if public_key and filter_from_get:
            logger.info(f"GET request with filter='{filter_from_get}'. Restoring state from session for key: {public_key}")
            context['public_url'] = public_key
            async with aiohttp.ClientSession() as session:
                meta_data = await get_public_resource_meta(public_key, session=session)

            if meta_data and 'error' not in meta_data:
                current_resource_type = meta_data.get('type')
                current_resource_name = meta_data.get('name', 'yadisk-archive')
                await set_session_value('resource_type', current_resource_type)
                await set_session_value('resource_name', current_resource_name)
                context['data'] = meta_data
                context['resource_type'] = current_resource_type

                all_items_list, available_types = process_metadata_and_get_types(meta_data)
                context['available_file_types'] = available_types

                context['filter_type'] = filter_from_get
                context['items'] = filter_items(all_items_list, filter_from_get)

            else:
                logger.warning(f"GET/Filter: Failed to get metadata for session key: {public_key}. Clearing session.")
                await pop_session_value('public_key', None)
                await pop_session_value('resource_type', None)
                await pop_session_value('resource_name', None)
                await pop_session_value('base_path', None)
                context['error'] = "Не удалось обновить данные по ссылке. Пожалуйста, введите URL заново."
                context['data'] = None; context['items'] = None; context['public_url'] = ''; context['resource_type'] = None; context['available_file_types'] = set(); context['filter_type'] = 'all';
        else:
            logger.info("GET request without filter or session key. Clearing session state.")
            await pop_session_value('public_key', None)
            await pop_session_value('resource_type', None)
            await pop_session_value('resource_name', None)
            await pop_session_value('base_path', None)
            context['filter_type'] = 'all'

    if 'available_file_types' not in context:
         context['available_file_types'] = set()

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
        clean_path_str = unquote(file_path).lstrip('/')
    except Exception as e:
         logger.error(f"Error decoding/cleaning file_path: '{file_path}'. Error: {e}")
         raise Http404("Invalid file path in URL.")
    path_for_api = f"/{clean_path_str}" if clean_path_str else "/"
    path_to_request = path_for_api if resource_type == 'dir' else None
    file_name = PurePath(clean_path_str).name or "downloaded_file"
    async with aiohttp.ClientSession() as session:
        logger.debug(f"Requesting download link for redirect: key={public_key}, path='{path_to_request}', file_name='{file_name}', resource_type={resource_type}")
        download_url = await get_public_resource_download_link(public_key, path=path_to_request, session=session)
        if not download_url:
            logger.warning(f"Failed to get download link (1): key={public_key}, path='{path_to_request}', type={resource_type}. Retrying without path...")
            download_url = await get_public_resource_download_link(public_key, path=None, session=session)
            if not download_url:
                 logger.error(f"Failed to get download link (2): key={public_key}. Raising 404.")
                 raise Http404("Could not get download link from Yandex API.")
        logger.info(f"Obtained download link, REDIRECTING to: {download_url}")
        return HttpResponseRedirect(download_url)


@require_POST
async def download_zip(request: HttpRequest) -> HttpResponse:
    logger.info("ZIP download process started")
    get_session_value = sync_to_async(request.session.get)
    public_key = await get_session_value('public_key')
    resource_type = await get_session_value('resource_type')
    resource_name = await get_session_value('resource_name', 'yadisk-archive')
    if not public_key:
        logger.warning("Attempting ZIP download without public_key in session.")
        raise Http404("Session expired or not found. Please enter the URL again.")
    if resource_type != 'dir':
        logger.warning(f"Attempting ZIP download for non-directory resource: key={public_key}, type={resource_type}")
        return redirect('viewer:index')
    selected_paths = request.POST.getlist('selected_files')
    if not selected_paths:
        logger.warning("Attempting ZIP download with no files selected.")
        return redirect('viewer:index')
    safe_name = slugify(resource_name)
    if not safe_name: safe_name = 'archive'
    zip_filename = f"{safe_name}.zip"
    logger.info(f"Generating ZIP archive with name: {zip_filename} (from resource name: '{resource_name}')")

    async def zip_generator():
        zip_buffer = io.BytesIO()
        compression = zipfile.ZIP_DEFLATED
        async with aiohttp.ClientSession() as session:
            tasks_get_links = []
            for path in selected_paths:
                 logger.debug(f"ZIP: Requesting link for path='{path}'")
                 tasks_get_links.append(get_public_resource_download_link(public_key, path=path, session=session))
            logger.info(f"ZIP: Requesting {len(tasks_get_links)} download links...")
            download_links_results = await asyncio.gather(*tasks_get_links, return_exceptions=True)
            path_link_pairs = []
            failed_links = 0
            for path, result in zip(selected_paths, download_links_results):
                if isinstance(result, Exception) or result is None:
                    logger.warning(f"ZIP: Failed to get link for path='{path}': {result}")
                    failed_links += 1
                else:
                    path_link_pairs.append((path, result))
            if not path_link_pairs:
                 logger.error("ZIP: Failed to get any download links.")
                 yield b''; return
            logger.info(f"ZIP: Starting packing {len(path_link_pairs)} files (skipped {failed_links})...")
            with zipfile.ZipFile(zip_buffer, 'w', compression=compression) as zip_file:
                download_tasks = []
                async def download_and_write(file_path: str, download_url: str):
                    archive_name = file_path.lstrip('/')
                    if not archive_name: archive_name = PurePath(file_path).name
                    try:
                        timeout = aiohttp.ClientTimeout(total=600, connect=30, sock_read=60)
                        headers = {'User-Agent': 'Mozilla/5.0'}
                        async with session.get(download_url, timeout=timeout, headers=headers) as resp:
                            if resp.status == 200:
                                file_content = await resp.read()
                                zip_file.writestr(archive_name, file_content)
                                logger.debug(f"ZIP: Added file: {archive_name} ({len(file_content)} bytes)")
                                return True
                            else:
                                error_body = await resp.text(); logger.warning(f"ZIP: Failed to download file {archive_name} ({resp.status}): {error_body[:100]}"); return False
                    except Exception as e: logger.exception(f"ZIP: Error downloading/writing file {archive_name}: {e}"); return False
                for path, download_url in path_link_pairs:
                    download_tasks.append(download_and_write(path, download_url))
                results = await asyncio.gather(*download_tasks)
                successful_files = sum(1 for r in results if r is True)
                logger.info(f"ZIP: Successfully packed {successful_files} of {len(path_link_pairs)} files.")
        zip_buffer.seek(0)
        logger.info(f"ZIP: Sending archive '{zip_filename}' to client...")
        while True:
            chunk = zip_buffer.read(8192);
            if not chunk: break
            yield chunk
        logger.info(f"ZIP: Finished sending archive '{zip_filename}'.")

    response = StreamingHttpResponse(zip_generator(), content_type='application/zip')
    try:
        ascii_name = zip_filename.encode('ascii').decode('ascii'); response['Content-Disposition'] = f'attachment; filename="{ascii_name}"'
    except UnicodeEncodeError:
        encoded_name = quote(zip_filename); response['Content-Disposition'] = f"attachment; filename*=UTF-8''{encoded_name}"
    return response