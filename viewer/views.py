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

async def index(request: HttpRequest) -> HttpResponse:
    context = {'error': None, 'data': None, 'items': None, 'public_url': '', 'filter_type': 'all', 'resource_type': None}

    get_session_value = sync_to_async(request.session.get)
    set_session_value = sync_to_async(request.session.__setitem__)
    pop_session_value = sync_to_async(request.session.pop)

    if request.method == 'POST':
        public_url = request.POST.get('public_url', '').strip()
        context['public_url'] = public_url

        await pop_session_value('public_key', None)
        await pop_session_value('resource_type', None)
        await pop_session_value('resource_name', None)
        await pop_session_value('base_path', None)

        if not public_url:
            context['error'] = "Пожалуйста, введите URL."
            return render(request, 'viewer/index.html', context)

        public_key = extract_public_key(public_url)
        if not public_key:
            context['error'] = "Некорректный URL или не удалось извлечь ключ."
            return render(request, 'viewer/index.html', context)

        async with aiohttp.ClientSession() as session:
            meta_data = await get_public_resource_meta(public_key, session=session)

        if meta_data is None:
            context['error'] = "Не удалось получить информацию по ссылке. Проверьте URL или попробуйте позже."
        elif 'error' in meta_data:
            context['error'] = f"Ошибка API Яндекса: {meta_data.get('message', 'Неизвестная ошибка')}"
        else:
            resource_type = meta_data.get('type')

            resource_name = meta_data.get('name', 'name')
            await set_session_value('public_key', public_key)
            await set_session_value('resource_type', resource_type)
            await set_session_value('resource_name', resource_name)
            await set_session_value('base_path', meta_data.get('path', ''))
            context['data'] = meta_data
            context['resource_type'] = resource_type

            items_list = []
            if resource_type == 'file':
                original_path = meta_data.get('path', meta_data.get('name', ''))
                relative_path = str(PurePath(original_path)).lstrip('/')
                meta_data['url_path'] = relative_path or meta_data.get('name')
                items_list = [meta_data]
                logger.info(f"INDEX VIEW (FILE): Processed item '{meta_data.get('name')}', original_path='{original_path}', generated url_path='{meta_data['url_path']}'")
            elif resource_type == 'dir' and '_embedded' in meta_data:
                items_list = sorted(
                    meta_data['_embedded']['items'],
                    key=lambda x: (x['type'] != 'dir', x['name'].lower())
                )
                for item in items_list:
                    if item['type'] == 'file' and 'path' in item:
                         original_path = item['path']
                         relative_path = str(PurePath(original_path)).lstrip('/')
                         item['url_path'] = relative_path
                         logger.info(f"INDEX VIEW (DIR): Processed item '{item['name']}', original_path='{original_path}', generated url_path='{item['url_path']}'")
                    elif item['type'] == 'dir':
                         item['url_path'] = None
            elif resource_type == 'dir':
                 items_list = []
            else:
                 context['error'] = "Неизвестный тип ресурса или ошибка структуры ответа API."

            context['items'] = items_list
            filter_type = request.GET.get('filter', 'all')
            context['filter_type'] = filter_type
            if filter_type != 'all' and isinstance(items_list, list):
                context['items'] = filter_items(items_list, filter_type)

    elif request.method == 'GET':
        public_key = await get_session_value('public_key')
        if public_key:
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

                items_list = []
                if current_resource_type == 'file':
                    original_path = meta_data.get('path', meta_data.get('name', ''))
                    relative_path = str(PurePath(original_path)).lstrip('/')
                    meta_data['url_path'] = relative_path or meta_data.get('name')
                    items_list = [meta_data]
                    logger.info(f"INDEX VIEW (GET/FILE): Processed item '{meta_data.get('name')}', original_path='{original_path}', generated url_path='{meta_data['url_path']}'")
                elif current_resource_type == 'dir' and '_embedded' in meta_data:
                     items_list = sorted(
                        meta_data['_embedded']['items'],
                        key=lambda x: (x['type'] != 'dir', x['name'].lower())
                     )
                     for item in items_list:
                        if item['type'] == 'file' and 'path' in item:
                            original_path = item['path']
                            relative_path = str(PurePath(original_path)).lstrip('/')
                            item['url_path'] = relative_path
                            logger.info(f"INDEX VIEW (GET/DIR): Processed item '{item['name']}', original_path='{original_path}', generated url_path='{item['url_path']}'")
                        elif item['type'] == 'dir':
                             item['url_path'] = None
                elif current_resource_type == 'dir':
                    items_list = []

                context['items'] = items_list
                filter_type = request.GET.get('filter', 'all')
                context['filter_type'] = filter_type
                if filter_type != 'all' and isinstance(items_list, list):
                    context['items'] = filter_items(items_list, filter_type)
            else:
                logger.warning(f"Не удалось получить метаданные для ключа из сессии (GET): {public_key}")
                await pop_session_value('public_key', None)
                await pop_session_value('resource_type', None)
                await pop_session_value('resource_name', None)
                await pop_session_value('base_path', None)
                context['error'] = "Не удалось обновить данные по ссылке из сессии."
                context['data'] = None; context['items'] = None; context['public_url'] = ''; context['resource_type'] = None
        else:
            await pop_session_value('resource_type', None)
            await pop_session_value('resource_name', None)
            await pop_session_value('base_path', None)
            context['resource_type'] = None

    return render(request, 'viewer/index.html', context)

def filter_items(items: list, filter_type: str) -> list:
    if filter_type == 'all': return items
    filtered = []
    for item in items:
        if item['type'] == 'dir': continue
        mime_type, _ = mimetypes.guess_type(item.get('name', ''))
        category = 'other'
        if mime_type:
            major_type = mime_type.split('/')[0]
            if major_type == 'image': category = 'image'
            elif major_type == 'video': category = 'video'
            elif major_type == 'audio': category = 'audio'
            elif mime_type.startswith('text/') or mime_type in ('application/pdf', 'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', 'application/vnd.ms-excel', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', 'application/vnd.ms-powerpoint', 'application/vnd.openxmlformats-officedocument.presentationml.presentation'): category = 'document'
            elif mime_type in ('application/zip', 'application/x-rar-compressed', 'application/x-7z-compressed', 'application/gzip', 'application/x-tar', 'application/x-bzip2', 'application/vnd.rar'): category = 'archive'
        if filter_type == category or (filter_type == 'other' and category == 'other'):
            filtered.append(item)
    return filtered


@require_GET
async def download_file(request: HttpRequest, file_path: str) -> HttpResponse:
    logger.critical("RUNNING download_file WITH REDIRECT LOGIC!")
    get_session_value = sync_to_async(request.session.get)
    public_key = await get_session_value('public_key')
    resource_type = await get_session_value('resource_type')
    if not public_key:
        logger.warning("Попытка скачивания файла без public_key в сессии.")
        raise Http404("Сессия истекла или не найдена. Пожалуйста, введите URL заново.")
    try:
        clean_path_str = unquote(file_path).lstrip('/')
    except Exception as e:
         logger.error(f"Ошибка при раскодировании/очистке file_path: '{file_path}'. Ошибка: {e}")
         raise Http404("Некорректный путь к файлу в URL.")
    path_for_api = f"/{clean_path_str}" if clean_path_str else "/"
    path_to_request = path_for_api if resource_type == 'dir' else None
    file_name = PurePath(clean_path_str).name or "downloaded_file"
    async with aiohttp.ClientSession() as session:
        logger.debug(f"Запрос ссылки на скачивание для редиректа: key={public_key}, path='{path_to_request}', file_name='{file_name}', resource_type={resource_type}")
        download_url = await get_public_resource_download_link(public_key, path=path_to_request, session=session)
        if not download_url:
            logger.warning(f"Не удалось получить ссылку для редиректа (1): key={public_key}, path='{path_to_request}', type={resource_type}. Пытаемся без path...")
            download_url = await get_public_resource_download_link(public_key, path=None, session=session)
            if not download_url:
                 logger.error(f"Не удалось получить ссылку для редиректа (2): key={public_key}. Отдаем 404.")
                 raise Http404("Не удалось получить ссылку для скачивания файла от API Яндекса.")
        logger.info(f"Получена ссылка для скачивания, РЕДИРЕКТИМ на: {download_url}")
        return HttpResponseRedirect(download_url)

@require_POST
async def download_zip(request: HttpRequest) -> HttpResponse:
    logger.info("Запущен процесс скачивания ZIP-архива")
    get_session_value = sync_to_async(request.session.get)
    public_key = await get_session_value('public_key')
    resource_type = await get_session_value('resource_type')

    resource_name = await get_session_value('resource_name', 'yadisk-archive')

    if not public_key:
        logger.warning("Попытка скачивания ZIP без public_key в сессии.")
        raise Http404("Сессия истекла или не найдена. Пожалуйста, введите URL заново.")
    if resource_type != 'dir':
        logger.warning(f"Попытка скачать ZIP для ресурса не типа 'dir': key={public_key}, type={resource_type}")
        return redirect('viewer:index')

    selected_paths = request.POST.getlist('selected_files')
    if not selected_paths:
        logger.warning("Попытка скачать ZIP без выбранных файлов.")
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
                 logger.debug(f"ZIP: Запрос ссылки для path='{path}'")
                 tasks_get_links.append(
                     get_public_resource_download_link(public_key, path=path, session=session)
                 )
            logger.info(f"ZIP: Запрос {len(tasks_get_links)} ссылок на скачивание...")
            download_links_results = await asyncio.gather(*tasks_get_links, return_exceptions=True)

            path_link_pairs = []
            failed_links = 0
            for path, result in zip(selected_paths, download_links_results):
                if isinstance(result, Exception) or result is None:
                    logger.warning(f"ZIP: Ошибка или нет ссылки для path='{path}': {result}")
                    failed_links += 1
                else:
                    path_link_pairs.append((path, result))

            if not path_link_pairs:
                 logger.error("ZIP: Не удалось получить ни одной ссылки для скачивания.")
                 yield b''
                 return

            logger.info(f"ZIP: Начинаем упаковку {len(path_link_pairs)} файлов (пропущено {failed_links})...")
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
                                logger.debug(f"ZIP: Добавлен файл: {archive_name} ({len(file_content)} байт)")
                                return True
                            else:
                                error_body = await resp.text()
                                logger.warning(f"ZIP: Не удалось скачать файл {archive_name} ({resp.status}): {error_body[:100]}")
                                return False
                    except Exception as e:
                        logger.exception(f"ZIP: Ошибка при скачивании/записи файла {archive_name}: {e}")
                        return False

                for path, download_url in path_link_pairs:
                    download_tasks.append(download_and_write(path, download_url))

                results = await asyncio.gather(*download_tasks)
                successful_files = sum(1 for r in results if r is True)
                logger.info(f"ZIP: Успешно упаковано {successful_files} из {len(path_link_pairs)} файлов.")

        zip_buffer.seek(0)
        logger.info(f"ZIP: Отправка архива '{zip_filename}' клиенту...")
        while True:
            chunk = zip_buffer.read(8192)
            if not chunk: break
            yield chunk
        logger.info(f"ZIP: Отправка архива '{zip_filename}' завершена.")

    response = StreamingHttpResponse(zip_generator(), content_type='application/zip')
    try:
        ascii_name = zip_filename.encode('ascii').decode('ascii')
        response['Content-Disposition'] = f'attachment; filename="{ascii_name}"'
    except UnicodeEncodeError:
        encoded_name = quote(zip_filename)
        response['Content-Disposition'] = f"attachment; filename*=UTF-8''{encoded_name}"

    return response
