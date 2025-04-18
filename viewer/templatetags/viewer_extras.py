from django import template
from urllib.parse import urlencode

register = template.Library()

@register.simple_tag
def dict_set(dictionary, key, value):
    new_dict = dictionary.copy()
    new_dict[key] = value
    return new_dict

@register.simple_tag
def dict_del(dictionary, key):
    new_dict = dictionary.copy()
    if key in new_dict:
        del new_dict[key]
    return new_dict

@register.filter
def filter_files(items):
    if not items:
        return []
    return [item for item in items if item.get('type') == 'file']

@register.simple_tag
def available_file_types_map():
    return {
        'image': 'Изображения',
        'document': 'Документы',
        'archive': 'Архивы',
        'video': 'Видео',
        'audio': 'Аудио',
        'other': 'Прочее',
    }

@register.filter
def start_index(paginator_page):
    return paginator_page.start_index()

@register.filter
def end_index(paginator_page):
    return paginator_page.end_index()
