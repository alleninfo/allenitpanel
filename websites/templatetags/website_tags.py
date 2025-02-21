from django import template

register = template.Library()

@register.filter
def get_item(dictionary, key):
    """获取字典中的值，支持字节类型的键"""
    if not dictionary:
        return None
    if isinstance(key, str):
        # 尝试字节类型的键
        byte_key = key.encode('utf-8')
        return dictionary.get(byte_key, dictionary.get(key))
    return dictionary.get(key) 