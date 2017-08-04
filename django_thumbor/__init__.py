# -*- coding: utf-8 -*-
import re
import base64
import hmac
import hashlib
from Crypto.Cipher import AES
from libthumbor import CryptoURL
from django_thumbor import conf
from django.conf import settings
from libthumbor.url import plain_image_url


class CryptoURLCopy(CryptoURL):

    def generate(self, **options):

        import urllib
        url = plain_image_url(**options)
        url = urllib.quote(url.encode('utf-8'), '/:?%=&()~",\'')

        signature = base64.urlsafe_b64encode(hmac.new(self.key, unicode(url).encode('utf-8'), hashlib.sha1).digest())
        pad = lambda s: s + (32 - len(s) % 32) * "$"
        cypher = AES.new((self.key * 32)[:32])

        encrypted = base64.urlsafe_b64encode(cypher.encrypt(pad(url.encode('utf-8'))))

        return '/%s/%s.jpg' % (signature, encrypted)

crypto = CryptoURLCopy(key=conf.THUMBOR_SECURITY_KEY)


def _remove_prefix(url, prefix):
    if url.startswith(prefix):
        return url[len(prefix):]
    return url


def _remove_schema(url):
    return _remove_prefix(url, 'http://')


def _prepend_media_url(url):
    if url.startswith(settings.MEDIA_URL):
        url = _remove_prefix(url, settings.MEDIA_URL)
        url.lstrip('/')
        return '%s/%s' % (conf.THUMBOR_MEDIA_URL, url)
    return url


# 注释部分为处理static中图片的代码
# def _prepend_static_url(url):
#     if url.startswith(settings.STATIC_URL):
#         url = _remove_prefix(url, settings.STATIC_URL)
#         url.lstrip('/')
#         return '%s/%s' % (conf.THUMBOR_STATIC_URL, url)
#     return url


def generate_url(image_url, **kwargs):
    image_url = _prepend_media_url(image_url)
    # image_url = _prepend_static_url(image_url)
    image_url = _remove_schema(image_url)

    kwargs = dict(conf.THUMBOR_ARGUMENTS, **kwargs)
    thumbor_server = kwargs.pop(
        'thumbor_server', conf.THUMBOR_SERVER).rstrip('/')
    encrypted_url = crypto.generate(image_url=image_url, **kwargs).strip('/')

    return '%s/%s' % (thumbor_server, encrypted_url)


def get_thumbor_image_url(image_url, default=None, **kwargs):
    if not default:
        default = image_url
    try:
        return generate_url(image_url, **kwargs)
    except:
        return default


pattern = '<img.{8,50}?src="([^"]*)".{10,100}?/>'


def url(matchobj):
    pattern = '/media/\S*\\.\w{3,4}?'
    img = matchobj.group(0)
    url = re.findall(pattern, img)[0]
    url_new = generate_url(url)
    img = img.replace(url, url_new)
    return img


def make_text(text):
    return re.sub(pattern, url, text)
