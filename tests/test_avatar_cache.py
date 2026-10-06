import unittest
from contextlib import chdir
from tempfile import TemporaryDirectory
from unittest.mock import AsyncMock, Mock, patch

import httpx
from test_smoke import _load_main_module


class SocialAvatarCacheTests(unittest.IsolatedAsyncioTestCase):
    async def test_social_avatar_storage_sets_public_cache_metadata(self):
        with TemporaryDirectory() as isolated_dir, chdir(isolated_dir):
            main = _load_main_module()
        storage = Mock()
        response = httpx.Response(200, content=b'avatar-bytes', headers={'content-type': 'image/jpeg'}, request=httpx.Request('GET', 'https://provider.example/avatar'))
        http = AsyncMock()
        http.__aenter__.return_value = http
        http.get.return_value = response
        with patch.object(main, '_get_s3_client', AsyncMock(return_value=storage)), patch.object(main, '_ensure_bucket'), patch.object(main.httpx, 'AsyncClient', return_value=http):
            result = await main._store_social_avatar('member', 'google', 'https://provider.example/avatar')
        metadata = storage.put_object.call_args.kwargs
        self.assertEqual(metadata['CacheControl'], 'public, max-age=31536000, immutable')
        self.assertEqual(metadata['Body'], b'avatar-bytes')
        self.assertTrue(metadata['Key'].startswith('avatars/member/'))
        self.assertEqual(result['avatar_source'], 'google')
        self.assertNotEqual(result['avatar_url'], 'https://provider.example/avatar')
