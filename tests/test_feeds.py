import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch
from apt_scope.feeds import NoRedirect, refresh


class FeedTests(unittest.TestCase):
    def test_valid_feed_refresh(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            config = root / 'feeds.json'
            config.write_text(json.dumps({'feeds': [{'name': 'demo', 'url': 'https://feed.example/bundle.json'}]}))
            response = Mock()
            response.read.return_value = b'{"type":"bundle","objects":[]}'
            context = Mock()
            context.__enter__ = Mock(return_value=response)
            context.__exit__ = Mock(return_value=False)
            opener = Mock()
            opener.open.return_value = context
            with patch('apt_scope.feeds.build_opener', return_value=opener):
                result = refresh(config, root / 'cache')
            self.assertTrue(result['complete'])
            self.assertEqual(len(result['feeds'][0]['sha256']), 64)
            self.assertTrue((root / 'cache' / 'demo.json').exists())

    def test_failure_preserves_cache_and_is_visible(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            config = root / 'feeds.json'
            config.write_text(json.dumps({'feeds': [{'name': 'demo', 'url': 'https://feed.example/bundle.json'}]}))
            cache = root / 'cache'
            cache.mkdir()
            (cache / 'demo.json').write_text('previous bundle')
            opener = Mock()
            opener.open.side_effect = OSError('connection failed')
            with patch('apt_scope.feeds.build_opener', return_value=opener):
                result = refresh(config, cache)
            self.assertFalse(result['complete'])
            self.assertTrue(result['feeds'][0]['old_cache_may_remain'])
            self.assertEqual((cache / 'demo.json').read_text(), 'previous bundle')

    def test_redirects_not_followed(self):
        self.assertIsNone(NoRedirect().redirect_request(None, None, 302, '', {}, 'https://other.example'))
