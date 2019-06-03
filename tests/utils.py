import os
import shutil
import tempfile
from ConfigParser import RawConfigParser

from twisted.trial import unittest
from twisted.internet import defer
from twisted.internet import reactor

import siptrackdlib
from siptrackdlib.storage import stsqlite


def make_storage(config):
    return siptrackdlib.storage.load(
        'stsqlite',
        config
    )


@defer.inlineCallbacks
def make_object_store(config):
    storage = make_storage(config)
    searcher = siptrackdlib.search.get_searcher('whoosh')
    object_store = siptrackdlib.ObjectStore(
        storage,
        searcher=searcher
    )
    yield object_store.init()
    defer.returnValue(object_store)


class BasicTestCase(unittest.TestCase):
    @defer.inlineCallbacks
    def setUp(self):
        self.config = RawConfigParser()
        self.config.add_section('sqlite')
        self.config.set('sqlite', 'filename', './db.sqlite')
        self.tempdir = self._makeTempDir()
        self.object_store = yield make_object_store(self.config)

    def tearDown(self):
        self._cleanTempDir(self.tempdir)

    def _makeTempDir(self):
        return tempfile.mkdtemp()

    def _cleanTempDir(self, dir):
        if not os.path.isdir(dir):
            return
        norm_path = os.path.abspath(os.path.normpath(dir))
        if os.path.normpath == '/':
            return
        shutil.rmtree(dir)

    @defer.inlineCallbacks
    def reloadObjectStore(self):
        yield self.object_store.reload()

