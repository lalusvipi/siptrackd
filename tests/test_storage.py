from twisted.internet import defer
from siptrackdlib.upgrade import perform_upgrade
from utils import BasicTestCase, make_storage


class TestStorage(BasicTestCase):

    @defer.inlineCallbacks
    def testStorageUpgrade(self):
        storage = make_storage(self.config)
        yield perform_upgrade(
            storage
        )
