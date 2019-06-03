from twisted.internet import defer
from utils import BasicTestCase


class TestBasic(BasicTestCase):
    def testGetOID0(self):
        res = self.object_store.getOID('0')
        self.assertEqual(
            res,
            self.object_store.view_tree
        )

