from utils import BasicTestCase
import siptrackdlib.errors


class TestObjectStore(BasicTestCase):
    def testGetMissingOID(self):
        self.assertRaises(
            siptrackdlib.errors.NonExistent,
            self.object_store.getOID,
            'abc'
        )

    def testGetExistingOID(self):
        obj = self.object_store.getOID('0')

    # TODO: Figure out this later.
    #def testPersistentObjects(self):
    #    oid = self.object_store.view_tree.add(None, 'view').oid
    #    self.reloadObjectStore()
    #    obj = self.object_store.getOID(oid)
    #    self.assertEqual(oid, obj.oid)
