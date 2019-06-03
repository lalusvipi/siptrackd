from utils import BasicTestCase


def raise_exception(a):
    raise Exception(a)

class TestTests(BasicTestCase):
    def testAssert(self):
        self.assert_(1 in [1, 2, 3])

    def testAssertEqual(self):
        self.assertEqual(True, True)

    def testAssertRaises(self):
        self.assertRaises(Exception, raise_exception, 1)
