import xmlrpclib
from twisted.web import xmlrpc
import twisted.python
from twisted.internet import threads
from twisted.internet import defer

from siptrackd_twisted import log
from siptrackd_twisted import helpers

class BaseRPC(xmlrpc.XMLRPC):
    def __init__(self, object_store, session_handler):
        xmlrpc.XMLRPC.__init__(self)
        self.object_store = object_store
        self.session_handler = session_handler

    def _get_view_tree(self):
        return self.object_store.view_tree
    def _set_view_tree(self, val):
        pass
    view_tree = property(_get_view_tree, _set_view_tree)

    def getOID(self, session, oid):
        return self.object_store.getOID(oid, self.node_type, user = session.user)

    @helpers.ValidateSession()
    @defer.inlineCallbacks
    def xmlrpc_add(self, session, parent_oid, *args, **kwargs):
        """Create a new node."""
        parent = self.object_store.getOID(parent_oid, user = session.user)
        node = parent.add(session.user, self.node_type, *args, **kwargs)
        yield node.commit()
        defer.returnValue(node.oid)

    @helpers.ValidateSession()
    @defer.inlineCallbacks
    def xmlrpc_delete(self, session, oid, recursive = True):
        """Delete a node."""
        node = self.getOID(session, oid)
        # TODO: Add more conditionals here for 'device category' perhaps?
        if node.parent.class_name == 'device' and node.class_name == 'password':
            data = {'device_user': node.getAttributeValue('username', '')}
            node.parent.addEventLog('device user removed', data, session.user, affects=node.parent)
        updated = node.delete(recursive, session.user)
        yield self.object_store.commit(updated)
        defer.returnValue(True)

    @defer.inlineCallbacks
    def _cbRender(self, result, request, responseFailed=None):
        """Override method to do threaded xmlrpclib.dump.

        This is ugly and non-portable, but will have to do for now.
        """
        if responseFailed:
            return

        if isinstance(result, xmlrpc.Handler):
            result = result.result
        if not isinstance(result, xmlrpc.Fault):
            result = (result,)
        try:
            try:
                content = yield self.threadDumpResult(result)
            except Exception, e:
                f = xmlrpc.Fault(self.FAILURE, "Can't serialize output: %s" % (e,))
                content = xmlrpclib.dumps(f, methodresponse=True,
                                          allow_none=self.allowNone)

            request.setHeader("content-length", str(len(content)))
            request.write(content)
        except:
            twisted.python.log.err()
        request.finish()

    def threadDumpResult(self, *args, **kwargs):
        """Threaded xmlrpclib.dumps."""
        return threads.deferToThread(self._threadDumpResult, *args, **kwargs)

    def _threadDumpResult(self, data):
        if data is None:
            data = self.prepared_data
        data = data
        content = xmlrpclib.dumps(
            data, methodresponse=True,
            allow_none=self.allowNone)
        return content
