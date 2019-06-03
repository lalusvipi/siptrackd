from twisted.web import xmlrpc
from twisted.internet import defer
import xmlrpclib

from siptrackdlib import attribute
import siptrackdlib.errors

from siptrackd_twisted import helpers
from siptrackd_twisted import gatherer
from siptrackd_twisted import baserpc
import siptrackd_twisted.errors

class AttributeRPC(baserpc.BaseRPC):
    node_type = 'attribute'

    @helpers.ValidateSession()
    @defer.inlineCallbacks
    def xmlrpc_add(self, session, parent_oid, name, atype, value):
        """Create a new attribute."""
        parent = self.object_store.getOID(parent_oid, user = session.user)
        # Binary data is converted into xmlrpclib.Binary objects. If this is
        # a binary attribute, make sure we received an xmlrpclib.Binary object
        # and extract the data.
        if atype == 'binary':
            try:
                value = str(value)
            except:
                raise siptrackdlib.errors.SiptrackError('attribute value doesn\'t match type')
        obj = parent.add(session.user, 'attribute', name, atype, value)
        if parent.class_name == 'password' and parent.parent.class_name == 'device' and name == 'username':
            data = {'device_user': value}
            if parent.password_key:
                key_name = parent.password_key.getAttributeValue('name', '')
                data.update({'password_key_name': key_name})
            parent.parent.addEventLog('device user added', data, session.user, affects=obj)
        if parent.class_name == 'device':
            parent.addEventLog(
                'create attribute',
                {'name': name},
                session.user,
                affects=obj
            )

        yield self.object_store.commit(obj)
        defer.returnValue(obj.oid)

    @helpers.ValidateSession()
    @defer.inlineCallbacks
    def xmlrpc_set_value(self, session, oid, value):
        """Set an existing attributes value."""
        attribute = self.getOID(session, oid)
        # Binary data is converted into xmlrpclib.Binary objects. If this is
        # a binary attribute, make sure we received an xmlrpclib.Binary object
        # and extract the data.
        if attribute.atype == 'binary':
            try:
                value = value.data
            except:
                raise siptrackdlib.errors.SiptrackError('attribute value doesn\'t match type')
        attribute.value = value
        if attribute.parent.class_name == 'device':
            attribute.parent.addEventLog(
                'update attribute',
                {'name': attribute.name},
                session.user,
                affects=attribute
            )
        yield self.object_store.commit(attribute)
        defer.returnValue(True)

    @helpers.ValidateSession()
    @defer.inlineCallbacks
    def xmlrpc_delete(self, session, oid, recursive = True):
        """Delete a node."""
        node = self.getOID(session, oid)
        parent = node.parent
        updated = node.delete(recursive, session.user)
        if parent.class_name == 'device':
            parent.addEventLog(
                'remove attribute',
                {'name': node.name},
                session.user,
                affects=node
            )
        yield self.object_store.commit(updated)
        defer.returnValue(True)

class VersionedAttributeRPC(baserpc.BaseRPC):
    node_type = 'versioned attribute'

    @helpers.ValidateSession()
    @defer.inlineCallbacks
    def xmlrpc_add(self, session, parent_oid, name, atype, max_versions, value = None):
        """Create a new versioned attribute."""
        parent = self.object_store.getOID(parent_oid, user = session.user)
        # Binary data is converted into xmlrpclib.Binary objects. If this is
        # a binary attribute, make sure we received an xmlrpclib.Binary object
        # and extract the data.
        if atype == 'binary':
            try:
                value = value.data
            except:
                raise siptrackdlib.errors.SiptrackError('attribute value doesn\'t match type')
        obj = parent.add(session.user, 'versioned attribute', name, atype, value, max_versions)
        if parent.class_name == 'device':
            parent.addEventLog(
                'create attribute',
                {'name': name},
                session.user,
                affects=obj
            )
        yield self.object_store.commit(obj)
        defer.returnValue(obj.oid)

    @helpers.ValidateSession()
    @defer.inlineCallbacks
    def xmlrpc_set_value(self, session, oid, value):
        """Set an existing attributes value."""
        attribute = self.getOID(session, oid)
        # Binary data is converted into xmlrpclib.Binary objects. If this is
        # a binary attribute, make sure we received an xmlrpclib.Binary object
        # and extract the data.
        if attribute.atype == 'binary':
            try:
                value = value.data
            except:
                raise siptrackdlib.errors.SiptrackError('attribute value doesn\'t match type')
        attribute.value = value
        if attribute.parent.class_name == 'device':
            attribute.parent.addEventLog(
                'update attribute',
                {'name': attribute.name},
                session.user,
                affects=attribute
            )
        yield self.object_store.commit(attribute)
        defer.returnValue(True)

    @helpers.ValidateSession()
    @defer.inlineCallbacks
    def xmlrpc_set_max_versions(self, session, oid, max_versions):
        """Set an existing attributes value."""
        attribute = self.getOID(session, oid)
        attribute.max_versions = max_versions
        yield self.object_store.commit(attribute)
        defer.returnValue(True)

    @helpers.ValidateSession()
    @defer.inlineCallbacks
    def xmlrpc_delete(self, session, oid, recursive = True):
        """Delete a node."""
        node = self.getOID(session, oid)
        parent = node.parent
        updated = node.delete(recursive, session.user)
        if parent.class_name == 'device':
            parent.addEventLog(
                'remove attribute',
                {'name': node.name},
                session.user,
                affects=node
            )
        yield self.object_store.commit(updated)
        defer.returnValue(True)


class EncryptedAttributeRPC(baserpc.BaseRPC):
    node_type = 'encrypted attribute'

    @helpers.ValidateSession()
    @defer.inlineCallbacks
    def xmlrpc_add(self, session, parent_oid, name, atype, value):
        """Create a new attribute."""
        parent = self.object_store.getOID(parent_oid, user = session.user)
        obj = parent.add(session.user, 'encrypted attribute', name, atype, value)
        if parent.class_name == 'device':
            parent.addEventLog(
                'create attribute',
                {'name': name},
                session.user,
                affects=obj
            )
        yield self.object_store.commit(obj)
        defer.returnValue(obj.oid)


    @helpers.ValidateSession()
    @defer.inlineCallbacks
    def xmlrpc_set_value(self, session, oid, value):
        """Set an existing attributes value."""
        attribute = self.getOID(session, oid)
        attribute.value = value
        if attribute.parent.class_name == 'device':
            attribute.parent.addEventLog(
                'update attribute',
                {'name': attribute.name},
                session.user,
                affects=attribute
            )
        yield self.object_store.commit(attribute)
        defer.returnValue(True)


    @helpers.ValidateSession()
    @defer.inlineCallbacks
    def xmlrpc_delete(self, session, oid, recursive = True):
        """Delete a node."""
        node = self.getOID(session, oid)
        parent = node.parent
        updated = node.delete(recursive, session.user)
        if parent.class_name == 'device':
            parent.addEventLog(
                'remove attribute',
                {'name': node.name},
                session.user,
                affects=node
            )
        yield self.object_store.commit(updated)
        defer.returnValue(True)


def encrypted_attribute_data_extractor(node, user):
    # errors.SiptrackError is raised by attribute.getPassword often when
    # searching objects or listing objects with enca attributes connected
    # to keys that the current user does not have access to. So default to
    # showing a blank attribute.
    #
    # TODO: Some indication that the user lacks password key access to show
    # the encrypted attribute. Or solve it in siptrackweb by simply showing
    # the password key each attribute is connected to along with the blank
    # attribute value.
    try:
        value = node.getAttribute(user)
    except Exception as e:
        value = ''
        pass

    return [node.name, node.atype, value]


def attribute_data_extractor(node, user):
    value = node.value
    # Binary data needs to be wrapped in xmlrpclib.Binary.
#    if node.atype == 'binary':
#        value = xmlrpclib.Binary(value)
    return [node.name, node.atype, value]


def versioned_attribute_data_extractor(node, user):
    values = node.values
    # Binary data needs to be wrapped in xmlrpclib.Binary.
    if node.atype == 'binary':
        values = [xmlrpclib.Binary(value) for value in node.values]
    return [node.name, node.atype, values, node.max_versions]


gatherer.node_data_registry.register(attribute.Attribute,
        attribute_data_extractor)

gatherer.node_data_registry.register(attribute.VersionedAttribute,
        versioned_attribute_data_extractor)

gatherer.node_data_registry.register(
    attribute.EncryptedAttribute,
    encrypted_attribute_data_extractor
)
