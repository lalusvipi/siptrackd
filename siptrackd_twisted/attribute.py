from twisted.web import xmlrpc
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
        return obj.oid

    @helpers.ValidateSession()
    def xmlrpc_set_value(self, session, oid, value):
        """Set an existing attributes value."""
        attribute = self.getOID(session, oid)
        # Binary data is converted into xmlrpclib.Binary objects. If this is
        # a binary attribute, make sure we received an xmlrpclib.Binary object
        # and extract the data.
        if attribute.atype == 'binary':
            try:
                value = str(value)
            except:
                raise siptrackdlib.errors.SiptrackError('attribute value doesn\'t match type')
        attribute.value = value
        return True

class VersionedAttributeRPC(baserpc.BaseRPC):
    node_type = 'versioned attribute'

    @helpers.ValidateSession()
    def xmlrpc_add(self, sid, parent_oid, name, atype, max_versions, value = None):
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
        return obj.oid

    @helpers.ValidateSession()
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
        return True

    @helpers.ValidateSession()
    def xmlrpc_set_max_versions(self, session, oid, max_versions):
        """Set an existing attributes value."""
        attribute = self.getOID(session, oid)
        attribute.max_versions = max_versions
        return True

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
