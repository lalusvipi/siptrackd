from twisted.web import xmlrpc
from twisted.internet import defer

from siptrackdlib import device

from siptrackd_twisted import helpers
from siptrackd_twisted import gatherer
from siptrackd_twisted import errors
from siptrackd_twisted import baserpc

class DeviceRPC(baserpc.BaseRPC):
    node_type = 'device'

    @helpers.ValidateSession()
    @defer.inlineCallbacks
    def xmlrpc_add(self, session, parent_oid):
        """Create a new device."""
        parent = self.object_store.getOID(parent_oid, user = session.user)
        device = parent.add(session.user, 'device')
        device.addEventLog('create device', user=session.user)
        log = device.getParent('view').event_log_tree.addEventLog(
            'create device',
            {'oid': device.oid},
            user=session.user,
            affects=device
        )
        yield self.object_store.commit(device)
        defer.returnValue(device.oid)

    @helpers.ValidateSession()
    @defer.inlineCallbacks
    def xmlrpc_delete(self, session, oid, prune_networks = True):
        """Delete a device."""
        device = self.getOID(session, oid)
        log = device.getParent('view').event_log_tree.addEventLog('remove device', {'oid': device.oid, 'name': device.getAttributeValue('name', '')}, user=session.user, affects=device)
        updated = device.delete(recursive = True, user = session.user,
                prune_networks = prune_networks)
        log = device.getParent('view').event_log_tree.addEventLog(
            'remove device',
            {
                'oid': device.oid,
                'name': device.getAttributeValue('name', '')
            },
            user=session.user,
            affects=device
        )
        updated = device.delete(
            recursive=True,
            user=session.user,
            prune_networks=prune_networks)
        yield self.object_store.commit(updated)
        defer.returnValue(True)

    @helpers.ValidateSession()
    @defer.inlineCallbacks
    def xmlrpc_autoassign_network(self, session, oid):
        """Autoassign a network to a device."""
        device = self.getOID(session, oid)
        network, modified = device.autoAssignNetwork(session.user)
        yield self.object_store.commit(modified)
        defer.returnValue(network.oid)

class DeviceTreeRPC(baserpc.BaseRPC):
    node_type = 'device tree'

    @helpers.ValidateSession()
    @defer.inlineCallbacks
    def xmlrpc_add(self, session, parent_oid):
        """Create a new device tree."""
        parent = self.object_store.getOID(parent_oid, user = session.user)
        obj = parent.add(session.user, 'device tree')
        yield self.object_store.commit(obj)
        defer.returnValue(obj.oid)

class DeviceCategoryRPC(baserpc.BaseRPC):
    node_type = 'device category'

    @helpers.ValidateSession()
    @defer.inlineCallbacks
    def xmlrpc_add(self, session, parent_oid):
        """Create a new device category."""
        parent = self.object_store.getOID(parent_oid, user = session.user)
        obj = parent.add(session.user, 'device category')
        yield self.object_store.commit(obj)
        defer.returnValue(obj.oid)

gatherer.node_data_registry.register(device.Device,
        gatherer.no_data_extractor)
gatherer.node_data_registry.register(device.DeviceTree,
        gatherer.no_data_extractor)
gatherer.node_data_registry.register(device.DeviceCategory,
        gatherer.no_data_extractor)
