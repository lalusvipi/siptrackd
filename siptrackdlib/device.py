from siptrackdlib.objectregistry import object_registry
from siptrackdlib import treenodes
from siptrackdlib import attribute
from siptrackdlib import permission
from siptrackdlib import password
from siptrackdlib import counter
from siptrackdlib import errors
from siptrackdlib import template
from siptrackdlib import config
from siptrackdlib import storagevalue
from siptrackdlib import deviceconfig
from siptrackdlib import eventlog

class DeviceTree(treenodes.BaseNode):
    class_id = 'DT'
    class_name = 'device tree'

    def __init__(self, oid, branch):
        super(DeviceTree, self).__init__(oid, branch)

class DeviceCategory(treenodes.BaseNode):
    class_id = 'DC'
    class_name = 'device category'
    
    def __init__(self, oid, branch):
        super(DeviceCategory, self).__init__(oid, branch)

class Device(treenodes.BaseNode):
    class_id = 'D'
    class_name = 'device'

    def __init__(self, oid, branch):
        super(Device, self).__init__(oid, branch)

    def _created(self, user):
        super(Device, self)._created(user)

    def _loaded(self, data = None):
        super(Device, self)._loaded(data)

    def relocate(self, new_parent, user = None):
        # TODO: add event log here?
        old_parent = self.parent
        super(Device, self).relocate(new_parent, user)

    def remove(self, recursive, user = None, prune_networks = False):
        """Remove a device.

        We override the default remove method due to prune_networks.
        """
        associations = []
        if prune_networks:
            if recursive:
                for entity in self.traverse(user=user):
                    associations += entity.listAssocRef()
            else:
                associations = self.listAssocRef()
        updated = self.branch.remove(recursive, user)
        if prune_networks:
            for association in associations:
                updated += association.prune(user)
        return updated
    delete = remove

    def _remove(self, user):
        ret = super(Device, self)._remove(user)
        # TODO: Test if this is necessary to keep because Device.remove()
        # is already calling branch.remove recursively so why keep
        # the remove_children storage action?
        self.storageAction('remove_children', {'child_type': 'EL'})
        return ret

    def autoAssignNetwork(self, user):
        for config_net in config.get_config_network_autoassign(self):
            if not config_net.network_tree.get():
                continue
            free, modified = config_net.network_tree.get().getFreeNetwork(
                    config_net.range_start.get(),
                    config_net.range_end.get(),
                    user)
            if not free:
                continue
            self.associate(free)
            if modified is None:
                modified = []
            modified.append(self)
            return free, modified
        raise errors.SiptrackError('device unable to autoassign, no available networks')

# Add the objects in this module to the object registry.
o = object_registry.registerClass(DeviceTree)
o.registerChild(attribute.Attribute)
o.registerChild(attribute.VersionedAttribute)
o.registerChild(Device)
o.registerChild(DeviceCategory)
o.registerChild(template.DeviceTemplate)
o.registerChild(config.ConfigNetworkAutoassign)
o.registerChild(config.ConfigValue)
o.registerChild(permission.Permission)

o = object_registry.registerClass(DeviceCategory)
o.registerChild(attribute.Attribute)
o.registerChild(attribute.VersionedAttribute)
o.registerChild(Device)
o.registerChild(DeviceCategory)
o.registerChild(template.DeviceTemplate)
o.registerChild(config.ConfigNetworkAutoassign)
o.registerChild(config.ConfigValue)
o.registerChild(permission.Permission)

o = object_registry.registerClass(Device)
o.registerChild(attribute.Attribute)
o.registerChild(attribute.VersionedAttribute)
o.registerChild(Device)
o.registerChild(password.Password)
o.registerChild(config.ConfigNetworkAutoassign)
o.registerChild(config.ConfigValue)
o.registerChild(permission.Permission)
o.registerChild(deviceconfig.DeviceConfig)
o.registerChild(deviceconfig.DeviceConfigTemplate)
o.registerChild(eventlog.EventLog)

