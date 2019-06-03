import time
from twisted.internet import defer

from siptrackdlib import objecttree
from siptrackdlib import treenodes
from siptrackdlib import view
from siptrackdlib import password
from siptrackdlib import errors
from siptrackdlib import search
from siptrackdlib import log
from siptrackdlib.objectregistry import object_registry

STORE_VERSION = '2'

tree_callbacks = {
        'load_data': treenodes.load_data_callback,
        'remove': treenodes.remove_callback,
        'relocate': treenodes.relocate_callback
}

UNLINKED_CLASS_IDS = []
#UNLINKED_CLASS_IDS = ['EL']

class ObjectStore(object):
    def __init__(self, storage, preload = True, searcher = None):
        self.preload = preload
        self.storage = storage
        self.searcher = searcher
#        if not searcher:
#            self.searcher = search.MemorySearch()

    @defer.inlineCallbacks
    def init(self):
        yield self._checkStorage()
        self.call_loaded = True
        self.oid_class_mapping = yield self._loadOIDClassMapping()
        self.object_tree = objecttree.Tree(tree_callbacks, self)
        self.object_registry = object_registry
        exists = yield self.storage.OIDExists('0')
        if not exists:
            # FIXME: with a global object registry things break down if
            # someone tries to create multiple object stores. -- The oid
            # allocator specifically. This should be fixed.
            object_registry.next_oid = 0
            self.view_tree = object_registry.createObject(
                    view.ViewTree.class_id, self.object_tree)
            # This is usally done from <treenode>._created callback, but that
            # method is never called when creating the vt node this way.
            self.view_tree.storageAction('create_node')
            yield self.view_tree.commit()
#            self.storage.addOID('ROOT', self.view_tree.oid,
#                    view.ViewTree.class_id)
            self.oid_class_mapping[self.view_tree.oid] = view.ViewTree.class_id
        else:
            print 'Populating object tree'
            yield self._populateObjectTree()
            print 'Object tree populated'
            self.view_tree = self.getOID('0')
        object_registry.next_oid = yield self._getNextOID()
        if self.preload:
            print 'Preloading objects'
            yield self.preLoad()
            print 'Objects preloaded'
        self.event_triggers_enabled = True
        self.event_triggers = list(self.view_tree.listChildren(include = ['event trigger']))
        yield self.view_tree._init()
        if self.searcher:
            self.searcher._buildIndex(self)

    @defer.inlineCallbacks
    def reload(self):
        """Reload an object store.

        Reload the object store from the backend, dropping all cached
        nodes.
        """
        self.object_tree.free()
        self.oid_class_mapping = yield self._loadOIDClassMapping()
        self.object_tree = objecttree.Tree(tree_callbacks, self)
        yield self._populateObjectTree()
        self.view_tree = self.getOID('0')
        if self.preload:
            yield self.preLoad()
        yield self.view_tree._init()
        treenodes.perm_cache.clear()

    @defer.inlineCallbacks
    def _checkStorage(self):
        yield self.storage.initialize(STORE_VERSION)
        current_version = yield self.storage.getVersion()
        if current_version != STORE_VERSION:
            error = 'Wanted storage version %s, got version %s, please run `siptrackd upgrade`.' % (
                    STORE_VERSION, current_version)
            raise errors.InvalidStorageVersion(error)
        defer.returnValue(True)

    @defer.inlineCallbacks
    def preLoad(self):
        """Preload node data.

        The following happens:
          * All node data is grabbed from storage.
          * The object tree is walked grabbing ext_data from each bran
            which causes the node to load (but it's _loaded method is
            node called due to ObjectStore.call_loaded not being set.
          * The nodes data is passed to it via it's _loaded method.
            The node is free to do whatever it likes with the data,
            several node types currently don't have a _loaded method
            despite the fact that they have storage data. They should
            really be added.
        If no data exists for the oid an empty dict is passed in.
        The layout of the data passed to the node is a dict of one or
        more of:
        data['storage_data_name] = (data_type, data)
        """
        print 'Loading OID data'
        data_mapping = yield self.storage.makeOIDData(UNLINKED_CLASS_IDS)
        print 'OID data loaded'
        self.call_loaded = False
        try:
            for branch in self.object_tree.traverse():
#                if branch.hasExtData():
#                    continue
                node = branch.ext_data
                if not node:
                    log.msg('ObjectStore.preLoad branch %s returned no ext_data node, skipping' % (branch))
                    continue
                data = {}
                if branch.oid in data_mapping:
                    data = data_mapping[branch.oid]
                # Calling _loaded must be done with call_loaded enabled.
                # This is due to the possibility that a nodes _loaded
                # will use getOID to fetch another node which might not
                # have been loaded yet. If that happens with call_loaded =
                # False the node will be loaded without ever having
                # _loaded called, which might be very bad.
                self.call_loaded = True
                node._loaded(data)
                self.call_loaded = False
        finally:
            self.call_loaded = True
        defer.returnValue(True)

    @defer.inlineCallbacks
    def _loadOIDClassMapping(self):
        """Return a mapping (dict) of oid -> class_id.

        The ObjectStore keeps a dict of oid to class_id mappings.
        This is done to avoid hitting storage every time a node needs
        to be loaded. When loading a node only the oid is known (from the
        branch), so the class_id needs to be looked up.
        """
        # This is now done directly in storage to avoid loading unneeded data
        # (ie. data for UNLINKED_CLASS_IDS - event logs).
        ret = yield self.storage.makeOIDClassMapping(UNLINKED_CLASS_IDS)
        defer.returnValue(ret)

    @defer.inlineCallbacks
    def _getNextOID(self):
        """Return the next available object id.

        Checks the object id's allocated in storage and returns the
        next available one.
        """
        last_oid = 0
        res = yield self.storage.listOIDs()
        for parent_oid, oid in res:
            oid = int(oid)
            if oid > last_oid:
                last_oid = oid
        last_oid += 1
        defer.returnValue(last_oid)

    @defer.inlineCallbacks
    def _populateObjectTree(self):
        """Populate the object tree with oids.

        Grabs all existing oids from storage and loads them into the
        object tree (a branch is created per oid.
        Also loads all associations.
        """
        oids = yield self.storage.listOIDs()
        self.object_tree.loadBranches(oids)
        associations = yield self.storage.listAssociations()
        self.object_tree.loadAssociations(associations)
        defer.returnValue(True)

    def getOID(self, oid, valid_types = None, user = None):
        """Return the object with the given object id.

        Returns actual objects, not tree.branches.
        valid_type can be either a string with a class name or a
        list of class name strings. If set the returned node must
        be one of the given types.
        """
        branch = self.object_tree.getBranch(oid)
        if not branch:
            raise errors.NonExistent("object doesn\'t exist: %s(%s)" % (type(oid), oid))
        if valid_types in [str, unicode]:
            valid_types = [valid_types]
        if valid_types:
            if branch.ext_data.class_name not in valid_types:
                raise errors.NonExistent('invalid node type')
        if user and not branch.ext_data.hasReadPermission(user):
            raise errors.PermissionDenied()
        return branch.ext_data

    def quicksearch(self, search_pattern, attr_limit = [], include = [], exclude = [], user = None,
                   fuzzy = True, default_fields = [], max_results = None):
        """Quick search for text strings.

        Uses the searcher interface from search.py.

        search_pattern : text pattern to search for.
        include    : include only node types listed
        exclude    : exclude node types listed
        """
        if not self.searcher:
            raise errors.SiptrackError('no searcher selected, quicksearch unavailable')
        returned = {}
        count = 0
        for oid in self.searcher.search(search_pattern, fuzzy, default_fields, max_results=None):
            try:
                node = self.getOID(oid)
            except errors.NonExistent:
                log.msg('quicksearch matched non-existent oid, something is wrong: %s' % (oid))
                continue
            local_types = [
                'attribute',
                'versioned attribute',
                'encrypted attribute'
            ]
            if node.class_name in local_types:
                if len(attr_limit) > 0 and node.name not in attr_limit:
                    continue
                # Get the attributes nearest _non-attribute_ parent.
                node = node.getParentNode()
            if not node.hasReadPermission(user):
                continue
            if node.oid in returned:
                continue
            if len(include) > 0 and node.class_name not in include:
                continue
            if node.class_name in exclude:
                continue
            returned[node.oid] = True
            if max_results and count >= max_results:
                break
            count += 1
            yield node

    def quicksearchHostnames(self, search_pattern, user = None, max_results = None):
        """Quick search for text strings.

        Uses the searcher interface from search.py.

        search_pattern : text pattern to search for.
        include    : include only node types listed
        exclude    : exclude node types listed
        """
        if not self.searcher:
            raise errors.SiptrackError('no searcher selected, quicksearch unavailable')
        returned = {}
        count = 0
        for oid in self.searcher.searchHostnames(search_pattern, max_results=None):
            try:
                node = self.getOID(oid)
            except errors.NonExistent:
                log.msg('quicksearch matched non-existent oid, something is wrong: %s' % (oid))
                continue

            local_types = [
                'attribute',
                'versioned attribute',
                'encrypted attribute'
            ]

            if node.class_name in local_types:
                # Get the attributes nearest _non-attribute_ parent.
                node = node.getParentNode()
            if not node.hasReadPermission(user):
                continue
            if node.oid in returned:
                continue
            if node.class_name not in ['device']:
                continue
            returned[node.oid] = True
            if max_results and count >= max_results:
                break
            count += 1
            yield node

    def triggerEvent(self, event_type, *event_args, **event_kwargs):
        # Don't trigger any more events while in an event trigger,
        # otherwise we could end up in a nasty loop.
        # This means that no triggers will ever be run from what
        # happens inside a trigger (node creation etc).
        if not self.event_triggers_enabled:
            return
        self.event_triggers_enabled = False
        # Make sure trigger failures don't affect anything else.
        try:
            for event_trigger in self.event_triggers:
                event_trigger.triggerEvent(event_type, *event_args, **event_kwargs)
        except Exception, e:
            log.msg('Trigger %s raised unhandled exception: %s' % (event_trigger, str(e)))
        self.event_triggers_enabled = True

    @defer.inlineCallbacks
    def commit(self, orig_nodes):
        if type(orig_nodes) not in [list, tuple]:
            nodes = [orig_nodes]
        else:
            nodes = list(orig_nodes)
        # This happens in a seperate thread.
        def db_commit(txn, commit_data):
            start = time.time()
            print 'STARTING STORAGE COMMIT', start, len(commit_data)
            for node, actions in commit_data:
                for action in actions:
                    args = action.get('args')
                    if action['action'] == 'create_node':
                        parent_oid = 'ROOT'
                        parent = node.parent
                        if parent:
                            parent_oid = parent.oid
                        self.storage.addOID(parent_oid, node.oid, node.class_id, txn)
                    elif action['action'] == 'remove_node':
                        self.storage.removeOID(node.oid, txn)
                    elif action['action'] == 'remove_children':
                        self.storage.removeChildOID(node.oid, args['child_type'], txn)
                    elif action['action'] == 'relocate':
                        self.storage.relocate(node.oid, node.branch.parent.oid, txn)
                    elif action['action'] == 'associate':
                        self.storage.associate(node.oid, args['other'], txn)
                    elif action['action'] == 'disassociate':
                        self.storage.disassociate(node.oid, args['other'], txn)
                    elif action['action'] == 'write_data':
                        self.storage.writeData(node.oid, args['name'], args['value'], txn)
                    elif action['action'] == 'affecting_node':
                        nodes.append(args['node'])
            print 'STORAGE COMMIT DONE', start, time.time()-start
        def get_commit_data(nodes):
            data = []
            for node in nodes:
                if node._storage_actions:
                    actions = node._storage_actions
                    node._storage_actions = []
                    data.append((node, actions))
            return data
        st_d = self.storage.interact(db_commit, get_commit_data(nodes))
        yield st_d
        se_d = self.searcher.commit(orig_nodes)
        defer.returnValue(True)
