import sys
import os
import time
import pprint
import traceback
from argparse import ArgumentParser, FileType
from ConfigParser import RawConfigParser

from twisted.internet import threads
from twisted.application import internet
from twisted.application import service
from twisted.application import app
from twisted.web import xmlrpc
from twisted.web import server
from twisted.cred import checkers
from twisted.internet import defer, reactor

try:
    from twisted.internet import ssl
    from OpenSSL import SSL
except ImportError:
    ssl = None
if ssl and not ssl.supported:
    ssl = None

from siptrackd_twisted import gatherer
from siptrackd_twisted import sessions
from siptrackd_twisted import helpers
from siptrackd_twisted import view
from siptrackd_twisted import counter
from siptrackd_twisted import network
from siptrackd_twisted import device
from siptrackd_twisted import password
from siptrackd_twisted import container
from siptrackd_twisted import attribute
from siptrackd_twisted import user
from siptrackd_twisted import template
from siptrackd_twisted import config
from siptrackd_twisted import simple
from siptrackd_twisted import baserpc
from siptrackd_twisted import log
from siptrackd_twisted import permission
from siptrackd_twisted import event
from siptrackd_twisted import deviceconfig
from siptrackd_twisted import eventlog

import siptrackdlib
import siptrackdlib.errors
import siptrackdlib.storage
import siptrackdlib.search
import siptrackdlib.log
import siptrackdlib.upgrade
from siptrackdlib.storage import stsqlite
from siptrackd_twisted import errors

DEFAULT_LISTEN_PORT = 9242
DEFAULT_SSL_LISTEN_PORT = 9243

# Evidently xmlrpclib converts incoming strings first to unicode, then to
# plain ascii strings if possible. We want unicode all over, so we need to
# check if inbound arguments are regular strings, and convert them to unicode
# if they are.
class SiptrackdRPC(baserpc.BaseRPC):
    """A basic twisted xmlrpc server class.

    Each method prefixed with xmlrpc_ is exported as an xmlrpc function.
    Most of the methods are wrapped in the 'error_handler' function that
    takes basic SiptrackError exceptions and returns xmlrpc Faults with
    the same error message as the SiptrackError exception.

    If no specific data is to be returned, return True if everything worked
    out or an xmlrpclib Fault if things went wrong.
    """
    @helpers.error_handler
    @defer.inlineCallbacks
    def xmlrpc_login(self, username, password):
        """Start a new session."""
        user, updated = self.view_tree.user_manager.login(username, password)
        if updated:
            yield self.object_store.commit(updated)
        if not user:
            log.msg('Invalid login for %s' % (username))
            raise errors.InvalidLoginError()
        log.msg('Valid login for %s' % (username))
        session = self.session_handler.startSession()
        session.user = user
        defer.returnValue(session.id)
    xmlrpc_login.signature = []
    xmlrpc_login.help = 'Start a new session, returns a session id.'

    @helpers.error_handler
    def xmlrpc_logout(self, session_id):
        """End a session."""
        self.session_handler.endSession(session_id)
        return True
    xmlrpc_logout.signature = [['boolean', 'string']]
    xmlrpc_logout.help = 'Terminate a session.'

    @helpers.error_handler
    def xmlrpc_ping(self):
        """Simple way to test if the server is responding."""
        return time.time()

    @helpers.error_handler
    def xmlrpc_version(self):
        """Returns siptrackd version information."""
        return siptrackdlib.version_information

    @helpers.error_handler
    def xmlrpc_hello(self, session_id):
        """Returns 1 for valid session id, 0 for invalid."""
        try:
            session = self.session_handler.fetchSession(session_id)
            return 1
        except errors.InvalidSessionError:
            return 0

    @helpers.ValidateSession()
    def xmlrpc_session_user_oid(self, session):
        """Return the oid for the user of the current session."""
        ret = session.user.user.oid
        return ret

    @helpers.ValidateSession()
    def xmlrpc_session_user_password_has_changed(self, session, password):
        session_user = session.user.user
        return session_user.passwordHasChanged(password)

    @helpers.ValidateSession()
    def xmlrpc_oid_exists(self, session, oid):
        """Check if an oid exists."""
        log.debug('oid_exists %s' % (oid), session.user)
        try:
            obj = self.object_store.getOID(oid)
        except siptrackdlib.errors.NonExistent:
            return False
        return True
    xmlrpc_location_exists = xmlrpc_oid_exists

    @helpers.ValidateSession()
    @defer.inlineCallbacks
    def xmlrpc_move_oid(self, session, oid, new_parent_oid):
        """Move an oid to a new parent."""
        obj = self.object_store.getOID(oid, user = session.user)

        if new_parent_oid in ['', 'ROOT']:
            new_parent = self.object_store.view_tree
        else:
            new_parent = self.object_store.getOID(
                new_parent_oid,
                user = session.user
            )

        old_parent = obj.parent
        obj.relocate(new_parent, user = session.user)

        if obj.class_name == 'device':
            data = {
                'src_oid': old_parent.oid,
                'dst_oid': new_parent.oid,
                'src_name': old_parent.getAttributeValue('name', ''),
                'dst_name': new_parent.getAttributeValue('name', '')
            }
            obj.addEventLog('relocate device', data, session.user)

        yield obj.commit()
        defer.returnValue(True)
    xmlrpc_relocate = xmlrpc_move_oid

    @helpers.ValidateSession()
    def xmlrpc_iter_fetch(self, session, oids, max_depth = -1, include_parents = True,
            include_associations = True, include_references = True):
        """Fetch data from a oid (and it's children)."""
        if type(oids) != list:
            oids = [oids]
        listcreator = gatherer.ListCreator(self.object_store, session.user)
        nodes = []
        for oid in oids:
            if oid in ['', 'ROOT']:
                oid = self.object_store.view_tree.oid
            # If the root is being fetched, and max_depth == -1, that's a
            # full tree fetch, checking for incude_parent/associations/references
            # will just slow things down markedly.
            if oid == self.object_store.view_tree.oid and max_depth == -1:
                include_parents = False
                include_associations = False
                include_references = False
            node = self.object_store.getOID(oid, user = session.user)
            nodes.append(node)
        build_iter = listcreator.iterBuild(nodes, max_depth, include_parents,
                include_associations, include_references)
        iter_id = session.data_iterators.add(build_iter)
        return session.data_iterators.getData(iter_id)

    @helpers.ValidateSession()
    def xmlrpc_iter_fetch_next(self, session, iter_id):
        """Fetch data from a oid (and it's children)."""
        return session.data_iterators.getData(iter_id)

    @helpers.ValidateSession()
    def xmlrpc_iter_quicksearch(self, session, search_pattern, attr_limit = [],
            include = [], exclude = [], include_data = True,
            include_parents = True, include_associations = True,
            include_references = True, fuzzy = True, default_fields = ['name', 'description'],
            max_results = None):
        """Search for objects starting at oid."""
        user = session.user
        searcher = self.object_store.quicksearch(search_pattern,
                                                 attr_limit,
                                                 include,
                                                 exclude,
                                                 user,
                                                 fuzzy,
                                                 default_fields,
                                                 max_results)
        listcreator = gatherer.ListCreator(self.object_store, user)
        build_iter = listcreator.iterSearch(searcher, include_data, include_parents,
                include_associations, include_references)
        iter_id = session.data_iterators.add(build_iter)
        return session.data_iterators.getData(iter_id)

    @helpers.ValidateSession()
    def xmlrpc_iter_quicksearch_next(self, session, iter_id):
        return session.data_iterators.getData(iter_id)

    @helpers.ValidateSession()
    def xmlrpc_iter_quicksearch_hostnames(self, session, search_pattern, include_data = True,
            include_parents = True, include_associations = True,
            include_references = True,
            max_results = None):
        """Search for objects starting at oid."""
        user = session.user
        searcher = self.object_store.quicksearchHostnames(search_pattern,
                                                 user,
                                                 max_results)
        listcreator = gatherer.ListCreator(self.object_store, user)
        build_iter = listcreator.iterSearch(searcher, include_data, include_parents,
                include_associations, include_references)
        iter_id = session.data_iterators.add(build_iter)
        return session.data_iterators.getData(iter_id)

    @helpers.ValidateSession()
    def xmlrpc_iter_quicksearch_hostnames_next(self, session, iter_id):
        return session.data_iterators.getData(iter_id)

    @helpers.ValidateSession()
    def xmlrpc_iter_search(self, session, oid, search_pattern, attr_limit = [],
            include = [], exclude = [], no_match_break = False,
            include_data = True, include_parents = True, include_associations = True,
            include_references = True):
        """Search for objects starting at oid."""
        if oid in ['', 'ROOT']:
            oid = self.object_store.view_tree.oid
        root = self.object_store.getOID(oid, user = session.user)
        searcher = root.search(search_pattern, attr_limit, include,
                exclude, no_match_break, user = session.user)
        listcreator = gatherer.ListCreator(self.object_store, session.user)
        build_iter = listcreator.iterSearch(searcher, include_data, include_parents,
                include_associations, include_references)
        iter_id = session.data_iterators.add(build_iter)
        return session.data_iterators.getData(iter_id)

    @helpers.ValidateSession()
    def xmlrpc_iter_search_next(self, session, iter_id):
        return session.data_iterators.getData(iter_id)

    @helpers.ValidateSession()
    @defer.inlineCallbacks
    def xmlrpc_associate(self, session, oid_1, oid_2):
        """Create an association between two objects."""
        obj_1 = self.object_store.getOID(oid_1, user = session.user)
        obj_2 = self.object_store.getOID(oid_2, user = session.user)
        obj_1.associate(obj_2)
        yield self.object_store.commit([obj_1, obj_2])
        defer.returnValue(True)

    @helpers.ValidateSession()
    @defer.inlineCallbacks
    def xmlrpc_disassociate(self, session, oid_1, oid_2):
        """Remove an association between two objects."""
        obj_1 = self.object_store.getOID(oid_1, user = session.user)
        obj_2 = self.object_store.getOID(oid_2, user = session.user)
        obj_1.disassociate(obj_2)
        yield self.object_store.commit([obj_1, obj_2])
        defer.returnValue(True)

    @helpers.ValidateSession()
    def xmlrpc_is_associated(self, session, oid_1, oid_2):
        """Remove an association between two objects."""
        obj_1 = self.object_store.getOID(oid_1, user = session.user)
        obj_2 = self.object_store.getOID(oid_2, user = session.user)
        return obj_1.isAssociated(obj_2)

    @helpers.ValidateSession()
    def xmlrpc_set_session_timeout(self, session, timeout):
        """Set a new max session idle timeout value for an active session."""
        session.setMaxIdle(timeout)
        return True

    @helpers.ValidateSession(require_admin=True)
    def xmlrpc_list_sessions(self, session):
        """List current active sessions."""
        sessions = []
        for session_id in self.session_handler.sessions:
            timeout = self.session_handler.sessions[session_id].max_idle - \
                    int(self.session_handler.sessions[session_id].idletime())
            session = {}
            session['id'] = session_id
            session['user'] = self.session_handler.sessions[session_id].user.user._username.get()
            session['timeout'] = timeout
            sessions.append(session)
        return sessions

    @helpers.ValidateSession(require_admin=True)
    def xmlrpc_kill_session(self, session, session_id):
        """Kill specified session."""
        self.session_handler.endSession(session_id)
        return True

    @helpers.ValidateSession(require_admin=True)
    def xmlrpc_flush_gatherer_data_cache(self, session):
        gatherer.entity_data_cache.flush()
        return True

    @helpers.ValidateSession(require_admin=True)
    def xmlrpc_get_oid_gatherer_data_cache(self, session, oid):
        ret = gatherer.entity_data_cache.cache.get(oid, False)
        return ret

    @helpers.ValidateSession(require_admin=True)
    def xmlrpc_log_permission_cache(self, session, oid, user_oid = None):
        node = self.object_store.getOID(oid)
        user = None
        if user_oid:
            user = self.object_store.getOID(user_oid)
        node.logPermissionCache(user)
        return True

    @helpers.ValidateSession(require_admin=True)
    @defer.inlineCallbacks
    def xmlrpc_reload_objectstore(self, session):
        log.msg('Reloading object store by command')
        try:
            yield self.object_store.reload()
            self.session_handler.killAllSessions()
        except Exception, e:
            log.msg('Reload failed: %s' % (e))
            tbmsg = traceback.format_exc()
            log.msg(tbmsg)
        else:
            log.msg('Reload complete')
        defer.returnValue(True)

@defer.inlineCallbacks
def object_store_reloader(session_handler, object_store, reload_interval):
    log.msg('Reloading object store by interval')
    try:
        yield object_store.reload()
        session_handler.killAllSessions()
    except Exception, e:
        log.msg('Reload failed: %s' % (e))
        tbmsg = traceback.format_exc()
        log.msg(tbmsg)
    else:
        log.msg('Reload complete')
    reactor.callLater(reload_interval, object_store_reloader, session_handler, object_store, reload_interval)

@defer.inlineCallbacks
def siptrackd_twisted_init(object_store, application):
    log.msg('Loading object store, this might take a while')
    yield object_store.init()
    log.msg('Object store loading complete')
    log.msg('Starting rpc listener')
    app.startApplication(application, False)
    log.msg('Running')


class SiptrackOpenSSLContextFactory(ssl.ContextFactory):
    """Initiate an openssl context.

    This is basically a straight copy of twisted.internet.ssl.DefaultOpenSSLContextFactory
    with the difference that it uses SSL.use_certificate_chain_file to
    allow use of certificate chains.
    """
    _context = None

    def __init__(self, privateKeyFileName, certificateFileName,
                 sslmethod=SSL.SSLv23_METHOD, _contextFactory=SSL.Context):
        """
        @param privateKeyFileName: Name of a file containing a private key
        @param certificateFileName: Name of a file containing a certificate
        @param sslmethod: The SSL method to use
        """
        self.privateKeyFileName = privateKeyFileName
        self.certificateFileName = certificateFileName
        self.sslmethod = sslmethod
        self._contextFactory = _contextFactory

        # Create a context object right now.  This is to force validation of
        # the given parameters so that errors are detected earlier rather
        # than later.
        self.cacheContext()

    def cacheContext(self):
        if self._context is None:
            ctx = self._contextFactory(self.sslmethod)
            # Disallow SSLv2!  It's insecure!  SSLv3 has been around since
            # 1996.  It's time to move on.
            ctx.set_options(SSL.OP_NO_SSLv2)
#            ctx.use_certificate_file(self.certificateFileName)
            ctx.use_certificate_chain_file(self.certificateFileName)
            ctx.use_privatekey_file(self.privateKeyFileName)
            self._context = ctx

    def __getstate__(self):
        d = self.__dict__.copy()
        del d['_context']
        return d

    def __setstate__(self, state):
        self.__dict__ = state

    def getContext(self):
        """
        Return an SSL context.
        """
        return self._context


def run_siptrackd_twisted(listen_port, ssl_port,
        ssl_private_key, ssl_certificate, storage, reload_interval,
        searcher):
    log.msg('Creating object store')
    object_store = siptrackdlib.ObjectStore(storage, searcher = searcher)
    session_handler = sessions.SessionHandler()

    log.msg('Creating rpc interface')
    siptrackd_rpc = SiptrackdRPC(object_store, session_handler)
    xmlrpc.addIntrospection(siptrackd_rpc)

    view_rpc = view.ViewRPC(object_store, session_handler)
    siptrackd_rpc.putSubHandler('view', view_rpc)
    view_tree_rpc = view.ViewTreeRPC(object_store, session_handler)
    view_rpc.putSubHandler('tree', view_tree_rpc)
    
    counter_rpc = counter.CounterRPC(object_store, session_handler)
    siptrackd_rpc.putSubHandler('counter', counter_rpc)
    counter_loop_rpc = counter.CounterLoopRPC(object_store, session_handler)
    counter_rpc.putSubHandler('loop', counter_loop_rpc)

    user_rpc = user.UserRPC(object_store, session_handler)
    siptrackd_rpc.putSubHandler('user', user_rpc)

    user_local_rpc = user.UserLocalRPC(object_store, session_handler)
    user_rpc.putSubHandler('local', user_local_rpc)

    user_ldap_rpc = user.UserLDAPRPC(object_store, session_handler)
    user_rpc.putSubHandler('ldap', user_ldap_rpc)

    user_active_directory_rpc = user.UserActiveDirectoryRPC(object_store, session_handler)
    user_rpc.putSubHandler('activedirectory', user_active_directory_rpc)
    user_rpc.putSubHandler('ad', user_active_directory_rpc)

    user_manager_rpc = user.UserManagerRPC(object_store, session_handler)
    user_rpc.putSubHandler('manager', user_manager_rpc)

    user_manager_local_rpc = user.UserManagerLocalRPC(object_store, session_handler)
    user_manager_rpc.putSubHandler('local', user_manager_local_rpc)

    user_manager_ldap_rpc = user.UserManagerLDAPRPC(object_store, session_handler)
    user_manager_rpc.putSubHandler('ldap', user_manager_ldap_rpc)

    user_manager_active_directory_rpc = user.UserManagerActiveDirectoryRPC(object_store, session_handler)
    user_manager_rpc.putSubHandler('activedirectory', user_manager_active_directory_rpc)
    user_manager_rpc.putSubHandler('ad', user_manager_active_directory_rpc)

    user_group_rpc = user.UserGroupRPC(object_store, session_handler)
    user_rpc.putSubHandler('group', user_group_rpc)

    user_group_ldap_rpc = user.UserGroupLDAPRPC(object_store, session_handler)
    user_group_rpc.putSubHandler('ldap', user_group_ldap_rpc)

    user_group_active_directory_rpc = user.UserGroupActiveDirectoryRPC(object_store, session_handler)
    user_group_rpc.putSubHandler('activedirectory', user_group_active_directory_rpc)
    user_group_rpc.putSubHandler('ad', user_group_active_directory_rpc)

    device_rpc = device.DeviceRPC(object_store, session_handler)
    siptrackd_rpc.putSubHandler('device', device_rpc)
    device_tree_rpc = device.DeviceTreeRPC(object_store, session_handler)
    device_rpc.putSubHandler('tree', device_tree_rpc)
    device_category_rpc = device.DeviceCategoryRPC(object_store, session_handler)
    device_rpc.putSubHandler('category', device_category_rpc)

    device_config_rpc = deviceconfig.DeviceConfigRPC(object_store, session_handler)
    device_rpc.putSubHandler('config', device_config_rpc)
    device_config_template_rpc = deviceconfig.DeviceConfigTemplateRPC(object_store, session_handler)
    device_config_rpc.putSubHandler('template', device_config_template_rpc)

    password_rpc = password.PasswordRPC(object_store, session_handler)
    siptrackd_rpc.putSubHandler('password', password_rpc)
    password_key_rpc = password.PasswordKeyRPC(object_store, session_handler)
    password_rpc.putSubHandler('key', password_key_rpc)
    password_tree_rpc = password.PasswordTreeRPC(object_store, session_handler)
    password_rpc.putSubHandler('tree', password_tree_rpc)
    password_category_rpc = password.PasswordCategoryRPC(object_store, session_handler)
    password_rpc.putSubHandler('category', password_category_rpc)
    sub_key_rpc = password.SubKeyRPC(object_store, session_handler)
    password_rpc.putSubHandler('subkey', sub_key_rpc)

    network_rpc = network.NetworkRPC(object_store, session_handler)
    siptrackd_rpc.putSubHandler('network', network_rpc)
    network_tree_rpc = network.NetworkTreeRPC(object_store, session_handler)
    network_rpc.putSubHandler('tree', network_tree_rpc)
    network_ipv4_rpc = network.NetworkIPV4RPC(object_store, session_handler)
    network_rpc.putSubHandler('ipv4', network_ipv4_rpc)
    network_range_rpc = network.NetworkRangeRPC(object_store, session_handler)
    network_rpc.putSubHandler('range', network_range_rpc)
    network_range_ipv4_rpc = network.NetworkRangeIPV4RPC(object_store, session_handler)
    network_range_rpc.putSubHandler('ipv4', network_range_ipv4_rpc)
    
    network_ipv6_rpc = network.NetworkIPV6RPC(object_store, session_handler)
    network_rpc.putSubHandler('ipv6', network_ipv6_rpc)
    network_range_ipv6_rpc = network.NetworkRangeIPV6RPC(object_store, session_handler)
    network_range_rpc.putSubHandler('ipv6', network_range_ipv6_rpc)

    container_rpc = container.ContainerRPC(object_store, session_handler)
    siptrackd_rpc.putSubHandler('container', container_rpc)
    container_tree_rpc = container.ContainerTreeRPC(object_store, session_handler)
    container_rpc.putSubHandler('tree', container_tree_rpc)

    attribute_rpc = attribute.AttributeRPC(object_store, session_handler)
    siptrackd_rpc.putSubHandler('attribute', attribute_rpc)

    versioned_attribute_rpc = attribute.VersionedAttributeRPC(object_store, session_handler)
    attribute_rpc.putSubHandler('versioned', versioned_attribute_rpc)

    encrypted_attribute_rpc = attribute.EncryptedAttributeRPC(
        object_store,
        session_handler
    )
    attribute_rpc.putSubHandler(
        'encrypted',
        encrypted_attribute_rpc
    )

    template_rpc = template.TemplateRPC(object_store, session_handler)
    siptrackd_rpc.putSubHandler('template', template_rpc)

    device_template_rpc = template.DeviceTemplateRPC(object_store,
            session_handler)
    template_rpc.putSubHandler('device', device_template_rpc)

    network_template_rpc = template.NetworkTemplateRPC(object_store,
            session_handler)
    template_rpc.putSubHandler('network', network_template_rpc)

    template_rule_rpc = template.TemplateRuleRPC(object_store, session_handler)
    template_rpc.putSubHandler('rule', template_rule_rpc)
 
    template_rule_password_rpc = template.TemplateRulePasswordRPC(object_store, session_handler)
    template_rule_rpc.putSubHandler('password', template_rule_password_rpc)
    template_rule_assign_network_rpc = template.TemplateRuleAssignNetworkRPC(object_store, session_handler)
    template_rule_rpc.putSubHandler('assign_network', template_rule_assign_network_rpc)
    template_rule_subdevice_rpc = template.TemplateRuleSubdeviceRPC(object_store, session_handler)
    template_rule_rpc.putSubHandler('subdevice', template_rule_subdevice_rpc)
    template_rule_text_rpc = template.TemplateRuleTextRPC(object_store, session_handler)
    template_rule_rpc.putSubHandler('text', template_rule_text_rpc)
    template_rule_fixed_rpc = template.TemplateRuleFixedRPC(object_store, session_handler)
    template_rule_rpc.putSubHandler('fixed', template_rule_fixed_rpc)
    template_rule_regmatch_rpc = template.TemplateRuleRegmatchRPC(object_store, session_handler)
    template_rule_rpc.putSubHandler('regmatch', template_rule_regmatch_rpc)
    template_rule_bool_rpc = template.TemplateRuleBoolRPC(object_store, session_handler)
    template_rule_rpc.putSubHandler('bool', template_rule_bool_rpc)
    template_rule_int_rpc = template.TemplateRuleIntRPC(object_store, session_handler)
    template_rule_rpc.putSubHandler('int', template_rule_int_rpc)
    template_rule_delete_attribute_rpc = template.TemplateRuleDeleteAttributeRPC(object_store, session_handler)
    template_rule_rpc.putSubHandler('delete_attribute', template_rule_delete_attribute_rpc)
    template_rule_flush_nodes_rpc = template.TemplateRuleFlushNodesRPC(object_store, session_handler)
    template_rule_rpc.putSubHandler('flush_nodes', template_rule_flush_nodes_rpc)
    template_rule_flush_associations_rpc = template.TemplateRuleFlushAssociationsRPC(object_store, session_handler)
    template_rule_rpc.putSubHandler('flush_associations', template_rule_flush_associations_rpc)

    config_rpc = config.ConfigRPC(object_store, session_handler)
    siptrackd_rpc.putSubHandler('config', config_rpc)
    config_network_autoassign_rpc = config.ConfigNetworkAutoassignRPC(object_store, session_handler)
    config_rpc.putSubHandler('network_autoassign', config_network_autoassign_rpc)
    config_value_rpc = config.ConfigValueRPC(object_store, session_handler)
    config_rpc.putSubHandler('value', config_value_rpc)

    simple_rpc = simple.SimpleRPC(object_store, session_handler)
    siptrackd_rpc.putSubHandler('simple', simple_rpc)

    permission_rpc = permission.PermissionRPC(object_store, session_handler)
    siptrackd_rpc.putSubHandler('permission', permission_rpc)

    command_rpc = event.CommandRPC(object_store, session_handler)
    siptrackd_rpc.putSubHandler('command', command_rpc)

    command_queue_rpc = event.CommandQueueRPC(object_store, session_handler)
    command_rpc.putSubHandler('queue', command_queue_rpc)

    event_rpc = event.EventRPC(object_store, session_handler)
    siptrackd_rpc.putSubHandler('event', event_rpc)

    event_trigger_rpc = event.EventTriggerRPC(object_store, session_handler)
    event_rpc.putSubHandler('trigger', event_trigger_rpc)

    event_trigger_rule_rpc = event.EventTriggerRuleRPC(object_store, session_handler)
    event_trigger_rpc.putSubHandler('rule', event_trigger_rule_rpc)

    event_trigger_rule_python_rpc = event.EventTriggerRulePythonRPC(object_store, session_handler)
    event_trigger_rule_rpc.putSubHandler('python', event_trigger_rule_python_rpc)

    event_log_rpc = eventlog.EventLogRPC(object_store, session_handler)
    event_rpc.putSubHandler('log', event_log_rpc)

    event_log_tree_rpc = eventlog.EventLogTreeRPC(object_store, session_handler)
    event_log_rpc.putSubHandler('tree', event_log_tree_rpc)

    root_service = service.MultiService()
    if listen_port:
        siptrackd_xmlrpc_service = internet.TCPServer(listen_port,
                server.Site(siptrackd_rpc))
        siptrackd_xmlrpc_service.setServiceParent(root_service)

    if ssl_port:
        ssl_context = SiptrackOpenSSLContextFactory(ssl_private_key,
                ssl_certificate)
        siptrackd_ssl_xmlrpc_service = internet.SSLServer(ssl_port,
                server.Site(siptrackd_rpc), ssl_context)
        siptrackd_ssl_xmlrpc_service.setServiceParent(root_service)

    application = service.Application('siptrackd')
    root_service.setServiceParent(application)

    reactor.callWhenRunning(siptrackd_twisted_init, object_store, application)

    if reload_interval:
        reactor.callLater(reload_interval, object_store_reloader, session_handler, object_store, reload_interval)

    reactor.run()
    log.msg('Shutting down siptrackd server.')

    return 0

def list_user_managers(storage):
    @defer.inlineCallbacks
    def run():
        print  'Creating object store, this might take a while.'
        object_store = siptrackdlib.ObjectStore(storage)
        yield object_store.init()
        for um in object_store.view_tree.listChildren(include = \
                ['user manager local', 'user manager ldap']):
            active = False
            if um is object_store.view_tree.user_manager:
                active = True
            s = 'name: %s, oid: %s, active: %s' % (
                    um.getAttributeValue('name', 'NONE'),
                    um.oid,
                    active)
            print s
        reactor.stop()
    reactor.callWhenRunning(run)
    reactor.run()

def reset_user_manager(storage):
    @defer.inlineCallbacks
    def run():
        print  'Creating object store, this might take a while.'
        object_store = siptrackdlib.ObjectStore(storage, preload=False)
        yield object_store.init()
        um = object_store.view_tree.add(None, 'user manager local')
        u = um.add(None, 'user local', 'admin', 'admin', True)
        object_store.view_tree.setActiveUserManager(um)
        yield object_store.commit([object_store.view_tree, um, u])
        print 'New user manager oid: %s' % (um.oid)
        reactor.stop()
    reactor.callWhenRunning(run)
    reactor.run()

def perform_upgrade(storage):
    @defer.inlineCallbacks
    def run():
        print'Running upgrade.'
        yield siptrackdlib.upgrade.perform_upgrade(storage)
        print 'Done.'
        reactor.stop()
    reactor.callWhenRunning(run)
    reactor.run()

def daemonize():
    if os.fork():
        os._exit(0)
    os.setsid()
    if os.fork():
        os._exit(0)
    null = os.open('/dev/null', os.O_RDWR)
    for i in range(3):
        try:
            os.dup2(null, i)
        except OSError, e:
            if e.errno != errno.EBADF:
                raise
    os.close(null)

def main(argv):
    config = RawConfigParser()
    parser = ArgumentParser()
    parser.add_argument(
        '-p',
        '--port',
        dest='listen_port',
        default=9242,
        help='port for cleartext connections, set to 0 for none (default 9242)'
    )
    parser.add_argument(
        '--ssl-port',
        dest='ssl_port',
        default=9243,
        help='port for ssl connections, set to 0 for none (default 9243)'
    )
    parser.add_argument(
        '-d',
        '--daemonize',
        dest='daemon',
        action='store_true',
        help='daemonize siptrackd'
    )
    parser.add_argument(
        '--ssl-private-key',
        dest='ssl_private_key',
        help='path to optional ssl private key file'
    )
    parser.add_argument(
        '--ssl-certificate',
        dest='ssl_certificate',
        help='path to optional ssl certificate (including cert chain)'
    )
    parser.add_argument(
        '-s', '--storage-options',
        type=FileType('r'),
        dest='storage_options',
        required=True,
        metavar='FILE',
        help='configuration file with storage options'
    )
    parser.add_argument(
        '-b',
        '--storage-backend',
        dest='storage_backend',
        required=True,
        help='storage backend to use'
    )
    parser.add_argument(
        '--list-storage-backends',
        dest='list_storage_backends',
        action='store_true',
        help='list available storage backends'
    )
    parser.add_argument(
        '--syslog',
        dest='log_syslog',
        action='store_true',
        help='log to syslog'
    )
    parser.add_argument(
        '-l',
        '--logfile',
        dest='log_file',
        help='log to a file, - for stdout'
    )
    parser.add_argument(
        '--list-user-managers',
        dest='list_user_managers',
        action='store_true',
        help='list existing user managers and exit'
    )
    parser.add_argument(
        '--reset-user-manager',
        dest='reset_user_manager',
        action='store_true',
        help='create a new local user manager and set it as active'
    )
    parser.add_argument(
        '--upgrade',
        dest='upgrade',
        action='store_true',
        help='upgrade siptrackd backend storage'
    )
    parser.add_argument(
        '--debug-logging',
        dest='debug_logging',
        action='store_true',
        help='turn on debug logging'
    )
    parser.add_argument(
        '--readonly',
        dest='readonly',
        action='store_true',
        help='readonly mode'
    )
    parser.add_argument(
        '--reload-interval',
        dest='reload_interval',
        help='Interval in which to reload the object store (s)'
    )
    parser.add_argument(
        '--searcher',
        dest='searcher',
        help='Searcher to use, one of: memory, whoosh, default: memory.'
    )
    parser.add_argument(
        '--searcher-args',
        dest='searcher_args',
        help='Searcher arguments, (whoosh index path).'
    )
    args = parser.parse_args()

    if args.list_storage_backends:
        for backend in siptrackdlib.storage.list_backends():
            print backend
        return 0

    if not args.listen_port:
        args.listen_port = DEFAULT_LISTEN_PORT
    elif args.listen_port == '0':
        args.listen_port = None
    else:
        try:
            args.listen_port = int(args.listen_port)
        except:
            print 'ERROR: invalid listen port'
            parser.print_help()
            return 1

    if not args.ssl_port:
        args.ssl_port = DEFAULT_SSL_LISTEN_PORT
    elif args.ssl_port == '0':
        args.ssl_port = None
    else:
        try:
            args.ssl_port = int(args.ssl_port)
        except:
            print 'ERROR: invalid ssl port'
            parser.print_help()
            return 1

    if not ssl:
        print 'ERROR: SSL command line options present but ssl can\'t be imported'
        print 'Is PyOpenSSL missing?'
        return 1

    if not args.ssl_private_key or \
            not os.path.isfile(args.ssl_private_key):
        args.ssl_port = None
    if not args.ssl_certificate or \
            not os.path.isfile(args.ssl_certificate):
        args.ssl_port = None

    if args.reload_interval:
        try:
            args.reload_interval = int(args.reload_interval)
        except Exception, e:
            print 'Invalid value for reload_interval: %s' % (args.reload_interval)
            return 1

    storage_kwargs = {}
    storage_kwargs = {'readonly': args.readonly}
    storage_config = RawConfigParser()
    storage_config.readfp(args.storage_options)
    try:
        storage = siptrackdlib.storage.load(
            args.storage_backend,
            storage_config,
            **storage_kwargs
        )
    except siptrackdlib.errors.StorageError, e:
        print 'ERROR:', e
        parser.print_help()
        return 1

    if args.list_user_managers:
        list_user_managers(storage)
        return 0
    if args.reset_user_manager:
        reset_user_manager(storage)
        return 0
    if args.upgrade:
        perform_upgrade(storage)
        return 0

    try:
        log.logger.setup(
            args.daemon,
            args.log_syslog,
            args.log_file,
            args.debug_logging
        )
    except Exception as e:
        print str(e)
        parser.print_help()
        sys.exit(1)

    siptrackdlib.log.set_logger(log.logger)

    if args.searcher:
        if args.searcher_args:
            searcher_args = args.searcher_args.split()
        else:
            searcher_args = []
        searcher = siptrackdlib.search.get_searcher(args.searcher, *searcher_args)
    else:
        searcher = siptrackdlib.search.get_searcher('memory')

    if args.daemon:
        daemonize()

    try:
        return run_siptrackd_twisted(args.listen_port, args.ssl_port,
                args.ssl_private_key, args.ssl_certificate, storage, args.reload_interval,
                searcher)
    except siptrackdlib.errors.SiptrackError, e:
        print 'ERROR:', e

