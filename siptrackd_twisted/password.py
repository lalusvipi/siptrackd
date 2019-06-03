from twisted.web import xmlrpc
from twisted.internet import defer
import xmlrpclib

from siptrackdlib import password

from siptrackd_twisted import helpers
from siptrackd_twisted import gatherer
from siptrackd_twisted import baserpc
from siptrackd_twisted import errors

class PasswordTreeRPC(baserpc.BaseRPC):
    node_type = 'password tree'

    @helpers.ValidateSession()
    @defer.inlineCallbacks
    def xmlrpc_add(self, session, parent_oid):
        """Create a new password tree."""
        parent = self.object_store.getOID(parent_oid, user = session.user)
        obj = parent.add(session.user, 'password tree')
        yield obj.commit()
        defer.returnValue(obj.oid)

class PasswordCategoryRPC(baserpc.BaseRPC):
    node_type = 'password category'

    @helpers.ValidateSession()
    @defer.inlineCallbacks
    def xmlrpc_add(self, session, parent_oid):
        """Create a new password category."""
        parent = self.object_store.getOID(parent_oid, user = session.user)
        obj = parent.add(session.user, 'password category')
        yield obj.commit()
        defer.returnValue(obj.oid)

class PasswordRPC(baserpc.BaseRPC):
    node_type = 'password'

    @helpers.ValidateSession()
    @defer.inlineCallbacks
    def xmlrpc_add(self, session, parent_oid, password, key_oid = ''):
        """Create a new password."""
        parent = self.object_store.getOID(parent_oid, user = session.user)
        if len(key_oid) == 0:
            key = None
        else:
            key = self.object_store.getOID(key_oid, user = session.user)
        passwd = parent.add(session.user, 'password', password, key)
        yield passwd.commit()
        defer.returnValue(passwd.oid)

    @helpers.ValidateSession()
    @defer.inlineCallbacks
    def xmlrpc_set_password(self, session, oid, new_password):
        """Change a Passwords password."""
        password = self.getOID(session, oid)
        password.setPassword(session.user, new_password)
        yield password.commit()
        cls_name = password.class_name
        parent_cls_name = password.parent.class_name
        if cls_name == 'password' and parent_cls_name == 'device':
            data = {'device_user': password.getAttributeValue('username', '')}
            password.parent.addEventLog(
                'device password updated',
                data,
                session.user,
                affects=password.parent
            )
        defer.returnValue(True)

    @helpers.ValidateSession()
    @defer.inlineCallbacks
    def xmlrpc_set_password_key(self, session, oid, new_password_key_oid):
        """Change a Passwords password key."""
        password = self.getOID(session, oid)
        event_data = {}

        if password.password_key:
            old_key_name = password.password_key.getAttributeValue('name', '')
            event_data.update({'old_password_key_name': old_key_name})
        else:
            event_data.update({'old_password_key_name': 'None'})

        new_password_key = None

        if new_password_key_oid:
            new_password_key = self.object_store.getOID(
                new_password_key_oid,
                'password key',
                session.user
            )

        password.setPasswordKey(session.user, new_password_key)
        yield password.commit()

        cls_name = password.class_name
        parent_cls_name = password.parent.class_name
        if cls_name == 'password' and parent_cls_name == 'device':
            event_data.update(
                {'device_user': password.getAttributeValue('username', '')}
            )

            old_key_name = event_data.get('old_password_key_name')
            if old_key_name is not None and password.password_key:
                new_key_name = password.password_key.getAttributeValue(
                    'name', ''
                )
                event_data.update(
                    {'new_password_key_name': new_key_name}
                )
            elif not password.password_key:
                event_data.update({'new_password_key_name': 'None'})

        password.parent.addEventLog(
            'password key updated',
            event_data,
            session.user,
            affects=password.parent
        )
        defer.returnValue(True)

class PasswordKeyRPC(baserpc.BaseRPC):
    node_type = 'password key'

    @helpers.ValidateSession()
    @defer.inlineCallbacks
    def xmlrpc_add(self, session, parent_oid, key):
        """Create a new password key."""
        parent = self.object_store.getOID(parent_oid, user = session.user)
        pk = parent.add(session.user, 'password key', key)
        yield pk.commit()
        defer.returnValue(pk.oid)

    @helpers.ValidateSession()
    @defer.inlineCallbacks
    def xmlrpc_change_key(self, session, oid, new_key):
        """Change a password keys key."""
        pk = self.getOID(session, oid)
        pk.changeKey(new_key)
        yield pk.commit()
        defer.returnValue(True)

    @helpers.ValidateSession()
    def xmlrpc_is_valid_password(self, session, pk_oid, test_password):
        """Check if a password is valid for this password key"""
        pk = self.getOID(session, pk_oid)
        ret_value = pk.isValidPassword(test_password)
        if ret_value != True:
            raise errors.SiptrackError('Incorrect password')
        return ret_value


class SubKeyRPC(baserpc.BaseRPC):
    node_type = 'subkey'

    @helpers.ValidateSession()
    @defer.inlineCallbacks
    def xmlrpc_delete(self, session, oid):
        """Delete a subkey."""
        subkey = self.object_store.getOID(oid, 'subkey', user = session.user)
        if session.user.user.administrator != True and \
                session.user.user.oid != subkey.parent.oid:
            raise errors.PermissionDenied()
        yield self.object_store.commit(self.object_store.getOID(oid, user = session.user).delete(recursive = True))
        defer.returnValue(True)

def password_data_extractor(node, user):
    password_key = ''
    if node.password_key:
        password_key = node.password_key.oid
    password = node.getPassword(None, user)
#    if not node.unicode:
#        password = xmlrpclib.Binary(password)
    return [password, password_key]

def sub_key_data_extractor(node, user):
    if node.password_key:
        oid = node.password_key.oid
    else:
        oid = ''
    return [oid]

gatherer.node_data_registry.register(password.PasswordTree,
        gatherer.no_data_extractor)
gatherer.node_data_registry.register(password.PasswordCategory,
        gatherer.no_data_extractor)
gatherer.node_data_registry.register(password.Password,
        password_data_extractor)
gatherer.node_data_registry.register(password.PasswordKey,
        gatherer.no_data_extractor)
gatherer.node_data_registry.register(password.PublicKey,
        gatherer.no_data_extractor)
gatherer.node_data_registry.register(password.SubKey,
        sub_key_data_extractor)
gatherer.node_data_registry.register(password.PendingSubKey,
        gatherer.no_data_extractor)
