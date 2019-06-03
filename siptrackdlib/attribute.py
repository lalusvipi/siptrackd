import re

from Crypto.Cipher import AES

from siptrackdlib.objectregistry import object_registry
from siptrackdlib import treenodes
from siptrackdlib import errors
from siptrackdlib import storagevalue

from siptrackdlib import log

class AttributeBase(treenodes.BaseNode):
    def regmatch(self, re_pattern, name = None):
        """See if the attributes value matches a regexp.

        If the passed in re_pattern isn't a string assume it's a precompiled
        regexp.
        """
        if name and name != self.name:
            return None
        if type(re_pattern) in [str, unicode]:
            re_compiled = re.compile(re_pattern, re.IGNORECASE)
        else:
            re_compiled = re_pattern
        value = self.value
        if self.atype in ['int', 'bool']:
            value = str(value)
        return re_compiled.search(value)

    def buildSearchValues(self):
        name = self.name
        if type(name) == unicode:
            name  = name.encode('utf-8')
        name = name.lower().replace(' ', '_').replace('/', '_')
        values = {}
        if self.atype == 'binary':
            values = {}
        elif self.atype == 'text':
            value = self.value
            if type(value) == str:
                try:
                    value = value.decode('utf-8').lower()
                except:
                    value = u''
            values = {name: value}
        else:
            values = {name: unicode(self.value)}
        return values

class Attribute(AttributeBase):
    """A single attribute.

    Attributes are used by pretty much every other object type.
    They are used to store varying types of data.
    Arguments:
        name  : the attribute name.
        atype : the attribute type, one of:
            text   : a unicode string.
            binary : a string of binary data (no encoding/decoding performed)
            int    : an integer
            bool   : True/False
        value : a value matching the attributes type.
    """
    class_id = 'CA'
    class_name = 'attribute'

    def __init__(self, oid, branch, name = None, atype = None, value = None):
        super(Attribute, self).__init__(oid, branch)
        self._name = name
        self._atype = atype
        self._value = value

    def getParentNode(self):
        """Get the closest parent _non-attribute_ node."""
        parent = self
        while parent.class_id in ['CA', 'VA']:
            parent = parent.parent
        return parent

    def _created(self, user):
        super(Attribute, self)._created(user)
        self.name = self._name
        self.atype = self._atype
        self.value = self._value

    def _loaded(self, data = None):
        super(Attribute, self)._loaded(data)
        if data:
            self._name = data['attr-name']
            self._atype = data['attr-type']
            self._value = data['attr-value']
            if self.atype == 'bool':
                if self._value == 0:
                    self._value = False
                else:
                    self._value = True

    def _remove(self, *args, **kwargs):
        oid = self.oid
        parent = self.parent
        super(Attribute, self)._remove(*args, **kwargs)
        self.searcherAction('remove_attr', {'parent': parent})

    def _get_name(self):
        if not self._name:
            raise errors.MissingData('missing attribute name: %s' % (self.oid))
        return self._name

    def _set_name(self, val):
        self._name = val
        self.storageAction('write_data', {'name': 'attr-name', 'value': self._name})
        self.setModified()
    name = property(_get_name, _set_name)

    def _get_value(self):
        if self._value is None:
            raise errors.MissingData('missing attribute value')
        return self._value

    def _set_value(self, val):
        if self._atype == 'text':
            if type(val) not in [unicode, str]:
                raise errors.SiptrackError('attribute value doesn\'t match type')
            self.storageAction('write_data', {'name': 'attr-value', 'value': val})
        elif self._atype == 'binary':
            if type(val) != str:
                raise errors.SiptrackError('attribute value doesn\'t match type')
            self.storageAction('write_data', {'name': 'attr-value', 'value': val})
        elif self._atype == 'int':
            if type(val) != int:
                raise errors.SiptrackError('attribute value doesn\'t match type')
            self.storageAction('write_data', {'name': 'attr-value', 'value': val})
        elif self._atype == 'bool':
            if val is True:
                self.storageAction('write_data', {'name': 'attr-value', 'value': 1})
            elif val is False:
                self.storageAction('write_data', {'name': 'attr-value', 'value': 0})
            else:
                raise errors.SiptrackError('attribute value doesn\'t match type')
        else:
            raise errors.SiptrackError('trying to set attribute value with invalid atype "%s"' % (self._atype))
        self._value = val
        self.searcherAction('set_attr', {'parent': self.parent})
        self.object_store.triggerEvent('node update', self)
        self.setModified()
    value = property(_get_value, _set_value)

    def _get_atype(self):
        if not self._atype:
            raise errors.MissingData('missing attribute value')
        return self._atype

    def _set_atype(self, val):
        self._atype = val
        self.storageAction('write_data', {'name': 'attr-type', 'value': self._atype})
        self.setModified()
    atype = property(_get_atype, _set_atype)

class VersionedAttribute(AttributeBase):
    """A single attribute.

    Attributes are used by pretty much every other object type.
    They are used to store varying types of data.
    Arguments:
        name  : the attribute name.
        atype : the attribute type, one of:
            text   : a unicode string.
            binary : a string of binary data (no encoding/decoding performed)
            int    : an integer
            bool   : True/False
        value : a value matching the attributes type.
    """
    class_id = 'VA'
    class_name = 'versioned attribute'

    def __init__(self, oid, branch, name = None, atype = None,
            value = None, max_versions = None):
        super(VersionedAttribute, self).__init__(oid, branch)
        self._name = storagevalue.StorageText(self, 'attr-name', name)
        self._atype = storagevalue.StorageText(self, 'attr-type', atype,
                self._atype_validator)
        values = []
        if value is not None:
            values = [value]
        self._values = storagevalue.StorageValue(self, 'attr-values', values,
                self._values_validator)
        self._max_versions = storagevalue.StorageNum(self, 'attr-max-versions',
                max_versions, self._max_versions_validator)

    def _atype_validator(self, value):
        if value not in ['text', 'binary', 'int', 'bool']:
            raise errors.SiptrackError('invalid type value for VersionedAttribute')

    def _values_validator(self, values):
        if type(values) != list:
            raise errors.SiptrackError('invalid value for VersionedAttribute')
        error = False
        for value in values:
            if not self._isValidValue(value):
                raise errors.SiptrackError('invalid value for VersionedAttribute')

    def _isValidValue(self, value):
        if self.atype == 'text':
            if type(value) not in [str, unicode]:
                return False
        if self.atype == 'binary':
            if type(value) not in [str]:
                return False
        if self.atype == 'int':
            if type(value) not in [int, long]:
                return False
        if self.atype == 'bool':
            if type(value) not in [bool]:
                return False
        return True

    def _max_versions_validator(self, value):
        if type(value) not in [int, long] or value < 1:
            raise errors.SiptrackError('invalid max versions value for VersionedAttribute')

    def getParentNode(self):
        """Get the closest parent _non-attribute_ node."""
        parent = self
        while parent.class_id in ['VA', 'CA']:
            parent = parent.parent
        return parent

    def _created(self, user):
        super(VersionedAttribute, self)._created(user)
        self._name.commit()
        self._atype.commit()
        self._values.commit()
        self._max_versions.commit()
        self.searcherAction('set_attr', {'parent': self.parent})

    def _loaded(self, data = None):
        super(VersionedAttribute, self)._loaded(data)
        self._name.preload(data)
        self._atype.preload(data)
        self._values.preload(data)
        self._max_versions.preload(data)

    def _remove(self, *args, **kwargs):
        oid = self.oid
        parent = self.parent
        super(VersionedAttribute, self)._remove(*args, **kwargs)
        self.searcherAction('remove_attr', {'parent': parent})

    def _get_name(self):
        return self._name.get()
    def _set_name(self, val):
        self._name.set(val)
        self.setModified()
    name = property(_get_name, _set_name)

    def _get_value(self):
        if self.values == []:
            return None
        else:
            return self.values[-1]
    def _set_value(self, val):
        if not self._isValidValue(val):
            raise errors.SiptrackError('invalid value for VersionedAttribute')
        values = self.values
        values.append(val)
        if len(values) > self.max_versions:
            values.pop(0)
        self.values = values
        self.searcherAction('set_attr', {'parent': self.parent})
        self.object_store.triggerEvent('node update', self)
        self.setModified()
    value = property(_get_value, _set_value)

    def _get_values(self):
        return self._values.get()
    def _set_values(self, val):
        self._values.set(val)
        self.setModified()
    values = property(_get_values, _set_values)

    def _pruneValues():
        """Prune the number of stored values.
        This makes sure we never store more than max_values.
        Used after max_versions has been set.
        """
        values = self.values
        if len(values) > self.max_versions:
            while len(values) > self.max_versions:
                values.pop(0)
            self.values = values

    def _get_max_versions(self):
        return self._max_versions.get()
    def _set_max_versions(self, val):
        self._max_versions.set(val)
        self._pruneValues()
    max_versions = property(_get_max_versions, _set_max_versions)

    def _get_atype(self):
        return self._atype.get()
    def _set_atype(self, val):
        self._atype.set(val)
        self.setModified()
    atype = property(_get_atype, _set_atype)


class EncryptedAttribute(AttributeBase):
    """
    Encrypted Attributes must be children of password nodes to have access
    to a password key through their parent password node.

    As of writing only atype=text is supported.
    """

    class_id = 'ENCA'
    class_name = 'encrypted attribute'

    def __init__(self, oid, branch, name = None, atype = None, value = None):
        super(EncryptedAttribute, self).__init__(oid, branch)
        parent = self.getParentNode()
        self._pk = parent.password_key
        self._name = name
        self._atype = atype
        self._value = value
        self._lock_data = storagevalue.StorageValue(self, 'enca-lockdata')


    def _created(self, user):
        super(EncryptedAttribute, self)._created(user)
        self.user = user
        self.name = self._name
        self.atype = self._atype
        self.value = self._value


    def _loaded(self, data = None):
        super(EncryptedAttribute, self)._loaded(data)
        if data:
            self._name = data['attr-name']
            self._atype = data['attr-type']
            self._value = data['attr-value']
        self._lock_data.preload(data)


    def _remove(self, *args, **kwargs):
        oid = self.oid
        parent = self.parent
        super(EncryptedAttribute, self)._remove(*args, **kwargs)
        self.searcherAction('remove_attr', {'parent': parent})


    # Override buildSearchValues to avoid exposing encrypted data
    # to search indexer.
    def buildSearchValues(self):
        name = self.name
        if type(name) == unicode:
            name  = name.encode('utf-8')
        name = name.lower().replace(' ', '_').replace('/', '_')
        values = {}
        if self.atype == 'text':
            values = {name: u''}
        return values


    def getParentNode(self):
        """Get the closest parent _non-attribute_ node."""
        parent = self
        while parent.class_id in ['VA', 'CA', 'ENCA']:
            parent = parent.parent
        return parent

    def getAttribute(self, user):
        parent = self.getParentNode()
        self._pk = parent.password_key

        if self._value is None:
            raise errors.MissingData('missing attribute value')

        if not self._pk.canEncryptDecrypt(None, user):
            raise errors.SiptrackError('Unable to access password key')

        self.user = user

        dec_value = self._pk.decrypt(
            self._value,
            self.lock_data,
            None,
            self.user
        )

        return dec_value


    def setAttribute(self, user, val):
        parent = self.getParentNode()
        self._pk = parent.password_key

        if self._atype != 'text':
            raise errors.SiptrackError('invalid atype: "{atype"}'.format(
                atype=self._atype
            ))
        if not isinstance(val, (unicode, str)):
            raise errors.SiptrackError(
                'attribute value must be unicode or str'
            )

        if isinstance(val, unicode):
            val = val.encode('utf-8')

        if not self._pk.canEncryptDecrypt(None, user):
            raise errors.SiptrackError('Unable to access password key')
        self.user = user

        enc_val, self.lock_data = self._pk.encrypt(val, None, self.user)

        self.storageAction(
            'write_data',
            {'name': 'attr-value', 'value': enc_val}
        )

        self._value = enc_val
        self.object_store.triggerEvent('node update', self)
        self.setModified()


    @property
    def name(self):
        if not self._name:
            raise errors.MissingData('missing attribute name: %s' % (self.oid))
        return self._name

    @name.setter
    def name(self, val):
        self._name = val
        self.storageAction('write_data', {'name': 'attr-name', 'value': self._name})
        self.setModified()


    @property
    def value(self):
        if self.user is None:
            raise errors.SiptrackError('User not available')
        return self.getAttribute(self.user)

    @value.setter
    def value(self, val):
        if self.user is None:
            raise errors.SiptrackError('User not available')

        self.setAttribute(self.user, val)


    @property
    def atype(self):
        if not self._atype:
            raise errors.MissingData('missing attribute value')
        return self._atype

    @atype.setter
    def atype(self, val):
        self._atype = val
        self.storageAction(
            'write_data',
            {'name': 'attr-type', 'value': self._atype}
        )


    @property
    def lock_data(self):
        return self._lock_data.get()

    @lock_data.setter
    def lock_data(self, val):
        self._lock_data.set(val)


# Add the objects in this module to the object registry.
o = object_registry.registerClass(Attribute)
o.registerChild(Attribute)
o.registerChild(VersionedAttribute)

o = object_registry.registerClass(VersionedAttribute)
o.registerChild(Attribute)
o.registerChild(VersionedAttribute)

o = object_registry.registerClass(EncryptedAttribute)
o.registerChild(EncryptedAttribute)
o.registerChild(Attribute)
o.registerChild(VersionedAttribute)
