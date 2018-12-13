#!/usr/bin/env python
################################
# models.py
#
# Version: 0.0.0.1
# Date: 2018-12-03
# Authors: Sophian Mehboub
################################
import requests
import json
import platform
from datetime import datetime
from utils import downloadCertificates, CertificateUtils, write, getInfoFqdn, getMacAddr

class EmptyException(Exception):
        pass

class LoginException(Exception):
        pass

class KatelloBase(object):
    api = '/katello/api'
    headers = {'Content-type': 'application/json', 'Accept': 'application/json'}
    search_field = 'name'
    def list(self):
        org_id_param = ''
        if hasattr(self,'organization_id'):
            org_id_param = '?organization_id=%s' % self.organization_id
        resp = requests.get('https://%s%s/%s%s' % (self.fqdn, self.api, self.__class__.__name__, org_id_param), headers=self.headers, auth=requests.auth.HTTPBasicAuth(self.username, self.password), verify=self.cacert)
        if resp.status_code == 401:
            raise LoginException("The username or password doesn't match")
        lst = resp.json()
        return lst
    def getByName(self,name):
        lst = self.list()
        try:
            obj = list(filter(lambda x: x[self.search_field] == name, lst['results']))[0]
        except IndexError:
            obj = {}
        return obj
    def getFullById(self,id):
        lst = self.list()
        try:
            resp = requests.get('https://%s%s/%s/%s' % (self.fqdn, self.api, self.__class__.__name__, id), headers=self.headers, auth=requests.auth.HTTPBasicAuth(self.username, self.password), verify=self.cacert)
            if resp.status_code == 401:
                raise LoginException("The username or password doesn't match")
            obj = resp.json()
        except IndexError:
            obj = {}
        return obj
    def getFullByName(self,name):
        lst = self.list()
        try:
            result = list(filter(lambda x: x[self.search_field] == name, lst['results']))[0]
            id = result['id']
            obj = self.getFullById(id)
        except IndexError:
            obj = {}
        return obj
    def create(self, data, get_obj=True):
        resp = requests.post('https://%s%s/%s' % (self.fqdn, self.api, self.__class__.__name__), data=json.dumps(data), headers=self.headers, auth=requests.auth.HTTPBasicAuth(self.username, self.password), verify=self.cacert)
        if resp.status_code == 401:
            raise LoginException("The username or password doesn't match")
        if get_obj == True:
            if self.search_field in data:
                search_field = data[self.search_field]
            else:
                o = self.__class__.__name__.rstrip('s')
                search_field = data[o][self.search_field]
            obj = self.getByName(search_field)
            if len(obj) == 0:
                raise EmptyException("The %s %s is not created, the post http request to foreman api failed" % (self.__class__.__name__, search_field))
            return obj


class organizations(KatelloBase):
    def __init__(self):
        pass
    def getCerts(self):
        url_certs = 'https://%s%s/%s/%s/download_debug_certificate' % (self.fqdn, self.api, self.__class__.__name__,  self.org)
        certs = downloadCertificates(url=url_certs, username=self.username, password=self.password, cacert=self.cacert)
        self.cert_utils = CertificateUtils(certs)
    def writeCert(self, path):
        write(path, self.cert_utils.getCert())
    def writeKey(self, path):
        write(path, self.cert_utils.getKey())

class gpg_keys(KatelloBase):
    def __init__(self):
        pass

class activation_keys(KatelloBase):
    def __init__(self):
        pass

class content_views(KatelloBase):
    def __init__(self):
        pass

class repositories(KatelloBase):
    def __init__(self):
        pass

class products(KatelloBase):
    def __init__(self):
        pass

class locations(KatelloBase):
    api = '/api'
    def __init__(self):
        pass
    def create(self):
        data = { "name": self.name,
                 "title": self.name
               }
        return super(locations, self).create(data)


class architectures(KatelloBase):
    api = '/api'
    def __init__(self):
        pass
    def create(self):
        data = { "name": platform.machine() }
        return super(architectures, self).create(data)

class domains(KatelloBase):
    api = '/api'
    def __init__(self):
        pass
    def create(self):
        domain = getInfoFqdn(platform.node())
        data = { "name": domain['domain'],
                 "fullname": domain['domain'],
                 "location_id": self.location_id,
                 "organizations": [ {"id": self.organization_id } ]
               }
        return super(domains, self).create(data)

class operatingsystems(KatelloBase):
    api = '/api'
    search_field = 'title'
    def __init__(self):
        pass
    def create(self):
        dist = platform.linux_distribution()
        now = datetime.utcnow().strftime("%Y-%m-%d %X UTC")
        data = { 'major' : dist[1].split('.')[0],
                 'minor' :  dist[1].split('.')[1],
                 'family' : dist[0].title(),
                 'release_name' : None,
                 'password_hash' : 'SHA256',
                 'created_at' : now,
                 'updated_at' : now,
                 'name' : dist[0].title(),
                 'title' : ' '.join(filter(None, dist)).title(),
                 'architectures' : [ {'name' : platform.machine()} ]
               }
        return super(operatingsystems, self).create(data)

class hosts(KatelloBase):
    api = '/api'
    add_subscriptions = '/subscriptions/add_subscriptions'
    def __init__(self):
        pass
    def create(self):
        data = { "host" : {
                    "operatingsystem_id": self.operatingsystem_id,
                    "mac": getMacAddr(),
                    "name": platform.node(),
                    "organization_id": self.organization_id,
                    "architecture_id": self.architecture_id,
                    "domain_id": self.domain_id,
                    "location_id": self.location_id
                   }
               }
        if hasattr(self, 'lifecycle_environment_id'):
            data['host']['lifecycle_environment_id'] = self.lifecycle_environment_id
        if hasattr(self, 'content_view_id'):
            data['host']['content_view_id'] = self.content_view_id
        return super(hosts, self).create(data)


class subscriptions(KatelloBase):
    host_subscription = '/api/hosts'
    add = 'add_subscriptions'
    def __init__(self):
        pass
    def create(self):
        self.api = self.host_subscription
        data = { "name": platform.node(),
                 "lifecycle_environment_id" : self.lifecycle_environment_id,
                 "content_view_id" : self.content_view_id
               }
        obj = super(subscriptions, self).create(data, get_obj=False)
        self.api = KatelloBase.api
        return obj
    def add_subscriptions(self):
        data = { "subscriptions" :
                    self.products_ids
               }
        resp = requests.put('https://%s%s/%s/%s/%s' % (self.fqdn, self.host_subscription, self.host_id, self.__class__.__name__, self.add), data=json.dumps(data), headers=self.headers, auth=requests.auth.HTTPBasicAuth(self.username, self.password), verify=self.cacert)
        if resp.status_code == 401:
            raise LoginException("The username or password doesn't match")
