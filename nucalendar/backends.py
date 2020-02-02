from django.contrib.auth.backends import BaseBackend
from django.contrib.auth.models import User
import ldap
import re
import os

class NULDAPBackend(BaseBackend):
  def authenticate(self, request, username=None, password=None):
    print(os.environ)

    con = ldap.initialize(os.environ.get('NU_LDAP_URL'))

    try:
      con.simple_bind_s(os.environ.get('NU_LDAP_BCN'),os.environ.get('NU_LDAP_PWD'))
    except ldap.LDAPError:
      return

    res = con.search_s(os.environ.get('NU_LDAP_BDN'),ldap.SCOPE_SUBTREE,'uid=' + username)
    if not res:
      return

    print(res)
    dn = res[0][0]
    try:
      con.simple_bind_s(dn, password)
    except ldap.LDAPError:
      return

    try:
      return User.objects.get(username=username)
    except User.DoesNotExist:
      f = open('/etc/passwd', 'r')
      passwd = f.read()
      users = re.findall("(?:^|\n)(.*?):", passwd)
      if username in users:
        user = User(username=username)
        user.is_staff = True
        user.is_superuser = True
        user.first_name = str(res[0][1]['givenName'][0], 'utf-8')
        user.last_name = str(res[0][1]['sn'][0], 'utf-8')
        user.email = str(res[0][1]['mail'][0], 'utf-8')
        user.save()
        return user
      return

  def get_user(self, user_id):
    try:
      return User.objects.get(pk=user_id)
    except User.DoesNotExist:
      return
