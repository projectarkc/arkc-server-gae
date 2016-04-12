import cgi
import urllib
import hashlib

from google.appengine.api import users, urlfetch, memcache
from google.appengine.ext import ndb

import webapp2

Form_FOOTER_TEMPLATE = """\
    <form action="/clientregister" method="post">
      This form adds client records.<br>
      <br>
      Client private SHA1:  <input type="text" name="clientprisha1"><br>
      Client public key:<br>
      <textarea cols="60" rows="10" name="clientpub"></textarea>
      <div><input type="submit" value="Add client record"></div>
    </form>
    <hr>
    <form action="/serverregister" method="post">
      This form updates the server record.<br>
      <br>
      Server Private key:<br>
      <textarea cols="60" rows="20" name="private"></textarea><br>
      Server Public key:<br>
      <textarea cols="60" rows="10" name="public"></textarea><br>
      Upload Key: <input type="text" name="key"><br>
      <div><input type="submit" value="Update"></div><br>
    </form>
    <hr>
    ArkC GAE Under development version.
  </body>
</html>
"""

upload_key = "FREEDOM"

class Client(ndb.Model):
    """A main model for representing an individual Guestbook entry."""
    Clientprisha1 = ndb.StringProperty(indexed=False)
    Clientpub = ndb.StringProperty(indexed=False)
    Clientsha1 = ndb.StringProperty()

class Server(ndb.Model):
    """A main model for representing an individual Guestbook entry."""
    Public = ndb.StringProperty(indexed=False)
    Private = ndb.StringProperty(indexed=False)

class ClientForm(webapp2.RequestHandler):

    def get(self):
        self.response.write('<html><body>')
        self.response.write(Form_FOOTER_TEMPLATE)


class ShowResult(webapp2.RequestHandler):

    def get(self):
        #userrecord_query = User.query(
        #ancestor=ndb.Key('client', 'client')
        #userrecords = userrecord_query.fetch(1)
        
        resp = '''<html><body>
      ALL DONE.
  </body>
</html>'''
        self.response.write(resp)


class ClientRegister(webapp2.RequestHandler):

    def post(self):
        # We set the same parent key on the 'Greeting' to ensure each
        # Greeting is in the same entity group. Queries across the
        # single entity group will be consistent. However, the write
        # rate to a single entity group should be limited to
        # ~1/second.
        userrecord = Client(parent=ndb.Key('Client', "Client"))
        userrecord.Clientprisha1 = self.request.get('clientprisha1').strip() + '\n'
        userrecord.Clientpub = self.request.get('clientpub').strip() + '\n'
        print(repr(userrecord.Clientpub))
        h = hashlib.sha1()
        h.update(userrecord.Clientpub)
        userrecord.Clientsha1 = h.hexdigest()
        userrecord.put()
        self.redirect('/result')


class ServerRegister(webapp2.RequestHandler):

    def post(self):
        # We set the same parent key on the 'Greeting' to ensure each
        # Greeting is in the same entity group. Queries across the
        # single entity group will be consistent. However, the write
        # rate to a single entity group should be limited to
        # ~1/second.
        userrecord = Server(parent=ndb.Key('Server', 'Server'))
        userrecord.Public = self.request.get('public').strip() + '\n'
        userrecord.Private = self.request.get('private').strip() + '\n'
        if self.request.get('key').strip()==upload_key:
            memcache.set(key="serverpri", value=userrecord.Private)
            q = Server.query(ancestor=ndb.Key('Server', 'Server'))
            for rec in q.iter(keys_only=True):
                rec.delete(use_datastore=True)
            userrecord.put()
            self.redirect('/result')

        

app = webapp2.WSGIApplication([
    ('/', ClientForm),
    ('/result', ShowResult),
    ('/clientregister', ClientRegister),
    ('/serverregister', ServerRegister)
])
