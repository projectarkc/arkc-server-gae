import cgi
import urllib
import hashlib

from google.appengine.api import users, urlfetch
from google.appengine.ext import ndb

import webapp2

Form_FOOTER_TEMPLATE = """\
    <form action="/clientregister" method="post">
      This form creates adds client records.<br>
      <br>
      Client private SHA1:  <input type="text" name="clientprisha1"><br>
      Client public key  <input type="text" name="clientpub"><br>
      <div><input type="submit" value="Register for ArkC"></div>
    </form>
    <hr>
    ArkC GAE Under development version.
  </body>
</html>
"""

class Client(ndb.Model):
    """A main model for representing an individual Guestbook entry."""
    Clientprisha1 = ndb.StringProperty(indexed=False)
    #password = ndb.StringProperty(indexed = False)
    #number = ndb.StringProperty(indexed=False)
    Clientpub = ndb.StringProperty(indexed=False)
    Clientsha1 = ndb.StringProperty()


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
        userrecord = Client(parent=ndb.Key('client', "client"))
        userrecord.Clientprisha1 = str(self.request.get('clientprisha1').strip())
        userrecord.Clientpub = str(self.request.get('clientpub').strip())
        h = hashlib.sha1()
        h.update(userrecord.Clientpub)
        userrecord.Clientsha1 = h.hexdigest()
        userrecord.put()
        self.redirect('/result')
        

app = webapp2.WSGIApplication([
    ('/', ClientForm),
    ('/result', ShowResult),
    ('/clientregister', ClientRegister),
])
