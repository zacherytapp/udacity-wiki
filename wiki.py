import re
import os
import random
import hashlib
import hmac
import time
import logging
import random
import urllib2
from string import letters

import jinja2
import webapp2


from google.appengine.ext import db
from google.appengine.api import memcache

SECRET = 'fart'
PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'

# Jinja2 boilerplate code - declaring variables for WikiHandler below.
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = False)

#Utilities
#------------------------------------------------------
def make_secure_val(val):
	return '%s|%s' % (val, hmac.new(SECRET, val).hexdigest())

def check_secure_val(secure_val):
	val = secure_val.split('|')[0]
	if secure_val == make_secure_val(val):
		return val

def wiki_key(name = 'default'):
	return db.Key.from_path('wikis', name)

#User Utilities
#-----------------------------------------------------------
def make_salt(length = 5):
	return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
	if not salt:
		salt = make_salt()
	h = hashlib.sha256(name + pw + salt).hexdigest()
	return '%s|%s' % (salt, h)

def is_valid_password_for_user(name, password, h):
	salt = h.split('|')[0]
	return h == make_pw_hash(name, password, salt)

def users_key(group = 'default'):
	return db.Key.from_path('users', group)

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
	return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
	return password and PASS_RE.match(password)

EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
def valid_email(email):
	return not email or EMAIL_RE.match(email)

def user_is_logged_in(user_id_cookie):
	logged_in = False
	user = None
	uid = user_id_cookie
	if uid and uid != "":
		logged_in = True
		u = User.by_id(int(uid))
		user = u.name
	return logged_in, user

#User DB Construction
#----------------------------------------------------
class User(db.Model):
	name = db.StringProperty(required = True)
	pw_hash = db.StringProperty(required = True)
	email = db.StringProperty()

	@classmethod
	def by_id(cls, uid):
		return User.get_by_id(uid, parent = users_key())

	@classmethod
	def by_name(cls, name):
		u = User.all().filter('name =', name).get()
		return u

	@classmethod
	def register(cls, name, pw, email = None):
		pw_hash = make_pw_hash(name, pw)
		return User(parent = users_key(),
					name = name,
					pw_hash = pw_hash,
					email = email)

	@classmethod
	def login(cls, name, pw):
		u = cls.by_name(name)
		if u and is_valid_password_for_user(name, pw, u.pw_hash):
			return u

#Wiki DB Construction
#---------------------------------------------------------
class Wiki(db.Model):
	content = db.TextProperty(required = False)
	url_path = db.StringProperty(required = False)
	created = db.DateTimeProperty(auto_now_add = True)
	last_modified = db.DateTimeProperty(auto_now = True)

	@classmethod
	def by_id(cls, wid):
		return Wiki.get_by_id(wid, parent = wiki_key())

	@classmethod
	def by_path_name(cls, path_name):
		w = Wiki.all().filter('url_path =', path_name).get()
		return w
#Wiki Utilities
#----------------------------------------------------------
def get_wiki_content(path):
	w = Wiki.by_path_name(path)
	existing_content = ""
	if w:
		existing_content = w.content
	return existing_content, path

#Handlers & Handler Logic
#----------------------------------------------------------
class WikiHandler(webapp2.RequestHandler):
	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

	def render_str(sef, template, **params):
		t = jinja_env.get_template(template)
		return t.render(params)

	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))

	def set_secure_cookie(self, name, val):
		cookie_val = make_secure_val(val)
		self.response.headers.add_header(
			'Set-Cookie',
			'%s = %s; Path=/' % (name, cookie_val))

	def read_secure_cookie(self, name):
		cookie_val = self.request.cookies.get(name)
		return cookie_val and check_secure_val(cookie_val)

	def set_password_cookie(self, name, value):
		self.response.headers.add_header(
			'Set-Cookie',
			'%s = %s; Path=/' % (name, value))

	def login(self, user):
		self.set_secure_cookie('user_id', str(user.key().id()))

	def logout(self):
		self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')	

	def initialize(self, *a, **kw):
		webapp2.RequestHandler.initialize(self, *a, **kw)
		uid = self.read_secure_cookie('user_id')
		self.user = uid and User.by_id(int(uid))

class MainHandler(WikiHandler):
    def get(self):
    	logged_in = False
    	user = None
    	path = self.request.path
    	unquoted_path = urllib2.unquote(path)
    	uid = self.read_secure_cookie('user_id')
    	if uid and uid != "":
			logged_in = True
			u = User.by_id(int(uid))
			user = u.name
    	self.render('base.html', logged_in = logged_in, username = user, path = unquoted_path)

class Signup(WikiHandler):
	def get(self):
		self.render('signup.html')

	def post(self):
		key = 'user_hashes'
		have_error = False
		self.username = self.request.get('username')
		self.password = self.request.get('password')
		self.verify = self.request.get('verify')
		self.email = self.request.get('email')

		params = dict(username = self.username,
					  email = self.email)

		if not valid_username(self.username):
			params['error_username'] = "Pick a new username - shit's taken."
			have_error = True

		if not valid_password(self.password):
			params['error_password'] = "That password sucks. Pick a new one."
			have_error = True

		elif self.password != self.verify:
			params['error_verify'] = "Your passwords don't match. Learn to type."
			have_error = True

		if not valid_email(self.email):
			params['error_email'] = "We need a legit email."
			have_error = True

		if have_error:
			self.render('signup.html', **params)

		else:
			password_hash = make_pw_hash(self.username, self.password)
			self.set_password_cookie('pw-hash', password_hash)
			memcache.set(key, password_hash)
			self.done()


class Register(Signup):
	def done(self):
		u = User.by_name(self.username)
		if u:
			msg = "That user already exists."
			self.render("signup.html", error_username = msg)
		else:
			u = User.register(self.username, self.password, self.email)
			u.put()
			self.login(u)
			self.redirect('/')

class Login(WikiHandler):
    def get(self):
        self.render('login.html')

    def post(self):
    	key = 'user_hashes'
    	username = self.request.get('username')
    	password = self.request.get('password')

    	u = User.login(username, password)
    	if u:
    		u_hashes = memcache.get(key)
    		if u_hashes == None or u.pw_hash not in u_hashes: 
    			memcache.set(key, u.pw_hash)
    		self.login(u)
    		self.set_password_cookie('pw_hash', str(u.pw_hash))
    		time.sleep(0.5)
    		self.redirect('/')
    	else:
    		msg = 'Either your username or password is incorrect.'
    		self.render('login.html', error = msg)

class EditPage(WikiHandler):
	def get(self, url):
		logged_in, user = user_is_logged_in(self.read_secure_cookie('user_id'))
		path = self.request.path
		unquoted_path = urllib2.unquote(path)
		if logged_in:
			self.render('editpage.html', logged_in = logged_in, username = user)
		else:
			self.redirect('/signup')

	def post(self, url):
		post_content = self.request.get('wiki_content')
		path = self.request.path[6:]
		w = Wiki.all().filter("url_path =", path).get()
		if w:
			w.content = post_content
			w.put()
		else:
			wiki_post = Wiki(content = post_content, url_path = path)
			wiki_post.put()
		time.sleep(0.5) #localhost has some lag writing values to the datastore
		self.redirect(path) 

class WikiPage(WikiHandler):
    def get(self, PAGE_RE):
		existing_content, path = get_wiki_content(self.request.path)
		unquoted_path = urllib2.unquote(path)
		logged_in, user = user_is_logged_in(self.read_secure_cookie('user_id'))
		self.render('base.html', logged_in = logged_in, username = user, path = unquoted_path, content = existing_content)

class Logout(WikiHandler):
	def get(self):
		self.logout()
		time.sleep(0.5) #logout process finishes after redirect (only in localhost)
		self.redirect('/')
    			

app = webapp2.WSGIApplication([('/' + PAGE_RE, WikiPage),
    						   ('/signup', Register),
    						   ('/login', Login),
    						   ('/logout', Logout),
    						   ('/_edit' + PAGE_RE, EditPage),
    						   (PAGE_RE, WikiPage),
							   ], debug=True)
