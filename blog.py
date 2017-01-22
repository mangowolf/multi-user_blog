import os
import re
import random
import hashlib
import hmac
from string import letters

import webapp2
import jinja2


from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
								autoescape = True)

secret = 'all your base belong to us'
def render_str(template, **params):
	t = jinja_env.get_template(template)
	return t.render(params)

def make_secure_val(val):
	return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

class Handler(webapp2.RequestHandler):
	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

	def render_str(self, template, **params):
		t = jinja_env.get_template(template)
		return t.render(params)

	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))

	def set_secure_cookie(self, name, val):
		cookie_val = make_secure_val(val)
		self.response.headers.add_header('Set-Cookie',
										'%s=%s; Path=/' % (name, cookie_val))

	def login(self, user):
		self.set_secure_cookie('user_id', str(user.key().id()))

def render_post(response, post):
	response.out.write('<b>' + post.subject + '</b><br>')
	response.out.write(post.content)

class MainPage(Handler):
	def get(self):
		self.write('Hello, Udacity')

#######User Functions
def make_salt(length = 5):
	return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
	if not salt:
		salt = make_salt()
	h = hashlib.sha256(name + pw + salt).hexdigest()
	return '%s,%s' % (salt, h)

def users_key(group = 'default'):
	return db.Key.from_path('users', group)

class User(db.Model):
	name = db.StringProperty(required = True)
	pw_hash = db.StringProperty(required = True)
	email = db.StringProperty()

	@classmethod
	def by_name(cls,name):
		u = User.all().filter('name=', name).get()
		return u

	@classmethod
	def register(cls, name, pw, email=None):
		pw_hash = make_pw_hash(name, pw)
		return User(parent = users_key(),
					name = name,
					pw_hash = pw_hash,
					email = email)

	@classmethod
	def login(cls,name,pw):
		u = cls.by_name(name)
		if u and valid_pw(name, pw, u.pw_hash):
			return u

###Blog Definitions and Classes

def blog_key(name = 'default'):
	return db.Key.from_path('blogs', name)

class Post(db.Model):
	subject = db.StringProperty(required = True)
	content = db.TextProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)
	last_modified = db.DateTimeProperty(auto_now = True)

	def render(self):
		self._render_text = self.content.replace('\n', '<br>')
		return render_str("post.html", p = self)

class BlogFront(Handler):
	def get(self):
		posts = db.GqlQuery("select * from Post order by created desc limit 10")
		self.render('index.html', posts = posts)

class PostPage(Handler):
	def get(self, post_id):
		key = db.Key.from_path('Post', int(post_id), parent=blog_key())
		post = db.get(key)

		if not post:
			self.error(404)
			return

		self.render("permalink.html", post = post)

class NewPost(Handler):
	def get(self):
		self.render("newpost.html")

	def post(self):
		subject = self.request.get('subject')
		content = self.request.get('content')

		if subject and content:
			p = Post(parent = blog_key(), subject = subject, content = content)
			p.put()
			self.redirect('/blog/%s' % str(p.key().id()))
		else:
			error = "subject and content, please!"
			self.render("newpost.html", subject=subject, content=content, error=error)

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
	return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
	return password and PASS_RE.match(password)

EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
	return not email or EMAIL_RE.match(email)

class Signup(Handler):
	'''def make_salt(self):
		return ''.join(random.choice(string.letters) for x in xrange(5))

	def hash_pw(self,name, pw, salt=None):
		salt = self.make_salt()
		hashPW = hashlib.sha256(name + pw + salt).hexdigest()
		return '%s,%s' % (hashPW,salt)
	'''
	def get(self):
		self.render("signup.html")

	def post(self):
		has_error = False
		self.username = self.request.get('username')
		self.password = self.request.get('password')
		self.verify = self.request.get('verify')
		self.email = self.request.get('email')
		#pwError = "Passwords did not match! Please re-enter password."

		params = dict(username = self.username,
					email = self.email)

		if not valid_username(self.username):
			params['error_username'] = "That's not a valid username."
			has_error = True

		if not valid_password(self.password):
			params['error_password'] = "That wasn't a valid password."
			has_error = True

		elif self.password != self.verify:
			params['error_verify'] = "Your passwords didn't match"
			has_error = True

		if not valid_email(self.email):
			params['error_email'] = "That's not a valid email."
			has_error = True

		if has_error:
			self.render('signup.html', **params)
		else:
			self.done()
		'''if password == verify:
			hashedPW = self.hash_pw(username,password)
			self.render("signup.html", username=username, password=password, verify=verify, email=email, hashedPW=hashedPW)
		else:

			self.render("signup.html", username=username, email=email, pwError=pwError)
		'''
	def done(self, *a, **kw):
		raise NotImplementedError

class Register(Signup):
	def done(self):
		#make sure the user doesn't already exist
		u = User.by_name(self.username)
		if u:
			msg = 'That user already exists.'
			self.render('signup.html', error_username = msg)
		else:
			u = User.register(self.username, self.password, self.email)
			u.put()

			self.login(u)
			self.redirect('/blog')

class Login(Handler):
	def get(self):
		self.render('login-form.html')

	#def post(self):

app = webapp2.WSGIApplication([('/', MainPage),
								('/blog/?', BlogFront),
								('/blog/([0-9]+)', PostPage),
								('/blog/newpost', NewPost),
								('/blog/signup', Register),
								('/blog/login', Login)
								], debug=True)
