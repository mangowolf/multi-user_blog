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
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),autoescape = True)

secret = 'all your base belong to us'

def render_str(template, **params):
	t = jinja_env.get_template(template)
	return t.render(params)

def make_secure_val(val):
	return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
	val = secure_val.split('|')[0]
	if secure_val == make_secure_val(val):
		return val

class Handler(webapp2.RequestHandler):
	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

	def render_str(self, template, **params):
		#t = jinja_env.get_template(template)
		params['user'] = self.user
		return render_str(template, **params)

	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))

	def set_secure_cookie(self, name, val):
		cookie_val = make_secure_val(val)
		self.response.headers.add_header('Set-Cookie','%s=%s; Path=/' % (name, cookie_val))

	def read_secure_cookie(self, name):
		cookie_val = self.request.cookies.get(name)
		return cookie_val and check_secure_val(cookie_val)

	def login(self, user):
		self.set_secure_cookie('user_id', str(user.key().id()))

	def logout(self):
		self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

	def initialize(self, *a, **kw):
		webapp2.RequestHandler.initialize(self, *a, **kw)
		uid = self.read_secure_cookie('user_id')
		self.user = uid and User.by_id(int(uid))


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

def valid_pw(name, password, h):
	salt = h.split(',')[0]
	return h == make_pw_hash(name, password, salt)

def users_key(group = 'default'):
	return db.Key.from_path('users', group)

class User(db.Model):
	name = db.StringProperty(required = True)
	pw_hash = db.StringProperty(required = True)
	email = db.StringProperty()

	@classmethod
	def by_id(cls,uid):
		return User.get_by_id(uid, parent = users_key())

	@classmethod
	def by_name(cls,name):
		u = User.all().filter('name =', name).get()
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

def blog_key(name):
	return db.Key.from_path('blogs', name)

def post_key(id):
	return db.Key.from_path('Post', id)

class Post(db.Model):
	author = db.StringProperty()
	subject = db.StringProperty(required = True)
	content = db.TextProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)
	last_modified = db.DateTimeProperty(auto_now = True)
	like_count = db.IntegerProperty()
	user_like = db.BooleanProperty()

	def render(self):
		self._render_text = self.content.replace('\n', '<br>')
		return render_str("post.html", p = self)

class Comment(db.Model):
	content = db.TextProperty(required = True)
	postid = db.StringProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)
	last_modified = db.DateTimeProperty(auto_now = True)

	def render(self):
		self.__render_text = self.content.replace('\n', '<br>')
		return render_str("comment.html", c = self)

class CommentPostPage(Handler):
	def get(self, post_id):
		if self.user:
			key = db.Key.from_path('Post', int(post_id), parent=blog_key(self.user.name))
			post = db.get(key)

			if not post:
				self.error(404)

			comments = db.GqlQuery("SELECT * FROM Comment WHERE postid =:1", str(post_id))
			#comments = db.Key.from_path('Comment', int(key), parent=post_key(post_id))
			#comments = db.GqlQuery("SELECT * FROM Comment WHERE postid =:1", post_id)
			self.render("post-comments.html", post = post, comments=comments)
		else:
			self.redirect('/login')

	def post(self, post_id):
		if not self.user:
			self.redirect('/blog')

		content = self.request.get('content')

		if content:
			c = Comment(postid = post_id, content = content)
			c.put()
			self.redirect('/blog/commentpost/%s' % post_id)

class BlogFront(Handler):
	def get(self):
		posts = db.GqlQuery("select * from Post order by created desc limit 10")
		self.render('front.html', posts = posts)
'''
	def post(self):

		if "like-button" in self.request.POST:

			post_id = self.request.get("id")
			key = db.Key.from_path('Post', int(post_id))
			post = db.get(key)
			if not post:
				self.error(404)
				return
			if self.user:
				error = 'You cannot like your own posts!'
				posts = db.GqlQuery("select * from Post order by created desc limit 10")
				self.render('front.html', posts = posts, error = error)
			else:
			post_id = self.request.get("id")
			#likeVal = Post.get_by_id(int(post_id), parent=blog_key(self.user.name))
			likeVal = db.Key.from_path('Post', post_id, parent=blog_key(self.user.name))
			#likeVal = db.get(key)
			post = db.get(likeVal)
			post.user_like = True
			post.like_count += 1
			post.put()
			#self.render("permalink.html", post = post)
			self.redirect('/blog/')
'''
class LikePost(Handler):
	def post(self, post_id):
		likeVal = db.Key.from_path('Post', int(post_id), parent=blog_key(self.user.name))
		post = db.get(likeVal)
		post.user_like = True
		post.like_count += 1
		post.put()
		self.redirect('/blog/')

class PostPage(Handler):
	def getKey(self, post_id):
		key = db.Key.from_path('Post', int(post_id), parent=blog_key(self.user.name))
		return key

	def get(self, post_id):
		postKey = self.getKey(post_id)
		post = db.get(postKey)

		if not post:
			self.error(404)
			return

		self.render("permalink.html", post = post)
'''
	def post(self, post_id):

		if "like-button" in self.request.POST:

			if self.user:
				error = 'You cannot like your own posts!'
				posts = db.GqlQuery("select * from Post order by created desc limit 10")
				self.render('front.html', posts = posts, error = error)
			else:
			likePost = Post.get_by_id(int(post_id), parent=blog_key(self.user.name))
			post = db.get(likePost)
			#post = db.get(likeVal)
			post.user_like = True
			post.like_count += 1
			post.put()
			self.render("permalink.html", post = post)
			#self.redirect('/blog/')
'''
class NewPost(Handler):
	def get(self):
		if self.user:
			self.render("newpost.html")
		else:
			self.redirect("/login")

	def post(self):
		if not self.user:
			self.redirect('/blog')

		author = self.user.name
		subject = self.request.get('subject')
		content = self.request.get('content')
		user_like = False;
		like_count = 0;

		if subject and content:
			p = Post(parent = blog_key(self.user.name), subject = subject, content = content, user_like = user_like, like_count = like_count, author = author)
			p.put()
			self.redirect('/blog/%s' % str(p.key().id()))
		else:
			error = "subject and content, please!"
			self.render("newpost.html", subject=subject, content=content, error=error)

class EditPost(Handler):
	def get(self, post_id):
		if self.user:
			key = db.Key.from_path('Post', int(post_id), parent=blog_key(self.user.name))
			query = db.get(key)
			self.render("edit-post.html", query=query)
		else:
			self.redirect("/login")

	def post(self, post_id):
		if not self.user:
			self.redirect('/blog')

		subject = self.request.get('subject')
		content = self.request.get('content')

		if "update" in self.request.POST:
			if subject and content:
				upVal = Post.get_by_id(int(post_id), parent=blog_key(self.user.name))
				upVal.subject = subject
				upVal.content = content
				upVal.put()
				self.redirect('/blog/%s' % str(upVal.key().id()))
			else:
				error = "subject and content, please!"
				self.render("edit-post.html", subject=subject, content=content, error=error)

		if "cancel" in self.request.POST:
			self.redirect('/blog')

		if "delete" in self.request.POST:
			if not self.user:
				self.redirect('/blog')

			postid = Post.get_by_id(int(post_id), parent=blog_key(self.user.name))
			self.redirect('/blog/delete-confirmation/%s' % str(postid.key().id()))

class DelConfirmation(Handler):
	def get(self, post_id):
		if self.user:
			key = db.Key.from_path('Post', int(post_id), parent=blog_key())
			query = db.get(key)
			self.render("delete-confirmation.html", query=query)
		else:
			self.redirect("/login")

	def post(self, post_id):
		if not self.user:
			self.redirect('/blog')

		if "delete-post" in self.request.POST:
			delVal = Post.get_by_id(int(post_id), parent=blog_key())
			delVal.delete()
			self.redirect("/blog")

		if "cancel-delete" in self.request.POST:
			self.redirect("/blog")

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
	def get(self):
		self.render("signup.html")

	def post(self):
		has_error = False
		self.username = self.request.get('username')
		self.password = self.request.get('password')
		self.verify = self.request.get('verify')
		self.email = self.request.get('email')

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

	def post(self):
		username = self.request.get('username')
		password = self.request.get('password')

		u = User.login(username, password)
		if u:
			self.login(u)
			self.redirect('/blog')
		else:
			msg = 'Invalid login'
			self.render('login-form.html', error = msg)

class Logout(Handler):
	def get(self):
		self.logout()
		self.redirect('/blog')

app = webapp2.WSGIApplication([('/', MainPage),
								('/blog/?', BlogFront),
								('/blog/([0-9]+)', PostPage),
								('/blog/newpost', NewPost),
								('/blog/editpost/([0-9]+)', EditPost),
								#('/blog/deletepost/([0-9]+)', DeletePost),
								('/blog/([0-9]+)/like', LikePost),
								('/blog/commentpost/([0-9]+)', CommentPostPage),
								('/blog/delete-confirmation/([0-9]+)', DelConfirmation),
								('/signup', Register),
								('/login', Login),
								('/logout', Logout),
								], debug=True)
