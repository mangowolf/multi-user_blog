import os
import re
import random
import hashlib
import hmac
from string import letters

import webapp2
import jinja2
import time


from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),autoescape = True)
error = ""

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
		self.redirect("/blog")

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
	'''Model defining the User object'''

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

def blog_key(name = 'default'):
	return db.Key.from_path('blogs', name)

##Models
class Post(db.Model):
	'''Model for Post Objects'''

	author = db.StringProperty(required = True)
	subject = db.StringProperty(required = True)
	content = db.TextProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)
	last_modified = db.DateTimeProperty(auto_now = True)
	like_count = db.IntegerProperty(default=0)
	#Array containing all users who have liked a post
	user_like = db.StringListProperty()

	def render(self):
		self._render_text = self.content.replace('\n', '<br>')
		return render_str("post.html", p = self)

class Comment(db.Model):
	'''Model for Comment Objects'''

	author = db.StringProperty(required = True)
	content = db.TextProperty(required = True)
	postid = db.StringProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)
	last_modified = db.DateTimeProperty(auto_now = True)

	def render(self):
		self.__render_text = self.content.replace('\n', '<br>')
		return render_str("comment.html", c = self)

##Post Handlers

class BlogFront(Handler):
	'''Handler for all Blog Postings'''

	def get(self):
		posts = db.GqlQuery("select * from Post order by created desc limit 10")
		self.render('front.html', posts = posts)

class PostPage(Handler):
	'''Handler for rendering posts'''

	def get(self, post_id):
		key = db.Key.from_path('Post', int(post_id), parent=blog_key())
		post = db.get(key)

		if not post:
			self.error(404)
			return

		self.render("permalink.html", post = post)

class NewPost(Handler):
	'''Handler for new Posts'''

	def get(self):
		if self.user:
			self.render("newpost.html")
		else:
			self.redirect("/login")

	def post(self):
		if not self.user:
			return self.redirect('/blog')

		author = self.user.name
		subject = self.request.get('subject')
		content = self.request.get('content')
		user_like = [];

		if "submit" in self.request.POST:
			if subject and content:
				p = Post(parent = blog_key(), subject = subject, content = content, author = author)
				p.put()
				self.redirect('/blog/%s' % str(p.key().id()))
			else:
				error = "subject and content, please!"
				self.render('newpost.html', subject=subject, content=content, error=error)
		
		if "cancel" in self.request.POST:
			self.redirect('/blog')

class EditPost(Handler):
	'''Handler for Editing Posts'''

	def get(self, post_id):
		if self.user:
			key = db.Key.from_path('Post', int(post_id), parent=blog_key())
			post = db.get(key)
			if not post:
				self.error(404)
				return

			if self.user.name == post.author:
				self.render("edit-post.html", post=post)
			else:
				self.write("You can't edit other User's posts!")
		else:
			return self.redirect('/login')

	def post(self, post_id):
		if not self.user:
			return self.redirect('/blog')

		subject = self.request.get('subject')
		content = self.request.get('content')

		if "update" in self.request.POST:
			if subject and content:
				upVal = Post.get_by_id(int(post_id), parent=blog_key())
				upVal.subject = subject
				upVal.content = content
				upVal.put()
				self.redirect('/blog/%s' % str(upVal.key().id()))
			else:
				error = "subject and content, please!"
				self.render("edit-post.html", subject=subject, content=content, error=error)

		if "delete" in self.request.POST:
			if not self.user:
				self.redirect('/blog')

			postid = Post.get_by_id(int(post_id), parent=blog_key())
			self.redirect('/blog/delete-confirmation/%s' % str(postid.key().id()))

class DelConfirmation(Handler):
	'''Handler to delete Posts'''

	def get(self, post_id):
		if self.user:
			key = db.Key.from_path('Post', int(post_id), parent=blog_key())
			query = db.get(key)
			self.render("delete-confirmation.html", query=query)
		else:
			self.redirect("/login")

	def post(self, post_id):
		if not self.user:
			return self.redirect('/blog')

		if "delete-post" in self.request.POST:
			delVal = Post.get_by_id(int(post_id), parent=blog_key())
			delVal.delete()
			time.sleep(0.1)
			return self.redirect("/blog")

		if "cancel-delete" in self.request.POST:
			return self.redirect("/blog")

class LikePost(Handler):
	'''Handler for Liking Posts'''

	def post(self, post_id):
		if self.user:
			key = db.Key.from_path('Post', int(post_id), parent=blog_key())
			post = db.get(key)

			if not post:
				self.error(404)
				return

			if self.user.name != post.author:
				if self.user.name in post.user_like:
					self.write("you can only like a post once")
				else:
					post.user_like.append(self.user.name)
					post.like_count += 1
					post.put()
					time.sleep(0.1)
					self.redirect("/blog")
			if self.user.name == post.author:
				self.write("you can't like your own post!")

		else:
			self.redirect("/login")

##Comment Handlers
class CommentPostPage(Handler):
	'''Handler for Comment Posts'''

	def get(self, post_id):
		if self.user:
			key = db.Key.from_path('Post', int(post_id), parent=blog_key())
			post = db.get(key)

			if not post:
				return self.error(404)

			comments = db.GqlQuery("SELECT * FROM Comment WHERE postid =:1", str(post_id))
			self.render("post-comments.html", post = post, comments=comments)
		else:
			self.redirect('/login')

	def post(self, post_id):
		if not self.user:
			return self.redirect('/blog')

		if "submit" in self.request.POST:
			content = self.request.get('content')
			author = self.user.name

			if content:
				c = Comment(postid = post_id, content = content, author = author)
				c.put()
				time.sleep(0.1)
				return self.redirect('/blog/commentpost/%s' % post_id)
		if "cancel" in self.request.POST:
			return self.redirect("/blog/%s" % str(post_id))

class EditComment(Handler):
	'''Handler for editing comments for a post'''

	def get(self, comment_id):
		if self.user:
			key = db.Key.from_path('Comment', int(comment_id))
			comment = db.get(key)
			if not comment:
				return self.error(404)

			if self.user.name == comment.author:
				self.render("edit-comment.html", comment = comment)
			else:
				self.write("You can't edit other User's comments!")
		else:
			self.redirect("/login")

	def post(self, comment_id):
		if not self.user:
			return self.redirect("/blog")

		content = self.request.get('content')
		commentVal = Comment.get_by_id(int(comment_id))

		if "update" in self.request.POST:
			if content:
				commentVal.content = content
				commentVal.put()
				time.sleep(0.1)
				return self.redirect("/blog/commentpost/%s" % str(commentVal.postid))

##Registration and Login Handlers

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
	'''Handler for New User Signups'''

	def get(self):
		self.render("signup.html")

	def post(self):
		if "submit" in self.request.POST:
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
		if "cancel" in self.request.POST:
			return self.redirect("/blog")

	def done(self, *a, **kw):
		raise NotImplementedError

class Register(Signup):
	'''Handler for new User registration'''

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
	'''Handler for User login'''

	def get(self):
		self.render('login-form.html')

	def post(self):
		if "submit" in self.request.POST:
			username = self.request.get('username')
			password = self.request.get('password')

			u = User.login(username, password)
			if u:
				self.login(u)
				self.redirect('/blog')
			else:
				msg = 'Invalid login'
				self.render('login-form.html', error = msg)
		if "cancel" in self.request.POST:
			return self.redirect("/blog")

class Logout(Handler):
	'''Handler for User logout'''

	def get(self):
		self.logout()
		self.redirect('/blog')

app = webapp2.WSGIApplication([('/', MainPage),
								('/blog/?', BlogFront),
								('/blog/([0-9]+)', PostPage),
								('/blog/newpost', NewPost),
								('/blog/editpost/([0-9]+)', EditPost),
								('/blog/([0-9]+)/like', LikePost),
								('/blog/commentpost/([0-9]+)', CommentPostPage),
								('/blog/editcomment/([0-9]+)', EditComment),
								('/blog/delete-confirmation/([0-9]+)', DelConfirmation),
								('/signup', Register),
								('/login', Login),
								('/logout', Logout),
								], debug=True)
