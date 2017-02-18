import os
import jinja2
import webapp2
import re
import random
import string
import hashlib
import hmac


from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)


USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_name(name):
    return name and USER_RE.match(name)


PASSWORD_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASSWORD_RE.match(password)


EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")
def valid_email(email):
    return not email or EMAIL_RE.match(email)


SECRET = "supersecret"


def make_secure_val(s):
    return "%s|%s" % (s, hmac.new(SECRET, s).hexdigest())


def check_secure_val(h):
    val = h.split('|')[0]
    if h == make_secure_val(val):
        return val


def make_salt():
    return ''.join(random.choice(string.letters) for x in xrange(5))


def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (h, salt)


def valid_pw(name, pw, h):
    salt = h.split(',')[1]
    return h == make_pw_hash(name, pw, salt)


class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header('Set-Cookie', '%s=%s; Path=/' % (name, cookie_val))

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


class Post(db.Model):
    title = db.StringProperty(required = True)
    body = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    number = db.IntegerProperty()


class User(db.Model):
    name = db.StringProperty(required = True)
    password_hash = db.StringProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid)

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email = None):
        password_hash = make_pw_hash(name, pw)
        return User(name = name,
                    password_hash = password_hash,
                    email = email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.password_hash):
            return u


class MainPage(Handler):
    def get(self):
        posts = db.GqlQuery("select * from Post order by created DESC limit 10")
        self.render("/front_page.html", user=self.user, posts=posts)


class AddPost(Handler):
    def get(self):
        self.render("/add_post.html", user=self.user)

    def post(self):
        title = self.request.get('title')
        body = self.request.get('body')

        if title and body:
            p = Post(title=title, body=body)
            p_key = p.put()
            p.number = p_key.id()
            p.put()

            self.redirect("/post/%s" % p_key.id())
        else:
            error = "please add a title and a body"
            self.render("/add_post.html", title=title, body=body, error=error)


class Permalink(Handler):
    def get(self, post_id):
        s = Post.get_by_id(int(post_id))
        self.render("/post.html", post=s, user=self.user)


class Signup(Handler):
    def get(self):
        self.render("/sign_up.html", user=self.user)

    def post(self):
        error = False
        self.name = self.request.get('name')
        self.password1 = self.request.get('password')
        self.password2 = self.request.get('verify')
        self.email = self.request.get('email')

        error_name = None
        error_email = None
        error_password = None

        params = dict(name=self.name,
                      email=self.email)

        if not valid_name(self.name):
            params['error_username'] = 'invalid username'
            error = True

        if not valid_email(self.email):
            params['error_email'] = 'invalid email'
            error = True

        if not valid_password(self.password1):
            params['error_password'] = 'invalid password'
            error = True

        if not self.password1 == self.password2:
            params['error_password'] = 'password mismatch'
            error = True

        if not error:
            self.done()
        else:
            self.render("sign_up.html", **params)

    def done(self, *a, **kw):
        raise NotImplementedError


class Register(Signup):
    def done(self):
        u = User.by_name(self.name)
        if u:
            msg = 'that user already exists'
            self.render('sign_up.html', error_username = msg)
        else:
            u = User.register(name=self.name, pw=self.password1, email=self.email)
            u.put()

            self.login(u)
            self.redirect('/')


class Login(Handler):
    def get(self):
        self.render('login.html')

    def post(self):
        username = self.request.get('name')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/')
        else:
            self.render('login.html', error="invalid login")


class Logout(Handler):
    def get(self):
        self.logout()
        self.redirect('/')

class Welcome(Handler):
    def get(self):
        if self.user:
            self.render('welcome.html', username = self.user.name)
        else:
            self.redirect('/signup')


app = webapp2.WSGIApplication([('/', MainPage),
                               ('/add', AddPost),
                               (r'/post/(\d+)', Permalink),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/welcome', Welcome)
                               ],
                              debug=True)
