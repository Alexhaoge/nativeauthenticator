import os
from jinja2 import ChoiceLoader, FileSystemLoader
from jupyterhub.handlers import BaseHandler
from jupyterhub.handlers.login import LoginHandler
from jupyterhub.utils import admin_only

from tornado import web
from tornado.escape import url_escape
from tornado.httputil import url_concat

from .orm import UserInfo

TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), 'templates')


class LocalBase(BaseHandler):
    _template_dir_registered = False

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if not LocalBase._template_dir_registered:
            self.log.debug('Adding %s to template path', TEMPLATE_DIR)
            loader = FileSystemLoader([TEMPLATE_DIR])
            env = self.settings['jinja2_env']
            previous_loader = env.loader
            env.loader = ChoiceLoader([previous_loader, loader])
            LocalBase._template_dir_registered = True


class SignUpHandler(LocalBase):
    """Render the sign in page."""
    async def get(self):
        if not self.authenticator.enable_signup:
            raise web.HTTPError(404)

        html = await self.render_template(
            'signup.html',
            ask_email=self.authenticator.ask_email_on_signup,
            two_factor_auth=self.authenticator.allow_2fa,
        )
        self.finish(html)

    def get_result_message(self, user, taken):
        alert = 'alert-info'
        message = 'Your information has been sent to the admin注册成功，请等待管理员审核'

        # Always error if username is taken.
        if taken:
            alert = 'alert-danger'
            message = ("Something went wrong. It appears that this "
                       "username is already in use. Please try again "
                       "with a different username. 用户名应当使用st加学号，如st1810001。")
        else:
            # Error if user creation was not successful.
            if not user:
                alert = 'alert-danger'
                pw_len = self.authenticator.minimum_password_length
                if pw_len:
                    message = ("Something went wrong. Be sure your "
                               "password has at least {} characters, doesn't "
                               "have spaces or commas and is not too "
                               "common. 遇到问题，密码不能太短或包含空格和冒号").format(pw_len)
                else:
                    message = ("Something went wrong. Be sure your password "
                               "doesn't have spaces or commas and is not too "
                               "common. Also do not use pure numbers as username. "
                               "遇到问题，密码不能太短或包含空格和冒号，或用户名密码有其他错误导致无法创建系统用户")

            # If user creation went through & open-signup is enabled, success.
            elif self.authenticator.open_signup:
                alert = 'alert-success'
                message = ('The signup was successful. You can now go to '
                           'home page and log in the system')

        return alert, message

    async def post(self):
        if not self.authenticator.enable_signup:
            raise web.HTTPError(404)

        user_info = {
            'username': self.get_body_argument('username', strip=False),
            'pw': self.get_body_argument('pw', strip=False),
            'email': self.get_body_argument('email', '', strip=False),
            'has_2fa': bool(self.get_body_argument('2fa', '', strip=False)),
        }
        taken = self.authenticator.user_exists(user_info['username'])
        user = self.authenticator.create_user(**user_info)

        alert, message = self.get_result_message(user, taken)

        otp_secret, user_2fa = '', ''
        if user:
            otp_secret = user.otp_secret
            user_2fa = user.has_2fa

        html = await self.render_template(
            'signup.html',
            ask_email=self.authenticator.ask_email_on_signup,
            result_message=message,
            alert=alert,
            two_factor_auth=self.authenticator.allow_2fa,
            two_factor_auth_user=user_2fa,
            two_factor_auth_value=otp_secret,
        )
        self.finish(html)


class AuthorizationHandler(LocalBase):
    """Render the sign in page."""
    @admin_only
    async def get(self):
        html = await self.render_template(
            'autorization-area.html',
            ask_email=self.authenticator.ask_email_on_signup,
            users=self.db.query(UserInfo).all(),
        )
        self.finish(html)


class ChangeAuthorizationHandler(LocalBase):
    @admin_only
    async def get(self, slug):
        UserInfo.change_authorization(self.db, slug)
        self.redirect(self.hub.base_url + 'authorize#' + slug)


class ChangePasswordHandler(LocalBase):
    """Render the reset password page."""

    @web.authenticated
    async def get(self):
        user = await self.get_current_user()
        html = await self.render_template(
            'change-password.html',
            user_name=user.name,
        )
        self.finish(html)

    @web.authenticated
    async def post(self):
        user = await self.get_current_user()
        new_password = self.get_body_argument('password', strip=False)
        result_message = 'Your password has been changed successfully'
        try:
            self.authenticator.change_password(user.name, new_password)
        except ValueError:
            result_message = f'Invalid Password. 密码长度不足或包含空格冒号或不符合linux要求'

        html = await self.render_template(
            'change-password.html',
            user_name=user.name,
            result_message=result_message,
        )
        self.finish(html)


class ChangePasswordAdminHandler(LocalBase):
    """Render the reset password page."""

    @admin_only
    async def get(self, user_name):
        if not self.authenticator.user_exists(user_name):
            raise web.HTTPError(404)
        html = await self.render_template(
            'change-password.html',
            user_name=user_name,
        )
        self.finish(html)

    @admin_only
    async def post(self, user_name):
        new_password = self.get_body_argument('password', strip=False)
        message_template = 'The password for {} has been changed successfully'
        try:
            self.authenticator.change_password(user_name, new_password)
        except ValueError:
            message_template = 'The password for {} failed to change.无法修改密码，密码长度不足或包含空格冒号或不符合linux要求'
        
        html = await self.render_template(
            'change-password.html',
            user_name=user_name,
            result_message=message_template.format(user_name),
        )
        self.finish(html)


class LoginHandler(LoginHandler, LocalBase):

    def _render(self, login_error=None, username=None):
        return self.render_template(
            'native-login.html',
            next=url_escape(self.get_argument('next', default='')),
            username=username,
            login_error=login_error,
            custom_html=self.authenticator.custom_html,
            login_url=self.settings['login_url'],
            enable_signup=self.authenticator.enable_signup,
            two_factor_auth=self.authenticator.allow_2fa,
            authenticator_login_url=url_concat(
                self.authenticator.login_url(self.hub.base_url),
                {'next': self.get_argument('next', '')},
            ),
        )


class DiscardHandler(LocalBase):
    """Discard a user from database"""

    @admin_only
    async def get(self, user_name):
        user = self.authenticator.get_user(user_name)
        if user is not None:
            if not user.is_authorized:
                # Delete user from NativeAuthenticator db table (users_info)
                user = type('User', (), {'name': user_name})
                try:
                    self.authenticator.delete_user(user)
                except ValueError:
                    html = await self.render_template(
                        'autorization-area.html',
                        ask_email=self.authenticator.ask_email_on_signup,
                        users=self.db.query(UserInfo).all(),
                        error=f'Unable to delete {user_name}无法删除系统用户'
                    )

                # Also delete user from jupyterhub registry, if present
                if self.users.get(user_name) is not None:
                    self.users.delete(user_name)

        self.redirect(self.hub.base_url + 'authorize')
