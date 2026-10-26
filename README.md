# session-auth

This is a little framework to help you build session-based authentication for a
web application.

In your application, you need to implement [`PasswordAuthInfoStore`] and
[`SessionStore`] on top of whatever database it is using.

After that, you can create an [`Auth`] instance for it, and you use the API in
your application on it to create users, log in to get a session, and identify
users by session.



