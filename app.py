import base64, pyotp
from flask import Flask, abort, Response, request
app = Flask(__name__)

users = {
    'testuser': 'secret33'
}

@app.route('/')
def authtest():
    buas = request.headers.get('Authorization')
    if buas is None:
        abort(401)
    buas = buas.split(' ')[1]
    uas = base64.b64decode(buas).split(':')
    if uas[0] not in users:
        abort(401)
    totp = pyotp.TOTP(users[uas[0]])
    authed = totp.verify(uas[1])
    if authed:
        return ('', 200)
    else:
        abort(401)

@app.errorhandler(401)
def accessdenied_401(error):
    return Response('Access denied', 401, {'WWW-Authenticate':'Basic realm="Login Required"'})

if __name__ == '__main__':
    app.run(port=8066)
