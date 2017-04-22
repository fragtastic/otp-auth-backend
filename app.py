import base64, datetime, hashlib, hmac, json, pyotp
from flask import Flask, abort, Response, request
app = Flask(__name__)

users = {
    'testuser': 'secret33'
}

hmacsecret = 'CHANGEME'

@app.route('/')
def authtest():
    fotp_token = request.cookies.get('FOTP-Token')
    valid = validate_token(fotp_token)
    if not valid:
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
            token = generate_token(uas[0])
            return token_response(token)
        else:
            abort(401)
    else:
        token = update_token(fotp_token)
        return token_response(token)

def token_response(token):
    tokens = json.dumps(token)
    resp = Response('', 200)
    # TODO - Expiration client side
    resp.set_cookie('FOTP-Token', tokens)
    return resp

def update_token(token):
    tokenj = json.loads(token)
    return generate_token(tokenj['payload']['user'])

def generate_token(user):
    now = datetime.datetime.utcnow()
    payload = {
        'exp': str(now + datetime.timedelta(minutes=1)),
        'iat': str(now),
        'user': user
    }
    payloads = json.dumps(payload)
    digest = hmac.new(bytes(hmacsecret), msg=bytes(payloads), digestmod=hashlib.sha256).hexdigest()
    token = {
        'payload': payload,
        'digest': digest
    }
    return token

def validate_token(token):
    if token is None:
        return False
    tokenj = json.loads(token)
    if 'payload' not in tokenj or 'digest' not in tokenj:
        return False
    now = datetime.datetime.utcnow()
    print tokenj['payload']['exp']
    print now
    if datetime.datetime.strptime(tokenj['payload']['exp'], "%Y-%m-%d %H:%M:%S.%f") <= now:
        print "EXPIRED"
        return False
    payloads = json.dumps(tokenj['payload'])
    digest = tokenj['digest']
    return hmac.new(bytes(hmacsecret), msg=bytes(payloads), digestmod=hashlib.sha256).hexdigest() == digest

@app.errorhandler(401)
def accessdenied_401(error):
    return Response('Access denied', 401, {'WWW-Authenticate':'Basic realm="Login Required"'})

if __name__ == '__main__':
    app.run(port=8066)
