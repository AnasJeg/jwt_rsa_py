from flask import Flask, request, jsonify
import jwt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

app = Flask(__name__)


public_key = serialization.load_pem_public_key(open('public.pem', 'rb').read(), backend=default_backend())


def protected_rsa(func):
    def wrapper_rsa(*args, **kwargs):
        token = request.headers.get('Authorization')
        if token:
            try:
                data = jwt.decode(token, public_key, algorithms=['RS256'])
                return func(data, *args, **kwargs)
            except jwt.ExpiredSignatureError:
                return jsonify({'message': 'token expired'}), 401
            except jwt.DecodeError:
                return jsonify({'message': 'token is invalid !!'}), 401
        return jsonify({'message': 'token is missing !!'}), 401
    return wrapper_rsa

def protected_hmac(func):
    def wrapper_hmac(*args, **kwargs):
        token = request.headers.get('Authorization')
        if token:
            try:
                data = jwt.decode(token, 'jwtg7', algorithms=['HS256'])
                return func(data, *args, **kwargs)
            except jwt.ExpiredSignatureError:
                return jsonify({'message': 'token expired'}), 401
            except jwt.DecodeError:
                return jsonify({'message': 'token is invalid !!'}), 401
        return jsonify({'message': 'token is missing !!'}), 401
    return wrapper_hmac


@app.route('/rsa', methods=['GET'])
@protected_rsa
def rsa_route(data):
    name = data['name']
    return jsonify({'message': f'RSA Service 2 by user {name}'})

@app.route('/hmac', methods=['GET'])
@protected_hmac
def hmac_route(data):
    name = data['name']
    return jsonify({'message': f'HMAC Service 2 by user {name}'})


if __name__ == '__main__':
    app.run(port=5002)
