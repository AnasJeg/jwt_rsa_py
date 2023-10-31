from flask import Flask, request, jsonify
import jwt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import uuid
import datetime

app = Flask(__name__)


private_key = serialization.load_pem_private_key(open('private.pem', 'rb').read(), password=None)


def gen_rsa(data):
    token = jwt.encode(data, private_key, algorithm='RS256')
    return token

def gen_hmac(data):
    token = jwt.encode(data, 'jwtg7', algorithm='HS256')
    return token

@app.route('/rsa', methods=['GET'])
def rsa_jwt():
    username = request.args.get('username')
    password = request.args.get('password')

    if username is not None and password is not None:
        jti = str(uuid.uuid4())
        token = gen_rsa({'sub':'emsi','iss':'http://127.0.0.1:5000','iat':datetime.datetime.utcnow(),'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30),'jti': jti,'name': username,'roles':['user','test']})
        return jsonify({'token': token})
    return jsonify({'message': 'Invalid credentials'}), 401

@app.route('/hmac', methods=['GET'])
def hmac_jwt():
    username = request.args.get('username')
    password = request.args.get('password')

    if username is not None and password is not None:
        jti = str(uuid.uuid4())
        token = gen_hmac({'sub': 'emsi','iss':'http://127.0.0.1:5000', 'iat': datetime.datetime.utcnow(), 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30),'jti': jti, 'name': username, 'roles': ['user', 'test']})
        return jsonify({'token': token})
    return jsonify({'message': 'Invalid credentials'}), 401

if __name__ == '__main__':
    app.run(port=5000)
