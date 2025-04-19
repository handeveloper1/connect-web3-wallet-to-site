from flask import Flask, request, render_template, jsonify
from eth_account.messages import encode_defunct
from eth_account import Account
import jwt
import random
from flask import session



app = Flask(__name__)
app.config['SECRET_KEY'] = 'super_secret_key'
nonces = {}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/login-data')
def login_data():
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return jsonify({'success': False}), 401

    token = auth_header.replace('Bearer ', '')

    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        address = payload['address']
        return jsonify({'success': True, 'address': address})
    except jwt.InvalidTokenError:
        return jsonify({'success': False}), 401

@app.route('/nonce', methods=['POST'])
def get_nonce():
    address = request.json.get('address')
    nonce = f"Giriş için imzala: {random.randint(100000, 999999)}"
    nonces[address.lower()] = nonce
    return jsonify({'nonce': nonce})



@app.route('/verify', methods=['POST'])
def verify():
    data = request.json
    address = data['address'].lower()
    signature = data['signature']
    nonce = nonces.get(address)

    if not nonce:
        return jsonify({'success': False})

    try:
        message = encode_defunct(text=nonce)
        recovered = Account.recover_message(message, signature=signature)
        if recovered.lower() == address:
            token = jwt.encode({'address': address}, app.config['SECRET_KEY'], algorithm='HS256')
            session['jwt_token'] = token 
            return jsonify({'success': True, 'token': token})
        else:
            return jsonify({'success': False})
    except Exception as e:
        print("[ERROR] Exception:", e)
        return jsonify({'success': False})

from flask import Flask
from pyngrok import ngrok


if __name__ == '__main__':
    #app.run(debug=False)
    app.run(host='0.0.0.0', port=5000, debug=False)
