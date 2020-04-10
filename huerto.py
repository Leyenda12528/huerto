from flask import Flask, jsonify, request, json
from flask_mysqldb import MySQL
from datetime import datetime, timedelta
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager
from flask_jwt_extended import (create_access_token, create_refresh_token, jwt_required, jwt_refresh_token_required, get_jwt_identity, get_raw_jwt)
import jwt
from functools import wraps

app = Flask(__name__)
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'huerto'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'
app.config['SECRET_KEY'] = 'secret'

mysql = MySQL(app)
bcrypt = Bcrypt(app)
#jwt = JWTManager(app)
CORS(app)

def token_requeried(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        #token = None
        #if 'x-access-token' in request.headers:
            #token = request.headers['x-access-token']
        token = request.args.get('token')
        if not token:
            return jsonify({'result': 'falta Token'}), 401
        try:
            data_token = jwt.decode(token, app.config['SECRET_KEY'])
            #cursor = mysql.connection.cursor()
            #cursor.execute("select * from usuarios where ID = %s", (data_token['ID'],))
            #data_base = cursor.fetchone()
            #data_usuario = data_base
        except:
            return jsonify({'result': 'Token inválido'}), 401
        #return f(data_usuario, *args, **kwargs)
        return f(*args, **kwargs)
    return decorated

@app.route('/public')
def public():
    return "view public"

@app.route('/private')
@token_requeried
def private():
    return "view private"

@app.route('/register', methods=['POST'])
def register():

    cursor = mysql.connection.cursor()
    usuario = request.get_json()['usuario']
    password = bcrypt.generate_password_hash(request.get_json()['password']).decode('utf-8')
    cursor.execute("insert into usuarios (usuario, pass, estatus) values (%s, %s, %s)", (usuario, password, 1))
    mysql.connection.commit()
    return jsonify({
        'result': 'Ingresado exitosamente',
        'usuario': request.json['usuario']
    })


@app.route("/login", methods=['POST'])
def login():
    if not request.json:
        return jsonify({'result': 'no json'})
    usuario = request.json.get('usuario', None)
    password = request.json.get('password', None)
    if usuario is None or password is None:
        return jsonify({'result': 'faltan parámentros'})

    cursor = mysql.connection.cursor()
    cursor.execute("select * from usuarios where usuario = %s", (usuario,))
    data = cursor.fetchone()
    if bcrypt.check_password_hash(data['pass'], password):
        token = jwt.encode(
            {
                'ID' : data['id'],
                'user': usuario,
                'iat': datetime.utcnow(),
                'exp': datetime.utcnow() + timedelta(minutes=5)
            },
            app.config['SECRET_KEY']
        )
        return jsonify({'token': token.decode('utf-8')})
    else:
        return jsonify({'result': 'User / Password Incorrect'})

if __name__ == '__main__':
    app.run(debug = True)