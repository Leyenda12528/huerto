from flask import Flask, jsonify, request, json
from flask_mysqldb import MySQL
from datetime import datetime
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager
from flask_jwt_extended import (create_access_token, create_refresh_token, jwt_required, jwt_refresh_token_required, get_jwt_identity, get_raw_jwt)
import jwt

app = Flask(__name__)
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'huerto'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'
app.config['JWT_SECRET_KEY'] = 'secret'

mysql = MySQL(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
CORS(app)

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


@app.route("/login")
def login():
    cursor = mysql.connection.cursor()
    cursor.execute("select * from usuarios")
    data = cursor.fetchall()
    print(data)
    return "Hola con Python"

if __name__ == '__main__':
    app.run(debug = True)