from flask import Flask, jsonify, request, json
from flask_mysqldb import MySQL
from datetime import datetime, timedelta
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager
from flask_jwt_extended import (create_access_token, create_refresh_token, jwt_required, jwt_refresh_token_required, get_jwt_identity, get_raw_jwt)
from functools import wraps
import jwt
import ast

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

#------------------------------------- VALIDACION DE TOKEN
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
            data_usuario = data_token
        except:
            return jsonify({'result': 'Token inválido'}), 401
        return f(data_usuario, *args, **kwargs)
        #return f(*args, **kwargs)
    return decorated

@app.route('/public')
def public():
    return "view public"

@app.route('/private')
@token_requeried
def private(data_usuario):
    return "view private "+str(data_usuario['usuario'])

#------------------------------------- GET PLANTAS
@app.route('/plantas')
@token_requeried
def getPlantas(data_usuario):
    Plantas = []    
    cursor = mysql.connection.cursor()

    cursor.execute("select * from usuarios_planta where id_usuario = %s",(int(data_usuario['ID']),))
    dataP = cursor.fetchall()
    for planta in dataP:
        cursor.execute("select * from plantas where id = %s ", (int(planta['id_planta']),))
        data = cursor.fetchall()
        for dato in data:
            Plantas.append(
                {
                    "ID" : dato['id'],
                    "nombre" : dato['nombre'],
                    "descripcion" : dato['descripcion'],
                    "tipo_tierra" : dato['tipo_tierra'],
                    "historico": ast.literal_eval(dato['historico'])
                }
            )

    return jsonify({'result': Plantas})

#------------------------------------- SET PLANTA
@app.route('/plantas', methods=['POST'])
@token_requeried
def setPlanta(data_usuario):
    if not request.json:
        return jsonify({'result': 'no json'})
    nombre = request.json.get('nombre', None)
    descripcion = request.json.get('descripcion', None)
    tipo_tierra = request.json.get('tipo_tierra', None)
    historico = request.json.get('historico', None)

    if nombre is None or descripcion is None or historico is None:
        return jsonify({'result': 'faltan parámentros'})

    #print(historico[0]['fecha'])
    #return "----------"
    cursor = mysql.connection.cursor()
    cursor.execute("insert into plantas (nombre, descripcion, tipo_tierra, historico, estatus) values(%s, %s, %s, %s, %s)", (nombre, descripcion, tipo_tierra, str(historico), 1))
    cursor.execute("insert into usuarios_planta (id_usuario, id_planta) values(%s, %s)", (data_usuario['ID'], cursor.lastrowid))
    mysql.connection.commit()
    return jsonify({
        'planta': nombre,
        'result': 'Ingresado exitosamente'
    })
#------------------------------------- 

#------------------------------------- REGISTER
@app.route('/register', methods=['POST'])
@token_requeried
def register(data_usuario):
    if not request.json:
        return jsonify({'result': 'no json'})
    usuario = request.json.get('usuario', None)
    password = request.json.get('password', None)
    if usuario is None or password is None:
        return jsonify({'result': 'faltan parámentros'})

    cursor = mysql.connection.cursor()
    usuario = request.get_json()['usuario']
    password = bcrypt.generate_password_hash(request.get_json()['password']).decode('utf-8')
    cursor.execute("insert into usuarios (usuario, pass, estatus) values (%s, %s, %s)", (usuario, password, 1))
    mysql.connection.commit()
    return jsonify({
        'usuario': request.json['usuario'],
        'result': 'Ingresado exitosamente'
    })

#------------------------------------- LOGIN
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