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
            return jsonify({'result': 'falta Token', 'valid' : False}), 401
        try:
            data_token = jwt.decode(token, app.config['SECRET_KEY'])
            #cursor = mysql.connection.cursor()
            #cursor.execute("select * from usuarios where ID = %s", (data_token['ID'],))
            #data_base = cursor.fetchone()
            data_usuario = data_token
        except:
            return jsonify({'result': 'Token inválido', 'valid' : False}), 401
        return f(data_usuario, *args, **kwargs)
        #return f(*args, **kwargs)
    return decorated

@app.route('/public')
def public():
    return "view public"

@app.route('/validateToken')
@token_requeried
def private(data_usuario):
    return jsonify({'result': 'Token válido', 'valid' : True})

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

    return jsonify({'result': Plantas, 'valid' : True})
#------------------------------------- GET PLANTA
@app.route('/planta/<int:id_planta>')
@token_requeried
def getPlanta(data_usuario, id_planta):
    Planta = {}
    cursor = mysql.connection.cursor()

    cursor.execute("select * from plantas where id = %s ", (id_planta,))
    dato = cursor.fetchone()
    if dato:
        Planta = {
            "ID" : dato['id'],
            "nombre" : dato['nombre'],
            "descripcion" : dato['descripcion'],
            "tipo_tierra" : dato['tipo_tierra'],
            "historico": ast.literal_eval(dato['historico'])
        }
        resp = Planta
    else:
        resp = {
            'valid' : False,
            'result': 'No existe planta'
        }
    return jsonify(resp)

#------------------------------------- SET PLANTA
@app.route('/plantas', methods=['POST'])
@token_requeried
def setPlanta(data_usuario):
    if not request.json:
        return jsonify({'result': 'no json', 'valid' : False})
    nombre = request.json.get('nombre', None)
    descripcion = request.json.get('descripcion', None)
    tipo_tierra = request.json.get('tipo_tierra', None)
    historico = request.json.get('historico', None)

    if nombre is None or descripcion is None or historico is None:
        return jsonify({'result': 'faltan parámentros', 'valid' : False})

    #print(historico[0]['fecha'])
    #return "----------"
    cursor = mysql.connection.cursor()
    cursor.execute("insert into plantas (nombre, descripcion, tipo_tierra, historico, estatus) values(%s, %s, %s, %s, %s)", (nombre, descripcion, tipo_tierra, str(historico), 1))
    ID = cursor.lastrowid
    cursor.execute("insert into usuarios_planta (id_usuario, id_planta) values(%s, %s)", (data_usuario['ID'], cursor.lastrowid))
    mysql.connection.commit()
    return jsonify({
        "ID" : ID,
        "nombre" : nombre,
        "descripcion" : descripcion,
        "tipo_tierra" : descripcion,
        "historico": historico,
        "estatus": 1
    })
#------------------------------------- UPDATE PLANTA
@app.route('/planta/<int:id_planta>', methods=['PUT'])
@token_requeried
def updatePlanta(data_usuario,id_planta):
    historico = request.json.get('historico', None)
    if historico is None:
        return jsonify({'result': 'faltan parámentros', 'valid' : False})
    cursor = mysql.connection.cursor()

    cursor.execute("select * from plantas where id = %s ", (id_planta,))
    dato = cursor.fetchone()
    if dato:
        cursor = mysql.connection.cursor()
        cursor.execute("update plantas set historico = %s where id = %s", (str(historico), id_planta))
        mysql.connection.commit()
        resp = {
            'result': True
        }
    else:
        resp = {
            'valid' : False,
            'result': 'No existe planta'
        }
    return jsonify(resp)
#------------------------------------- UPDATE CONTRASEÑA
@app.route('/user', methods=['PUT'])
@token_requeried
def updateUser(data_usuario):
    if not request.json:
        return jsonify({'result': 'no json', 'valid' : False})
    passwordNew = request.json.get('passwordNew', None)
    passwordOld = request.json.get('passwordOld', None)
    if passwordNew is None or passwordOld is None:
        return jsonify({'result': 'faltan parámentros', 'valid' : False})
    cursor = mysql.connection.cursor()
    cursor.execute("select * from usuarios where usuario = %s", (data_usuario['user'],))
    data = cursor.fetchone()
    if data:
        if bcrypt.check_password_hash(data['pass'], passwordOld):
            password = bcrypt.generate_password_hash(passwordNew).decode('utf-8')
            cursor.execute("update usuarios set pass = %s where id = %s", (password, data_usuario['ID']))
            mysql.connection.commit()
            resp = {
                'valid' : True,
            }
        else:
            resp = {
                'result': 'Contraseña Incorrecta'
            }
    else:
        resp = {
            'valid' : False,
            'result': 'User'
        }
    return jsonify(resp)
#------------------------------------- 

#------------------------------------- REGISTER
@app.route('/register', methods=['POST'])
#@token_requeried
#def register(data_usuario):
def register():
    if not request.json:
        return jsonify({'result': 'no json', 'valid' : False})
    usuario = request.json.get('usuario', None)
    password = request.json.get('password', None)
    if usuario is None or password is None:
        return jsonify({'result': 'faltan parámentros', 'valid' : False})

    cursor = mysql.connection.cursor()
    usuario = request.get_json()['usuario']
    cursor.execute("select usuario from usuarios")
    senl = 0
    for dato in cursor.fetchall():
        if dato['usuario'] == usuario:
            senl = 1
            break
    if senl == 0:
        password = bcrypt.generate_password_hash(request.get_json()['password']).decode('utf-8')
        cursor.execute("insert into usuarios (usuario, pass, estatus) values (%s, %s, %s)", (usuario, password, 1))
        mysql.connection.commit()
        resp = {
            'valid' : True,
            'result': 'Ingresado exitosamente',
            'usuario': request.json['usuario']
        }
    else:
        resp = {
            'valid' : False,
            'result' : 'Usuario existente'
        }

    return jsonify(resp)

#------------------------------------- LOGIN
@app.route("/login", methods=['POST'])
def login():
    if not request.json:
        return jsonify({'result': 'no json', 'valid' : False})
    usuario = request.json.get('usuario', None)
    password = request.json.get('password', None)
    if usuario is None or password is None:
        return jsonify({'result': 'faltan parámentros', 'valid' : False})

    cursor = mysql.connection.cursor()
    cursor.execute("select * from usuarios where usuario = %s", (usuario,))
    data = cursor.fetchone()
    if data:
        if bcrypt.check_password_hash(data['pass'], password):
            token = jwt.encode(
                {
                    'ID' : data['id'],
                    'user': usuario,
                    'iat': datetime.utcnow(),
                    'exp': datetime.utcnow() + timedelta(hours=1)
                },
                app.config['SECRET_KEY']
            )
            resp = {
                'valid' : True,
                'token': token.decode('utf-8')
            }
        else:
            resp = {
                'valid' : False,
                'result': 'Password'
            }
    else:
        resp = {
            'valid' : False,
            'result': 'User'
        }
    return jsonify(resp)

if __name__ == '__main__':
    app.run(debug = True)