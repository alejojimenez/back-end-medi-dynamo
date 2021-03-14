import os
import re
from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_script import Manager
from flask_migrate import Migrate, MigrateCommand
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from models import User, db

BASEDIR = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "mysql://root:X3#stejen@127.0.0.1:3306/medidynamo" 
#+ os.path.join(BASEDIR, "medidynamo.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["DEBUG"] = True
app.config["ENV"] = "development"
app.config["SECRET_KEY"] = "secret_key"
app.config["JWT_SECRET_KEY"] = 'encrypt'

db.init_app(app)
Migrate(app, db)
manager = Manager(app)
manager.add_command("db", MigrateCommand)
jwt = JWTManager(app)
bcrypt = Bcrypt(app)
CORS(app)

@app.route('/signup', methods=["POST"])
def signup():
    ## Expresion regular para validar email ##
    email_reg = '^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$'
    ## Expresion regular para validar una contraseña ##
    password_reg = '^.*(?=.{8,})(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).*$'
    ## Instanciar un nuevo usuario ##
    user = User()
    ## Chequear email que recibe del Front-End
    if re.search(email_reg, request.json.get("email")):
        user.email = request.json.get("email")
    else:
        return jsonify({"msg":"Formato del Correo Invalido"}), 401
    ## Chequear contraseña que recibe del Front-End
    if re.search(password_reg, request.json.get("password")):
        password_hash = bcrypt.generate_password_hash(request.json.get("password"))
        user.password = password_hash
    else:
        return jsonify({"msg":"Formato del Password Invalido"}), 401

    user.username = request.json.get("username", None)
    user.name = request.json.get("name")

    db.session.add(user)
    db.session.commit()

    return jsonify({"success":True})

@app.route('/login', methods=["POST"])
def login():
    # Validar contenido del Front
    if not request.is_json:
        return jsonify({"msg":"El Contenido esta Vacio"}), 400
    email = request.json.get("email", None)
    password = request.json.get("password", None)
    # Validar datos requeridos
    if not email:
        return jsonify({"msg":"Falta enviar el Correo"}), 400
    if not password:
        return jsonify({"msg":"Falta enviar el Password"}), 400
    # Consulta tabla user
    user = User.query.filter_by(email=email).first()
    # Validar usuario
    if user is None:
        return jsonify({"msg":"Usuario no Registrado"}), 404
    # Validar password
    if bcrypt.check_password_hash(user.password, password):
        access_token = create_access_token(identity=email)
        return jsonify({
            "access_token": access_token,
            "user": user.serialize(),
            "success":True
        }), 200
    else:
        return jsonify({"msg": "Password Invalido"}), 400


if __name__ == "__main__":
    manager.run()