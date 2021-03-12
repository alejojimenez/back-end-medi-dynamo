import os
import re
from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_script import Manager
from flask_migrate import Migrate, MigrateCommand
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from flask_mysqldb import MySQL
from datetime import datetime
from models import User, db

BASEDIR = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "mysql://uhbczqfljazmvkl0:X9OXM4a4dCxQTzyPw2ek@bp8jizhsaakrh6qw6udz-mysql.services.clever-cloud.com:3306/bp8jizhsaakrh6qw6udz" + os.path.join(BASEDIR, "medidynamo")
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
    email_reg = '^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$'
    ## Expresion regular para validar una contraseña ##
    password_reg = '^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[a-zA-Z]).{8,}$'
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

if __name__ == "__main__":
    manager.run()