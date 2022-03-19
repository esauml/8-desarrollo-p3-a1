#Archivo de configuración que tiene la función de crear nuestra aplicación, iniciar la base de datos y registrará nuestros modelos.
#Importamos el módulo os
import os
#Importamos la clase Flask del módulo flask
from flask import Flask
#Importamos la clase Security y SQLAlchemySessionUserDatastore de flask-security
from flask_security import Security, SQLAlchemyUserDatastore
#Importamos la clase SQLAlchemy del módulo flask_sqlalchemy
from flask_sqlalchemy import SQLAlchemy

#Creamos una instancia de SQLAlchemy
db = SQLAlchemy()
#Importamos las clases de User y Role del modelo
from .models import User, Role
#Creamos un objeto de la clase SQLAlchemySessionUserDatastore
userDataStore = SQLAlchemyUserDatastore(db, User, Role)

#Método de inicio de la aplicación
def create_app():
    #Creamos una instancia de la clase Flask
    app = Flask(__name__)

    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    #Generamos la clave aleatoria de sesión Flask para crear una cookie con la inf. de la sesión
    app.config['SECRET_KEY'] = os.urandom(24)
    #Definimos la ruta a la BD: mysql://user:password@localhost/bd'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:@localhost/flasksecurity'
    # We're using PBKDF2 with salt.
    app.config['SECURITY_PASSWORD_HASH'] = 'pbkdf2_sha512'
    #Semilla para el método de encriptado que utiliza flask-security
    app.config['SECURITY_PASSWORD_SALT'] = 'thisissecretsalt'

    #Inicializamos y creamos la BD
    db.init_app(app)
    @app.before_first_request
    def create_all():
        app.logger.debug('DB creation')
        db.create_all()

    #Conectando los modelos a fask-security usando SQLAlchemyUserDatastore
    security = Security(app, userDataStore)

    #login_manager = LoginManager()
    #login_manager.login_view = 'auth.login'
    #login_manager.init_app(app)

    #Importamos la clase User de models
    #from .models import User
    #@login_manager.user_loader
    #def load_user(user_id):
        # since the user_id is just the primary key of our user table, use it in the query for the user
        #return User.query.get(int(user_id))


    #Registramos el blueprint para las rutas auth de la aplicación
    from .auth import auth as auth_blueprint
    app.register_blueprint(auth_blueprint)

    #Registramos el blueprint para las partes no auth de la aplicación
    from .main import main as main_blueprint
    app.register_blueprint(main_blueprint)

    return app
