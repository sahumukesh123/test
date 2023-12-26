import requests
from flask import Flask, jsonify, request, make_response
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
import mysql.connector
# import jwt
from functools import wraps
import json
import os
from jwt.exceptions import DecodeError

import logging
from flask import make_response
logging.basicConfig(filename='app.log', level=logging.INFO)

app = Flask(__name__)

app.config['JWT_SECRET_KEY'] = 'your_jwt_secret_key'  # Change this to a secure secret key
app.config['JWT_TOKEN_LOCATION'] = ['headers', 'cookies']
app.config['JWT_COOKIE_CSRF_PROTECT'] = False  # Disable CSRF protection for cookies
app.config['JWT_ACCESS_COOKIE_NAME'] = 'token'

jwt = JWTManager(app)


# def create_connection():
#     connection = mysql.connector.connect(
#         host="prdb.cxaui20y089h.ap-south-1.rds.amazonaws.com",
#         user="admin",
#         password="Narendra12345",
#         database="projectdemo"
#
#     )
#     print("connection is created successfully")
#     return connection


# connection = create_connection()
# print(connection)




conn = mysql.connector.connect(host='database.clau0466sb6g.us-east-1.rds.amazonaws.com',
                               user='admin',
                               password='12345678',
                               database='database1')
cursor = conn.cursor()


cursor.execute("""
    CREATE TABLE IF NOT EXISTS mukesh (
        email VARCHAR(100) PRIMARY KEY,
        password VARCHAR(80) NOT NULL,
        roles VARCHAR(255)
    )
""")
conn.commit()


# Routes

# User Registration
@app.route('/register', methods=['POST'])
def register():
    global cursor
    if not conn.is_connected():
        conn.reconnect()
    cursor = conn.cursor()
    try:
        data = request.get_json()
        
        email = data['email']
        password = data['password']
        roles = data.get('roles', '')  # Optional roles parameter

        # Check if the username and email are available
        cursor.execute("SELECT * FROM users WHERE username = %s", (email))
        existing_user = cursor.fetchone()
        if existing_user:
            return jsonify({'error': 'email already exists'}), 400

        # Register the user
        cursor.execute("INSERT INTO users (email, password, roles) VALUES (%s, %s, %s)",
                       (email, password, roles))
        conn.commit()
        cursor.close()

        return jsonify({'message': 'User registered successfully'}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# User Login
@app.route('/login', methods=['POST'])
def login():
    global cursor
    try:
        data = request.get_json()
        email = data['email']
        password = data['password']

        if not conn.is_connected():
            conn.reconnect()
        cursor = conn.cursor()

        # Authenticate the user
        cursor.execute("SELECT * FROM users WHERE email = %s AND password = %s", (email, password))
        user = cursor.fetchone()

        if user:
            access_token = create_access_token(identity=email)
            response = make_response(jsonify({'message': 'Login successful'}))
            response.set_cookie('token', access_token)

            return response, 200
        else:
            return jsonify({'error': 'Invalid username or password'}), 401
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def roles_required(*required_roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            current_user = get_jwt_identity()
            cursor.execute("SELECT roles FROM users WHERE email = %s", (current_user,))
            user_roles = cursor.fetchone()[0]

            if 'admin' in user_roles.split(','):
                # Admin has access to all functionalities
                return f(*args, **kwargs)
            elif any(role in user_roles.split(',') for role in required_roles):
                # User has access to the specified roles
                return f(*args, **kwargs)
            else:
                return jsonify({'error': 'Unauthorized: User does not have the necessary role'}), 403

        return decorated_function

    return decorator



@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200


# FIRST FUNCTION: EUROS TO INR
@app.route('/', methods=["GET"])
def home():
    return "This is a home page:"

# Adding an endpoint:

def euro_to_inr(euros):
    rate = 84
    try:
        euros = float(euros)
    except ValueError:
        raise ValueError(": Euros quantity should be a number")

    if euros < 0:
        raise ValueError("Invalid input: Euro should be non negative")

    inr = euros * rate
    return inr

@app.route('/euro_to_inr', methods=["POST"])
@jwt_required()
def handle_euros():

    headers = {'Authorization': f'Bearer {request.cookies.get("token")}'}
    response = requests.post('http://127.0.0.1:5000/euro_to_inr', headers=headers)

    data = request.get_json()
    euros = data.get("euros")
    try:
        if euros is None:
            raise ValueError("Invalid input: Euros value is missing")

        result = euro_to_inr(euros)
        return jsonify({'result': result})
    except ValueError as e:
        return jsonify({'error': str(e)}), 400

# SECOND FUNCTION: POUNDS TO INR
def pounds_to_inr(pounds):
    rate = 104
    try:
        pounds = float(pounds)
    except ValueError:
        raise ValueError("Value of quantity of Pounds should be in number:")

    if pounds < 0:
        raise ValueError("Value of the quantity of the pounds cannot be less than 0")

    inr = pounds * rate
    return inr

@app.route("/Pounds_to_inr", methods=["POST"])
@jwt_required()
def handle_Pounds():
    data = request.get_json()
    pounds = data.get("pounds")

    try:
        if pounds is None:
            raise ValueError("Invalid input: Pounds value is missing")

        result = pounds_to_inr(pounds)
        return jsonify({'result': result})
    except ValueError as e:
        return jsonify({'error': str(e)}), 400

# THIRD FUNCTION: FRANCS TO INR
def francs_to_inr(francs):
    rate = 96.6
    try:
        francs = float(francs)
    except ValueError:
        raise ValueError("Invalid value. Please enter amount in numbers")

    if francs < 0:
        raise ValueError("Francs cannot be in negative:")

    inr = francs * rate
    return inr

@app.route('/francs_to_inr', methods=["POST"])
@jwt_required()
def handle_francs():
    data = request.get_json()
    francs = data.get("francs")

    try:
        if francs is None:
            raise ValueError("Invalid input: Francs value is missing")

        result = francs_to_inr(francs)
        return jsonify({'result': result})
    except ValueError as e:
        return jsonify({'error': str(e)}), 400


@app.route('/add', methods=['POST'])
@jwt_required()
@roles_required('user')
def get_add():
    try:
        current_user_id = get_jwt_identity()
        response = request.get_json()
        # if response.status_code != 200:
        #     return jsonify({'error': response.json()['message']}), response.status_code

        num1 = response.get('a')
        num2 = response.get('b')

        if num1 is None or num2 is None:
            return jsonify({'error': 'invalid no format'}), 400

        try:
            result = float(num1) + float(num2)
            return jsonify({'result': result})
        except ValueError:
            return jsonify({'error': 'invalid number format'}), 400

    except Exception as e:
        return jsonify({'error': str(e)}), 500



# Subtract Functionality
@app.route('/subtract', methods=['POST'])
@jwt_required()
@roles_required('other')  # User can access 'add' and 'subtract'
def subtract():
    try:
        data = request.get_json()
        result = data['a'] - data['b']
        return jsonify({'result': result}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    app.run(host="0.0.0.0", debug=True)
