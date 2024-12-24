from flask import Flask, request, jsonify
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_sqlalchemy import SQLAlchemy
import os
from dotenv import load_dotenv

from functools import wraps # for token_required

from flask_cors import CORS

# database connection to posgresql
import psycopg2
from psycopg2 import Error
# for Gemini
import google.generativeai as genai
# for matching
import re

load_dotenv()

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('SQLALCHEMY_DATABASE_URI')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = os.environ.get('SQLALCHEMY_TRACK_MODIFICATIONS')
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY')

# CORS(app)
CORS(app, resources={r"/api/*": {"origins": "http://localhost:5173"}})

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)


# User Model (using email as the unique identifier)
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)  # Email field
    first_name = db.Column(db.String(64), nullable=False)
    second_name = db.Column(db.String(64), nullable=False)
    instructions = db.Column(db.Text, nullable=False)
    password = db.Column(db.String(120), nullable=False)

    def __repr__(self):
        return f'<User {self.email}>'

# Create tables | doesn't work when the internet is not working (crashes the app)
# with app.app_context():
#     db.create_all()

instructions = os.environ.get('GEMINI_INSTRUCTIONS')

@app.before_request
def log_request_info():
    print("----- Incoming Request -----")
    print(f"Method: {request.method}")
    print(f"URL: {request.url}")
    print("Headers:")
    for key, value in request.headers.items():
        print(f"  {key}: {value}")
    print("Body:")
    try:
        # Attempt to decode the body as text (common for JSON, form data)
        print(request.get_data().decode('utf-8'))
    except UnicodeDecodeError:
        # If it's not easily decodable, print the raw bytes
        print(request.get_data())
    print("----------------------------")


def connect_to_remote_postgres(host, port, user, password, database):
    """
    Establishes a connection to a remote PostgreSQL database.

    Args:
        host (str): Hostname or IP address of the database server.
        port (int): Port number the database server is listening on.
        user (str): Username for database authentication.
        password (str): Password for database authentication.
        database (str): Name of the database to connect to.

    Returns:
        psycopg2.extensions.connection: Database connection object if successful, None otherwise.
    """
    try:
        connection = psycopg2.connect(
            host=host,
            port=port,
            user=user,
            password=password,
            database=database
        )
        if connection:
            print("Connected to PostgreSQL database successfully!")
            return connection

    except (Exception, Error) as error:
        print("Error while connecting to PostgreSQL", error)
        return None

def execute_query(connection, query, params=None):
    """
    Executes a SQL query on the database.

    Args:
        connection (psycopg2.extensions.connection): Database connection object.
        query (str): SQL query to execute.
        params (tuple, optional): Parameters to pass to the query (for parameterized queries). Defaults to None.

    Returns:
        list: Result set of the query if successful, None otherwise.
    """
    if not connection:
        print("No database connection available. Cannot execute query.")
        return None

    cursor = connection.cursor()
    try:
        cursor.execute(query, params)
        if query.upper().startswith("SELECT"):  # Only fetch results for SELECT statements
            #column_names = [desc[0] for desc in cursor.description]
            #print(column_names)
            # cursor.description
            results = cursor.fetchall()
            # results.append(cursor.fetchall())
            return results
        else:  # For INSERT, UPDATE, DELETE, commit the changes
            connection.commit()
            print("Query executed successfully.")
            return None
    except (Exception, Error) as error:
        print("Error executing query:", error)
        connection.rollback()  # Roll back in case of error
        return None
    finally:
        cursor.close()

def close_connection(connection):
    """Closes the database connection."""
    if connection:
        connection.close()
        print("Database connection closed.")


def extract_sql_type(text):
    """
    Extracts SQL code from a multiline string, specifically the content between
    "```sql" and "```".

    Args:
        text (str): The input string containing potential SQL code blocks.

    Returns:
        list: A list of strings, where each string is a SQL code block extracted
              from the input. Returns an empty list if no SQL blocks are found.
    """

    sql_pattern = r"```sql\n(.*?)\n```"  # Updated regex pattern for multi-line match
    type_pattern = r"```type\n(.*?)\n```"
    sql_match = re.findall(sql_pattern, text, re.DOTALL)
    type_match = re.findall(type_pattern, text, re.DOTALL)

    return [sql_match[0], type_match[0]]


# Token required decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message': 'Token is missing!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.filter_by(id=data['id']).first()
        except:
            return jsonify({'message': 'Token is invalid!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated

def convert_to_recharts_line_data(sql_results):
  """
  Converts SQL query results in the form [label, x, y] to the format required by Recharts LineChart.

  Args:
    sql_results: A list of lists/tuples, where each inner list/tuple represents a data point:
                 [label, x, y]  (e.g., ["Sales", "Jan", 4000])

  Returns:
    A list of dictionaries, where each dictionary represents a data point with keys for x-axis
    and each series' y-axis values.
  """

  series_data = {}  # Dictionary to group data by series label
  x_values = set()  # Use a set to store unique x-axis values

  for label, x, y in sql_results:
    if label not in series_data:
      series_data[label] = {}
    series_data[label][x] = y
    x_values.add(x)

  # Sort x-values for consistent order
  x_values = sorted(list(x_values))

  # Build the final data structure
  recharts_data = []
  for x in x_values:
    data_point = {"name": x}  # 'name' key for x-axis (can be changed if needed)
    for label, values in series_data.items():
      data_point[label] = values.get(x, 0)  # Get y-value for the x, default to 0 if not found
    recharts_data.append(data_point)

  return recharts_data


# Registration Route
@app.route('/api/register', methods=['POST'])
def register():
    email = request.json.get('email')  # Get email from the request
    password = request.json.get('password')
    first_name = request.json.get('first_name')
    second_name = request.json.get('second_name')
    instructions = request.json.get('instructions')

    user = User.query.filter_by(email=email).first()
    if user:
        return jsonify({'message': 'Email already exists'}), 400

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = User(
        email=email, 
        password=hashed_password, 
        first_name=first_name, 
        second_name=second_name, 
        instructions=instructions
    ) 
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'User registered successfully'}), 201

# Login Route
@app.route('/api/login', methods=['POST'])
def login2():
    auth = request.get_json()

    if not auth or not auth.get('email') or not auth.get('password'):
        return jsonify({'error': 'Could not verify', 'WWW-Authenticate': 'Basic realm="Login required!"'}), 401

    user = User.query.filter_by(email=auth['email']).first()

    if not user:
        return jsonify({'error': 'Could not verify', 'WWW-Authenticate': 'Basic realm="Login required!"'}), 401

    if bcrypt.check_password_hash(user.password, auth['password']):
        # token = jwt.encode({'id': user.id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'], algorithm="HS256")
        # return jsonify({'message': 'Login successful!', 'token': token, 'user': {'first_name': user.first_name, 'email': user.email}}), 200
        access_token = create_access_token(identity=str(user.id))
        return jsonify(access_token=access_token, user={'first_name': user.first_name, 'email': user.email})

    # return jsonify({'error': 'Could not verify', 'WWW-Authenticate': 'Basic realm="Login required!"'}), 401
    return jsonify({'error': 'Bad username or password'}), 401

# Example Protected Route
@app.route('/api/protected', methods=['GET'])
@token_required
def protected2(current_user):
    return jsonify({'message': f'Hello, {current_user.first_name}! This is a protected route.'})

@app.route('/api/insight', methods=['POST'])
@jwt_required()
def update_chart():
    current_user_id = get_jwt_identity()
    print("Current User ID (from JWT):", current_user_id)  # Log the user ID

    user = User.query.get(int(current_user_id)) # convert it back to an int
    print("User:", user)  # Log the user object
    try:
        data = request.get_json()
        if not data.get('message'):
            print('error: no data')
            return jsonify({'error': 'Invalid data format. Requires "body".'}), 400
        print(data)
        print(data.get('message'))
        
        # if not isinstance(data['labels'], list) or not isinstance(data['values'], list):
        #     return jsonify({'error': 'Invalid data format. "labels" and "values" must be lists.'}), 400
        
        # if len(data['labels']) != len(data['values']):
        #     return jsonify({'error': 'Invalid data format. "labels" and "values" must have the same length.'}), 400
        genai.configure(api_key=os.environ.get('GEMINI_API_KEY'))
        model = genai.GenerativeModel(
            model_name="gemini-1.5-flash",
            system_instruction=instructions)
        # prompt = input("What do you want to know about mineral goods revenues?\n")
        prompt = data.get('message')
        print('starting to process the question')
        response = model.generate_content(prompt)
        print('finished processing?')
        print(response.text)
        query, chart_type = extract_sql_type(response.text)
        print('what did it print?')

        db_host = os.environ.get('db_host')
        db_port = os.environ.get('db_port')  
        db_user = os.environ.get('db_user')
        db_password = os.environ.get('db_password')
        db_name = os.environ.get('db_name')

        conn = connect_to_remote_postgres(db_host, db_port, db_user, db_password, db_name)
        print('got the connect')
        if conn:
            # Example SELECT query
            # select_query = "SELECT * FROM public.mineral_revenues LIMIT 10;"
            select_query = query
            results = execute_query(conn, select_query)
            print('queried')
            if results:
                label = results
                # for row in results:
                #     print(row)
                #     xaxis.append(row[1])
                #     yaxis.append(row[2])
                close_connection(conn)
                if chart_type == 'line':
                    label = convert_to_recharts_line_data(label)
                print('returning success!')    
                #return jsonify({ 'data': label, 'sorted': sorted_label}), 200

                return jsonify({'type': chart_type, 'data': label}), 200
            # Example INSERT query (be cautious with modifications)
            # insert_query = "INSERT INTO your_table (column1, column2) VALUES (%s, %s);"
            # insert_values = ("value1", "value2")
            # execute_query(conn, insert_query, insert_values)

        close_connection(conn)

        return None, 500
    except Exception as e:
        print('exception is: ', str(e))
        return jsonify({'error': str(e)}), 500

# Login Route
@app.route('/login', methods=['POST'])
def login():
    email = request.json.get('email')  # Get email from the request
    password = request.json.get('password')

    print(email, password)

    user = User.query.filter_by(email=email).first()  # Query by email
    print(user)
    if not user or not bcrypt.check_password_hash(user.password, password):
        print(bcrypt.check_password_hash(user.password, password))
        return jsonify({'message': 'Invalid email or password'}), 401

    access_token = create_access_token(identity=email)  # Use email as identity
    return jsonify({'access_token': access_token}), 200

# Protected Route
@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user = get_jwt_identity()  # current_user will be the email
    return jsonify(logged_in_as=current_user), 200


if __name__ == '__main__':
    app.run(debug=True)