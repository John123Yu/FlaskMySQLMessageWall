from flask import Flask, render_template, request, redirect, session, flash
from mysqlconnection import MySQLConnector
from flask.ext.bcrypt import Bcrypt
import re
from datetime import datetime, timedelta
app = Flask(__name__)
app.secret_key = "ThisisSecretone"
mysql = MySQLConnector(app,'mydb')
bcrypt = Bcrypt(app)

EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
PASSWORD_REGEX = re.compile(r'^(?=.*[A-Z])(?=.*\d)')
counter = False

@app.route('/')
def loginpage():
	return render_template("login.html")

@app.route('/users', methods=['POST'])
def create_user():
	user_query = "SELECT * FROM users WHERE email = :email LIMIT 1"
	query_data = { 'email': request.form['email'] }
	user = mysql.query_db(user_query, query_data)
	counter = 0
	error = {}

	if user:
		error['EmailDuplicate'] = "Email Already In Use!"
		counter += 1
	if len(request.form['first_name']) < 1 or len(request.form['last_name']) < 1 or len(request.form['email']) < 1 or len(request.form['password']) < 1 or len(request.form['confirm_password']) < 1:
		error['NonEmptyFields'] =  "All Field inputs must not be empty"
		counter += 1
	if len(request.form['first_name']) < 2 or len(request.form['last_name']) < 2:
		error['TwoCharacters'] = "First and Last name must be at least 2 characters"
		counter += 1
	if request.form['first_name'].isalpha() == False or request.form['last_name'].isalpha() == False:
		error['OnlyAlphabets'] = "First and Last name must contain only alphabetic characters"
		counter += 1
	if len(request.form['password']) < 8:
		error['EightCharacters'] = "Password needs to be at least 8 characters"
		counter += 1
	if not EMAIL_REGEX.match(request.form['email']):
		error['InvalidEmail'] = "Invalid Email Address"
		counter += 1
	if not PASSWORD_REGEX.match(request.form['password']):
		error['InvalidPassword'] = "Password requires one uppercase letter and one number"
		counter += 1
	if request.form['password'] != request.form['confirm_password']:
		error['ConfirmPassword'] = "Confirm password does not match password"
		counter += 1
	if counter == 0:
		password = request.form['password']
		pw_hash = bcrypt.generate_password_hash(password)
		query = "INSERT INTO users (first_name, last_name, email, password, created_at, updated_at) VALUES (:first_name, :last_name, :email, :password, NOW(), NOW())"
		data = {
	             'first_name': request.form['first_name'], 
	             'last_name':  request.form['last_name'],
	             'email': request.form['email'],
	             'password': pw_hash
	           }
		mysql.query_db(query, data)

		user_query_login = "SELECT * FROM users WHERE email = :email LIMIT 1"
		query_data_login = { 'email': request.form['email'] }
		user_login = mysql.query_db(user_query_login, query_data_login)
		session['login'] = user_login[0]['id']
		return redirect('/thewall')
	else:
		return render_template("login.html", error_messages = error)

@app.route('/login', methods=['POST'])
def login():
	global counter
	counter = False
	error = {}
	email = request.form['email']
	password = request.form['password']
	user_query = "SELECT * FROM users WHERE email = :email LIMIT 1"
	query_data = { 'email': email }
	user = mysql.query_db(user_query, query_data)
	if user:
		if bcrypt.check_password_hash(user[0]['password'], password):
			session['login'] = user[0]['id']
			return redirect('/thewall')
		else:
			error["IncorrectLogin"] = "Incorrect Password"
			return render_template('login.html', login_error = error)
	else:
		flash("No such email!", "error")
		error["NoEmail"] = "Entered Email Not in Database"
		return render_template('login.html', login_error = error)

@app.route('/thewall')
def index():
	if session['login'] == 0:
		return redirect('/')
	else:
		query = "SELECT users.email, messages.id, messages.message, messages.created_at, users.first_name, users.last_name, DATE_FORMAT(messages.created_at, '%M %D %Y %H:%i') AS created_time, messages.user_id FROM users JOIN messages ON users.id = messages.user_id ORDER BY messages.created_at DESC"                           # define your query
		message = mysql.query_db(query)   
		addThirtyMin = timedelta(minutes = 90)
		currentTime = datetime.now()
		# and current_time > message['created_at'] + add_thirtymin
		querycomment = "SELECT *, DATE_FORMAT(comments.created_at, '%M %D %Y %H:%i') AS comment_time FROM users JOIN comments ON users.id = comments.user_id ORDER BY comments.created_at"
		comments = mysql.query_db(querycomment)
		return render_template('thewall.html', all_messages=message, current_time = currentTime, add_thirtymin = addThirtyMin, all_comments = comments)

@app.route('/postmessage', methods = ['POST'])
def postmessage():
	query = "INSERT INTO messages (message, created_at, updated_at, user_id) VALUES (:message , Now(), Now(), :id)" 
	data = {
		'message': request.form['message'],
		'id': session['login']
	}
	mysql.query_db(query, data)
	return redirect('/thewall')

@app.route('/postcomment/<id>', methods = ['POST'])
def postcomment(id):
	query = "INSERT INTO comments (comment, created_at, updated_at, user_id, message_id) VALUES (:comment , Now(), Now(), :id, :messageid)" 
	data = {
		'comment': request.form['comment'],
		'id': session['login'],
		'messageid': id
	}
	mysql.query_db(query, data)
	return redirect('/thewall')

@app.route('/logout', methods = ['POST'])
def logout():
	session['login'] = 0
	print session['login']
	return redirect('/')

@app.route('/delete/<id>', methods = ['POST'])
def delete(id):
    query = "DELETE FROM messages WHERE messages.id = :id"
    data = {'id': id}
    mysql.query_db(query, data)
    query2 = "DELETE FROM comments WHERE "
    return redirect('/thewall')

@app.route('/deletecomment/<id>', methods = ['POST'])
def deletecomment(id):
    query = "DELETE FROM comments WHERE comments.id = :id"
    data = {'id': id}
    mysql.query_db(query, data)
    return redirect('/thewall')

app.run(debug=True) # run our server


