import urllib
import uuid
from flask import Flask, render_template, request, redirect, url_for, session, make_response
from flask_mail import Mail, Message
import re
import hashlib
import datetime
import os
import math
import json
from flask_mysql_connector import MySQL

app = Flask(__name__)

# Change this to your secret key (can be anything, it's for extra protection)
app.secret_key = 'secretWJT'

# App Settings
app.config['threaded'] = True

# Enter your database connection details below
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'Evenodd!512'
app.config['MYSQL_DATABASE'] = 'pythonlogin_advanced'

# Enter your email server details below, the following details uses the gmail smtp server (requires gmail account)
app.config['MAIL_SERVER']= 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = 'wallytauriac@gmail.com'
app.config['MAIL_PASSWORD'] = 'Evenodd!512'
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True

# Enter your domain name below
app.config['DOMAIN'] = 'http://gmail.com'

# Intialize MySQL
mysql = MySQL(app)

# Intialize Mail
mail = Mail(app)

# The list of roles
roles_list = ['Admin', 'Member']

# http://localhost:5000/pythonlogin/ - this will be the login page, we need to use both GET and POST requests
# @app.route('/pythonlogin/', methods=['GET', 'POST'])
@app.route('/', methods=['GET', 'POST'])
def login():
    # Redirect user to home page if logged-in
    if loggedin():
        return redirect(url_for('home'))
    # Output message if something goes wrong...
    msg = 'Not logged in'
    # Retrieve the settings
    settings = get_settings()
    # Check if "username" and "password" POST requests exist (user submitted form)
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'token' in request.form:
        # Bruteforce protection
        login_attempts_res = login_attempts(False)
        if settings['brute_force_protection']['value'] == 'true' and login_attempts_res and login_attempts_res['attempts_left'] <= 1:
            return 'You cannot login right now! Please try again later!'
        # Create variables for easy access
        username = request.form['username']
        password = request.form['password']
        token = request.form['token']
        # Retrieve the hashed password
        hash = password + app.secret_key
        #hashed_password = hashlib.sha256(password.encode("utf-8")).hexdigest()
        hash = hashlib.sha1(hash.encode())
        password = hash.hexdigest();
        # Check if account exists using MySQL
        conn = mysql.connection
        cursor = conn.cursor()

        cursor.execute('SELECT * FROM accounts WHERE username = %s AND password = %s', (username, password,))
        # Fetch one record and return result
        account = cursor.fetchone()
        # If account exists in accounts table in out database
        if account:
            # Check if account is activated
            if settings['account_activation']['value'] == 'true' and account['activation_code'] != 'activated' and account['activation_code'] != '':
                return 'Please activate your account to login!'
            # CSRF protection, form token should match the session token
            if settings['csrf_protection']['value'] == 'true' and str(token) != str(session['token']):
                return 'Invalid token!'
            # Two-factor
            if settings['twofactor_protection']['value'] == 'true' and account['ip'] != request.environ['REMOTE_ADDR']:
                session['tfa_id'] = account['id']
                session['tfa_email'] = account['email']
                return 'tfa: twofactor'
            # Create session data, we can access this data in other routes
            session['loggedin'] = True
            # session['id'] = account['id']
            session['id'] = account[0]
            # session['username'] = account['username']
            session['username'] = account[1]
            # session['role'] = account['role']
            session['role'] = account[4]
            # Reset the attempts left
            cursor.execute('DELETE FROM login_attempts WHERE ip_address = %s', (request.environ['REMOTE_ADDR'],))
            mysql.connection.commit()
            # If the user checked the remember me checkbox...
            if 'rememberme' in request.form:
                rememberme_code = account['rememberme']
                if not rememberme_code:
                    # Create hash to store as cookie
                    rememberme_code = account['username'] + request.form['password'] + app.secret_key
                    rememberme_code = hashlib.sha1(rememberme_code.encode())
                    rememberme_code = rememberme_code.hexdigest()
                # the cookie expires in 90 days
                expire_date = datetime.datetime.now() + datetime.timedelta(days=90)
                resp = make_response('Success', 200)
                resp.set_cookie('rememberme', rememberme_code, expires=expire_date)
                # Update rememberme in accounts table to the cookie hash
                cursor.execute('UPDATE accounts SET rememberme = %s WHERE id = %s', (rememberme_code, account['id'],))
                mysql.connection.commit()
                # Return response
                return resp
            # return 'Success'
            return redirect(url_for('home'))
        else:
            # Account doesnt exist or username/password incorrect
            if settings['brute_force_protection']['value'] == 'true':
                # Bruteforce protection enabled - update attempts left
                login_attempts_res = login_attempts();
                return 'Incorrect username/password! You have ' + str(login_attempts_res['attempts_left']) + ' attempts remaining!'
            else:
                return 'Incorrect username/password!'
    # Generate random token that will prevent CSRF attacks
    token = uuid.uuid4()
    session['token'] = token
    # Show the login form with message (if any)
    return render_template('index.html', msg=msg, token=token, settings=settings)

# http://localhost:5000/pythinlogin/register - this will be the registration page, we need to use both GET and POST requests
@app.route('/pythonlogin/register', methods=['GET', 'POST'])
def register():
    # Redirect user to home page if logged-in
    if loggedin():
        return redirect(url_for('home'))
    # Output message variable
    msg = ''
    # Retrieve the settings
    settings = get_settings()
    # Check if "username", "password", "cpassword" and "email" POST requests exist (user submitted form)
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'cpassword' in request.form and 'email' in request.form:
        # Create variables for easy access
        username = request.form['username']
        password = request.form['password']
        cpassword = request.form['cpassword']
        email = request.form['email']
        role = 'Member'
        # Hash the password
        hash = password + app.secret_key
        hash = hashlib.sha1(hash.encode())
        hashed_password = hash.hexdigest();
        # Check if account exists using MySQL

        conn = mysql.connection
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM accounts WHERE username = %s', (username,))
        account = cursor.fetchone()
        # reCAPTCHA
        if settings['recaptcha']['value'] == 'true':
            if 'g-recaptcha-response' not in request.form:
                return 'Invalid captcha!'
            req = urllib.request.Request('https://www.google.com/recaptcha/api/siteverify', urllib.parse.urlencode({ 'response': request.form['g-recaptcha-response'], 'secret': settings['recaptcha_secret_key']['value'] }).encode())
            response_json = json.loads(urllib.request.urlopen(req).read().decode())
            if not response_json['success']:
                return 'Invalid captcha!'
        # Validation
        if account:
            return 'Account already exists!'
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            return 'Invalid email address!'
        elif not re.match(r'[A-Za-z0-9]+', username):
            return 'Username must contain only characters and numbers!'
        elif not username or not password or not cpassword or not email:
            return 'Please fill out the form!'
        elif password != cpassword:
            return 'Passwords do not match!'
        elif len(username) < 5 or len(username) > 20:
            return 'Username must be between 5 and 20 characters long!'
        elif len(password) < 5 or len(password) > 20:
            return 'Password must be between 5 and 20 characters long!'
        elif settings['account_activation']['value'] == 'true':
            # Account activation enabled
            # Generate a random unique id for activation code
            activation_code = uuid.uuid4()
            # Insert account into database
            cursor.execute('INSERT INTO accounts (username, password, email, activation_code, role, ip) VALUES (%s, %s, %s, %s, %s, %s)', (username, hashed_password, email, activation_code, role, request.environ['REMOTE_ADDR'],))
            mysql.connection.commit()
            # Create new message
            email_info = Message('Account Activation Required', sender = app.config['MAIL_USERNAME'], recipients = [email])
            # Activate Link URL
            activate_link = app.config['DOMAIN'] + url_for('activate', email=email, code=str(activation_code))
            # Define and render the activation email template
            email_info.body = render_template('activation-email-template.html', link=activate_link)
            email_info.html = render_template('activation-email-template.html', link=activate_link)
            # send activation email to user
            mail.send(email_info)
            # Output message
            return 'Please check your email to activate your account!'
        else:
            # Account doesnt exists and the form data is valid, now insert new account into accounts table
            cursor.execute('INSERT INTO accounts (username, password, email, activation_code, role, ip) VALUES (%s, %s, %s, "activated", %s, %s)', (username, hashed_password, email, role, request.environ['REMOTE_ADDR'],))
            mysql.connection.commit()
            # Auto login if the setting is enabled
            if settings['auto_login_after_register']['value'] == 'true':
                session['loggedin'] = True
                session['id'] = cursor.lastrowid
                session['username'] = username
                session['role'] = role
                return 'autologin'
            # Output message
            return 'You have registered! You can now login!'
    elif request.method == 'POST':
        # Form is empty... (no POST data)
        return 'Please fill out the form!'
    # Render registration form with message (if any)
    return render_template('register.html', msg=msg, settings=settings)

# http://localhost:5000/pythinlogin/activate/<email>/<code> - this page will activate a users account if the correct activation code and email are provided
@app.route('/pythonlogin/activate/<string:email>/<string:code>', methods=['GET'])
def activate(email, code):
    # Output message variable
    msg = 'Account doesn\'t exist with that email or the activation code is incorrect!'
    # Check if the email and code provided exist in the accounts table

    conn = mysql.connection
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM accounts WHERE email = %s AND activation_code = %s', (email, code,))
    account = cursor.fetchone()
    # If account exists
    if account:
        # account exists, update the activation code to "activated"
        cursor.execute('UPDATE accounts SET activation_code = "activated" WHERE email = %s AND activation_code = %s', (email, code,))
        mysql.connection.commit()
        # automatically log the user in and redirect to the home page
        session['loggedin'] = True
        session['id'] = account['id']
        session['username'] = account['username']
        session['role'] = account['role']
        # Redirect to home page
        return redirect(url_for('home'))
    # Render activation template
    return render_template('activate.html', msg=msg)

# http://localhost:5000/pythinlogin/home - this will be the home page, only accessible for loggedin users
@app.route('/pythonlogin/home')
def home():
    # Check if user is loggedin
    if loggedin():
        # User is loggedin, render the home page
        return render_template('home.html', username=session['username'], role=session['role'])
    # User is not loggedin, redirect to login page
    return redirect(url_for('login'))

# http://localhost:5000/pythinlogin/profile - this will be the profile page, only accessible for loggedin users
@app.route('/pythonlogin/profile')
def profile():
    # Check if user is loggedin
    if loggedin():
        # Retrieve all account info from the database

        conn = mysql.connection
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM accounts WHERE id = %s', (session['id'],))
        account = cursor.fetchone()
        # Render the profile page along with the account info
        return render_template('profile.html', account=account, role=session['role'])
    # User is not loggedin, redirect to login page
    return redirect(url_for('login'))

# http://localhost:5000/pythinlogin/profile/edit - user can edit their existing details
@app.route('/pythonlogin/profile/edit', methods=['GET', 'POST'])
def edit_profile():
    # Check if user is loggedin
    if loggedin():
        # Output message
        msg = ''
        # Retrieve the settings
        settings = get_settings()
        # We need to retrieve additional account info from the database and populate it on the profile page

        conn = mysql.connection
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM accounts WHERE id = %s', (session['id'],))
        account = cursor.fetchone()
        # Check if "username", "password" and "email" POST requests exist (user submitted form)
        if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'email' in request.form:
            # Create variables for easy access
            username = request.form['username']
            password = request.form['password']
            cpassword = request.form['cpassword']
            email = request.form['email']
            # Retrieve account by the username
            cursor.execute('SELECT * FROM accounts WHERE username = %s', (username,))
            new_account = cursor.fetchone()
            # validation check
            if not re.match(r'[^@]+@[^@]+\.[^@]+', email):
                msg = 'Invalid email address!'
            elif not re.match(r'[A-Za-z0-9]+', username):
                msg = 'Username must contain only characters and numbers!'
            elif not username or not email:
                msg = 'Please fill out the form!'
            elif session['username'] != username and new_account:
                msg = 'Username already exists!'
            elif len(username) < 5 or len(username) > 20:
                msg = 'Username must be between 5 and 20 characters long!'
            elif password and (len(password) < 5 or len(password) > 20):
                msg = 'Password must be between 5 and 20 characters long!'
            elif password != cpassword:
                msg = 'Passwords do not match!'
            else:
                # Determine password
                current_password = account['password']
                # If new password provided
                if password:
                    # Hash the password
                    hash = password + app.secret_key
                    hash = hashlib.sha1(hash.encode())
                    current_password = hash.hexdigest();
                # update account with the new details
                cursor.execute('UPDATE accounts SET username = %s, password = %s, email = %s WHERE id = %s', (username, current_password, email, session['id'],))
                mysql.connection.commit()
                # Update session variables
                session['username'] = username
                session['email'] = email
                # retrieve updated acount
                cursor.execute('SELECT * FROM accounts WHERE id = %s', (session['id'],))
                account = cursor.fetchone()
                # Reactivate account if account acivation option enabled
                if settings['account_activation']['value'] == 'true':
                    # Generate a random unique id for activation code
                    activation_code = uuid.uuid4()
                    # Update activation code in database
                    cursor.execute('UPDATE accounts SET activation_code = %s WHERE id = %s', (activation_code, session['id'],))
                    mysql.connection.commit()
                    # Create new message
                    email_info = Message('Account Activation Required', sender = app.config['MAIL_USERNAME'], recipients = [email])
                    # Activate Link URL
                    activate_link = app.config['DOMAIN'] + url_for('activate', email=email, code=str(activation_code))
                    # Define and render the activation email template
                    email_info.body = render_template('activation-email-template.html', link=activate_link)
                    email_info.html = render_template('activation-email-template.html', link=activate_link)
                    # send activation email to user
                    mail.send(email_info)
                    # Output message
                    msg = 'You have changed your email address! You need to re-activate your account! You will be automatically logged-out.'
                else:
                    # Output message
                    msg = 'Account updated successfully!'
        # Render the profile page along with the account info
        return render_template('profile-edit.html', account=account, role=session['role'], msg=msg)
    # Redirect to the login page
    return redirect(url_for('login'))

# http://localhost:5000/pythinlogin/forgotpassword - user can use this page if they have forgotten their password
@app.route('/pythonlogin/forgotpassword', methods=['GET', 'POST'])
def forgotpassword():
    msg = ''
    # If forgot password form submitted
    if request.method == 'POST' and 'email' in request.form:
        # Capture input email
        email = request.form['email']
        # Define the connection cursor
        conn = mysql.connection
        cursor = conn.cursor()
        # Retrieve account info from database that's associated with the captured email
        cursor.execute('SELECT * FROM accounts WHERE email = %s', (email,))
        account = cursor.fetchone()
        # If account exists
        if account:
            # Generate unique reset ID
            reset_code = uuid.uuid4()
            # Update the reset column in the accounts table to reflect the generated ID
            cursor.execute('UPDATE accounts SET reset = %s WHERE email = %s', (reset_code, email,))
            mysql.connection.commit()
            # Create new email message
            email_info = Message('Password Reset', sender = app.config['MAIL_USERNAME'], recipients = [email])
            # Generate reset password link
            reset_link = app.config['DOMAIN'] + url_for('resetpassword', email = email, code = str(reset_code))
            # Email content
            email_info.body = 'Please click the following link to reset your password: ' + str(reset_link)
            email_info.html = '<p>Please click the following link to reset your password: <a href="' + str(reset_link) + '">' + str(reset_link) + '</a></p>'
            # Send mail
            mail.send(email_info)
            msg = 'Reset password link has been sent to your email!'
        else:
            msg = 'An account with that email does not exist!'
    # Render the forgot password template
    return render_template('forgotpassword.html', msg=msg)

# http://localhost:5000/pythinlogin/resetpassword/EMAIL/CODE - proceed to reset the user's password
@app.route('/pythonlogin/resetpassword/<string:email>/<string:code>', methods=['GET', 'POST'])
def resetpassword(email, code):
    msg = ''
    conn = mysql.connection
    cursor = conn.cursor()
    # Retrieve the account with the email and reset code provided from the GET request
    cursor.execute('SELECT * FROM accounts WHERE email = %s AND reset = %s', (email, code,))
    account = cursor.fetchone()
    # If account exists
    if account:
        # Check if the new password fields were submitted
        if request.method == 'POST' and 'npassword' in request.form and 'cpassword' in request.form:
            npassword = request.form['npassword']
            cpassword = request.form['cpassword']
            # Password fields must match
            if npassword == cpassword and npassword != "":
                # Hash new password
                hash = npassword + app.secret_key
                hash = hashlib.sha1(hash.encode())
                npassword = hash.hexdigest()
                # Update the user's password
                cursor.execute('UPDATE accounts SET password = %s, reset = "" WHERE email = %s', (npassword, email,))
                mysql.connection.commit()
                msg = 'Your password has been reset, you can now <a href="' + url_for('login') + '">login</a>!'
            else:
                msg = 'Passwords must match and must not be empty!'
        # Render the reset password template
        return render_template('resetpassword.html', msg=msg, email=email, code=code)
    return 'Invalid email and/or code!'

# http://localhost:5000/pythinlogin/twofactor - two-factor authentication
@app.route('/pythonlogin/twofactor', methods=['GET', 'POST'])
def twofactor():
    # Output message
    msg = ''
    conn = mysql.connection
    cursor = conn.cursor()
    # Verify the ID and email provided
    if 'tfa_email' in session and 'tfa_id' in session:
        # Retrieve the account
        cursor.execute('SELECT * FROM accounts WHERE id = %s AND email = %s', (session['tfa_id'], session['tfa_email'],))
        account = cursor.fetchone()
        # If account exists
        if account:
            # If the code param exists in the POST request form
            if request.method == 'POST' and 'code' in request.form:
                # If the user entered the correct code
                if request.form['code'] == account['tfa_code']:
                    # Get the user's IP address
                    ip = request.environ['REMOTE_ADDR']
                    # Update IP address in database
                    cursor.execute('UPDATE accounts SET ip = %s WHERE id = %s', (ip, account['id'],))
                    mysql.connection.commit()
                    # Clear TFA session variables
                    session.pop('tfa_email')
                    session.pop('tfa_id')
                    # Authenticate the user
                    session['loggedin'] = True
                    session['id'] = account['id']
                    session['username'] = account['username']
                    session['role'] = account['role']
                    # Redirect to home page
                    return redirect(url_for('home'))
                else:
                    msg = 'Incorrect code provided!'
            else:
                # Generate unique code
                code = str(uuid.uuid4()).upper()[:5]
                # Update code in database
                cursor.execute('UPDATE accounts SET tfa_code = %s WHERE id = %s', (code, account['id'],))
                mysql.connection.commit()
                # Create new message
                email_info = Message('Your Access Code', sender = app.config['MAIL_USERNAME'], recipients = [account['email']])
                # Define and render the twofactor email template
                email_info.body = render_template('twofactor-email-template.html', code=code)
                email_info.html = render_template('twofactor-email-template.html', code=code)
                # send twofactor email to user
                mail.send(email_info)
        else:
            msg = 'No email and/or ID provided!'
    else:
        msg = 'No email and/or ID provided!'
    # Render twofactor template
    return render_template('twofactor.html', msg=msg)

def login_attempts(update = True):
    conn = mysql.connection
    cursor = conn.cursor()
    # Get the user's IP address
    ip = request.environ['REMOTE_ADDR']
    # Get the current date
    now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    # Update attempts left
    if update:
        cursor.execute('INSERT INTO login_attempts (ip_address, `date`) VALUES (%s,%s) ON DUPLICATE KEY UPDATE attempts_left = attempts_left - 1, `date` = VALUES(`date`)', (ip, str(now),))
        mysql.connection.commit()
    # Retrieve the login attemmpts
    cursor.execute('SELECT * FROM login_attempts WHERE ip_address = %s', (ip,))
    login_attempts = cursor.fetchone()
    if login_attempts:
        # The date the attempts left expires (removed from database)
        expire = datetime.datetime.strptime(now, '%Y-%m-%d %H:%M:%S') + datetime.timedelta(days=1)
        # If current date is greater than expiration date
        if datetime.datetime.strptime(now, '%Y-%m-%d %H:%M:%S') > expire:
            # Delete the entry
            cursor.execute('DELETE FROM login_attempts WHERE id_address = %s', (ip, account['id'],))
            mysql.connection.commit()
            login_attempts = []
    return login_attempts

# http://localhost:5000/pythinlogin/logout - this will be the logout page
@app.route('/pythonlogin/logout')
def logout():
    # Remove session data, this will log the user out
    session.pop('loggedin', None)
    session.pop('id', None)
    session.pop('username', None)
    session.pop('role', None)
    # Remove cookie data "remember me"
    resp = make_response(redirect(url_for('login')))
    resp.set_cookie('rememberme', expires=0)
    return resp

# Check if logged in function, update session if cookie for "remember me" exists
def loggedin():
    conn = mysql.connection
    cursor = conn.cursor()
    # Check if user is logged-in
    if 'loggedin' in session:
        # Update last seen date
        cursor.execute('UPDATE accounts SET last_seen = NOW() WHERE id = %s', (session['id'],))
        mysql.connection.commit()
        return True
    elif 'rememberme' in request.cookies:
        # check if remembered, cookie has to match the "rememberme" field
        cursor.execute('SELECT * FROM accounts WHERE rememberme = %s', (request.cookies['rememberme'],))
        account = cursor.fetchone()
        if account:
            # update session variables
            session['loggedin'] = True
            session['id'] = account['id']
            session['username'] = account['username']
            session['role'] = account['role']
            return True
    # account not logged in return false
    return False

# ADMIN PANEL
# http://localhost:5000/pythonlogin/admin/ - admin dashboard, view new accounts, active accounts, statistics
@app.route('/pythonlogin/admin/', methods=['GET', 'POST'])
def admin():
    # Check if admin is logged-in
    if not admin_loggedin():
        return redirect(url_for('login'))
    conn = mysql.connection
    cursor = conn.cursor()
    # Retrieve new accounts for the current date
    cursor.execute('SELECT * FROM accounts WHERE cast(registered as DATE) = cast(now() as DATE) ORDER BY registered DESC')
    accounts = cursor.fetchall()
    # Get the total number of accounts
    cursor.execute('SELECT COUNT(*) AS total FROM accounts')
    accounts_total = cursor.fetchone()
    # Get the total number of active accounts (<1 month)
    cursor.execute('SELECT COUNT(*) AS total FROM accounts WHERE last_seen < date_sub(now(), interval 1 month)')
    inactive_accounts = cursor.fetchone()
    # Retrieve accounts created within 1 day from the current date
    cursor.execute('SELECT * FROM accounts WHERE last_seen > date_sub(now(), interval 1 day) ORDER BY last_seen DESC')
    active_accounts = cursor.fetchall()
    # Get the total number of inactive accounts
    cursor.execute('SELECT COUNT(*) AS total FROM accounts WHERE last_seen > date_sub(now(), interval 1 month)')
    active_accounts2 = cursor.fetchone()
    # Render admin dashboard template
    return render_template('admin/dashboard.html', accounts=accounts, selected='dashboard', selected_child='view', accounts_total=accounts_total['total'], inactive_accounts=inactive_accounts['total'], active_accounts=active_accounts, active_accounts2=active_accounts2['total'], time_elapsed_string=time_elapsed_string)

# http://localhost:5000/pythonlogin/admin/accounts - view all accounts
@app.route('/pythonlogin/admin/accounts/<string:msg>/<string:search>/<string:status>/<string:activation>/<string:role>/<string:order>/<string:order_by>/<int:page>', methods=['GET', 'POST'])
@app.route('/pythonlogin/admin/accounts', methods=['GET', 'POST'], defaults={'msg': '', 'search' : '', 'status': '', 'activation': '', 'role': '', 'order': 'DESC', 'order_by': '', 'page': 1})
def admin_accounts(msg, search, status, activation, role, order, order_by, page):
    # Check if admin is logged-in
    if not admin_loggedin():
        return redirect(url_for('login'))
    # Params validation
    msg = '' if msg == 'n0' else msg
    search = '' if search == 'n0' else search
    status = '' if status == 'n0' else status
    activation = '' if activation == 'n0' else activation
    role = '' if role == 'n0' else role
    order = 'DESC' if order == 'DESC' else 'ASC'
    order_by_whitelist = ['id','username','email','activation_code','role','registered','last_seen']
    order_by = order_by if order_by in order_by_whitelist else 'id'
    results_per_page = 20
    param1 = (page - 1) * results_per_page
    param2 = results_per_page
    param3 = '%' + search + '%'
    # SQL where clause
    where = '';
    where += 'WHERE (username LIKE %s OR email LIKE %s) ' if search else ''
    # Add filters
    if status == 'active':
        where += 'AND last_seen > date_sub(now(), interval 1 month) ' if where else 'WHERE last_seen > date_sub(now(), interval 1 month) '
    if status == 'inactive':
        where += 'AND last_seen < date_sub(now(), interval 1 month) ' if where else 'WHERE last_seen < date_sub(now(), interval 1 month) '
    if activation == 'pending':
        where += 'AND activation_code != "activated" ' if where else 'WHERE activation_code != "activated" '
    if role:
        where += 'AND role = %s ' if where else 'WHERE role = %s '
    # Params array and append specified params
    params = []
    if search:
        params.append(param3)
        params.append(param3)
    if role:
        params.append(role)
    # Fetch the total number of accounts
    conn = mysql.connection
    cursor = conn.cursor()
    cursor.execute('SELECT COUNT(*) AS total FROM accounts ' + where, params)
    accounts_total = cursor.fetchone()
    # Append params to array
    params.append(param1)
    params.append(param2)
    # Retrieve all accounts from the database
    cursor.execute('SELECT * FROM accounts ' + where + ' ORDER BY ' + order_by + ' ' + order + ' LIMIT %s,%s', params)
    accounts = cursor.fetchall()
    # Determine the URL
    url = url_for('admin_accounts') + '/n0/' + (search if search else 'n0') + '/' + (status if status else 'n0') + '/' + (activation if activation else 'n0') + '/' + (role if role else 'n0')
    # Handle output messages
    if msg:
        if msg == 'msg1':
            msg = 'Account created successfully!';
        if msg == 'msg2':
            msg = 'Account updated successfully!';
        if msg == 'msg3':
            msg = 'Account deleted successfully!'
    # Render the accounts template
    return render_template('admin/accounts.html', accounts=accounts, selected='accounts', selected_child='view', msg=msg, page=page, search=search, status=status, activation=activation, role=role, order=order, order_by=order_by, results_per_page=results_per_page, accounts_total=accounts_total['total'], math=math, url=url, time_elapsed_string=time_elapsed_string)

# http://localhost:5000/pythonlogin/admin/roles - view account roles
@app.route('/pythonlogin/admin/roles', methods=['GET', 'POST'])
def admin_roles():
    # Check if admin is logged-in
    if not admin_loggedin():
        return redirect(url_for('login'))
    # Set the connection cursor
    conn = mysql.connection
    cursor = conn.cursor()
    # Select and group roles from the accounts table
    cursor.execute('SELECT role, COUNT(*) as total FROM accounts GROUP BY role')
    roles = cursor.fetchall()
    new_roles = {}
    # Update the structure
    for role in roles:
        new_roles[role['role']] = role['total']
    for role in roles_list:
        if not new_roles[role]:
            new_roles[role] = 0
    # Get the total number of active roles
    cursor.execute('SELECT role, COUNT(*) as total FROM accounts WHERE last_seen > date_sub(now(), interval 1 month) GROUP BY role')
    roles_active = cursor.fetchall()
    new_roles_active = {}
    for role in roles_active:
        new_roles_active[role['role']] = role['total']
    # Get the total number of inactive roles
    cursor.execute('SELECT role, COUNT(*) as total FROM accounts WHERE last_seen < date_sub(now(), interval 1 month) GROUP BY role')
    roles_inactive = cursor.fetchall()
    new_roles_inactive = {}
    for role in roles_inactive:
        new_roles_inactive[role['role']] = role['total']
    # Render he roles template
    return render_template('admin/roles.html', selected='roles', selected_child='', enumerate=enumerate, roles=new_roles, roles_active=new_roles_active, roles_inactive=new_roles_inactive)

# http://localhost:5000/pythonlogin/admin/settings - manage settings
@app.route('/pythonlogin/admin/settings/<string:msg>', methods=['GET', 'POST'])
@app.route('/pythonlogin/admin/settings', methods=['GET', 'POST'], defaults={'msg': ''})
def admin_settings(msg):
    # Check if admin is logged-in
    if not admin_loggedin():
        return redirect(url_for('login'))
    # Get settings
    settings = get_settings()
    # Set the connection cursor
    conn = mysql.connection
    cursor = conn.cursor()
    # If user submitted the form
    if request.method == 'POST' and request.form:
        # Retrieve the form data
        data = request.form
        # Iterate the form data
        for key, value in data.items():
            # Check if checkbox is checked
            if 'true' in request.form.getlist(key):
                value = 'true'
            # Convert boolean values to lowercase
            value = value.lower() if value.lower() in ['true', 'false'] else value
            # Update setting
            cursor.execute('UPDATE settings SET setting_value = %s WHERE setting_key = %s', (value,key,))
            mysql.connection.commit()
        # Redirect and output message
        return redirect(url_for('admin_settings', msg='msg1'))
    # Handle output messages
    if msg and msg == 'msg1':
        msg = 'Settings updated successfully!';
    else:
        msg = ''
    # Render the settings template
    return render_template('admin/settings.html', selected='settings', selected_child='', msg=msg, settings=settings, settings_format_tabs=settings_format_tabs, settings_format_form=settings_format_form)

# http://localhost:5000/pythonlogin/admin/about - view the about page
@app.route('/pythonlogin/admin/about', methods=['GET', 'POST'])
def admin_about():
    # Check if admin is logged-in
    if not admin_loggedin():
        return redirect(url_for('login'))
    # Render the about template
    return render_template('admin/about.html', selected='about', selected_child='')

# http://localhost:5000/pythonlogin/admin/accounts/delete/<id> - delete account
@app.route('/pythonlogin/admin/accounts/delete/<int:id>', methods=['GET', 'POST'])
@app.route('/pythonlogin/admin/accounts/delete', methods=['GET', 'POST'], defaults={'id': None})
def admin_delete_account(id):
    # Check if admin is logged-in
    if not admin_loggedin():
        return redirect(url_for('login'))
    # Set the database connection cursor
    conn = mysql.connection
    cursor = conn.cursor()
    # Delete account from database by the id get request param
    cursor.execute('DELETE FROM accounts WHERE id = %s', (id,))
    mysql.connection.commit()
    # Redirect to accounts page and output message
    return redirect(url_for('admin_accounts', msg='msg3', activation='n0', order='id', order_by='DESC', page=1, role='n0', search='n0', status='n0'))

# http://localhost:5000/pythonlogin/admin/account/<optional:id> - create or edit account
@app.route('/pythonlogin/admin/account/<int:id>', methods=['GET', 'POST'])
@app.route('/pythonlogin/admin/account', methods=['GET', 'POST'], defaults={'id': None})
def admin_account(id):
    # Check if admin is logged-in
    if not admin_loggedin():
        return redirect(url_for('login'))
    # Default page (Create/Edit)
    page = 'Create'
    conn = mysql.connection
    cursor = conn.cursor()
    # Default input account values
    account = {
        'username': '',
        'password': '',
        'email': '',
        'activation_code': '',
        'rememberme': '',
        'role': 'Member',
        'registered': str(datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')),
        'last_seen': str(datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
    }
    roles = ['Member', 'Admin']
    # GET request ID exists, edit account
    if id:
        # Edit an existing account
        page = 'Edit'
        # Retrieve account by ID with the GET request ID
        cursor.execute('SELECT * FROM accounts WHERE id = %s', (id,))
        account = cursor.fetchone()
        # If user submitted the form
        if request.method == 'POST' and 'submit' in request.form:
            # update account
            password = account['password']
            # If password exists in POST request
            if request.form['password']:
                 hash = request.form['password'] + app.secret_key
                 hash = hashlib.sha1(hash.encode())
                 password = hash.hexdigest()
            # Update account details
            cursor.execute('UPDATE accounts SET username = %s, password = %s, email = %s, activation_code = %s, rememberme = %s, role = %s, registered = %s, last_seen = %s WHERE id = %s', (request.form['username'],password,request.form['email'],request.form['activation_code'],request.form['rememberme'],request.form['role'],request.form['registered'],request.form['last_seen'],id,))
            mysql.connection.commit()
            # Redirect to admin accounts page
            return redirect(url_for('admin_accounts', msg='msg2', activation='n0', order='id', order_by='DESC', page=1, role='n0', search='n0', status='n0'))
        if request.method == 'POST' and 'delete' in request.form:
            # delete account
            return redirect(url_for('admin_delete_account', id=id))
    if request.method == 'POST' and request.form['submit']:
        # Create new account, hash password
        hash = request.form['password'] + app.secret_key
        hash = hashlib.sha1(hash.encode())
        password = hash.hexdigest();
        # Insert account into database
        cursor.execute('INSERT INTO accounts (username,password,email,activation_code,rememberme,role,registered,last_seen) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)', (request.form['username'],password,request.form['email'],request.form['activation_code'],request.form['rememberme'],request.form['role'],request.form['registered'],request.form['last_seen'],))
        mysql.connection.commit()
        # Redirect to the admin accounts page and output message
        return redirect(url_for('admin_accounts', msg='msg1', activation='n0', order='id', order_by='DESC', page=1, role='n0', search='n0', status='n0'))
    # Render the admin account template
    return render_template('admin/account.html', account=account, selected='accounts', selected_child='manage', page=page, roles=roles, datetime=datetime.datetime, str=str)

# http://localhost:5000/pythonlogin/admin/emailtemplate - admin email templates page, manage email templates
@app.route('/pythonlogin/admin/emailtemplate/<string:msg>', methods=['GET', 'POST'])
@app.route('/pythonlogin/admin/emailtemplate', methods=['GET', 'POST'], defaults={'msg': ''})
def admin_emailtemplate(msg):
    # Check if admin is logged-in
    if not admin_loggedin():
        return redirect(url_for('login'))
    # Get the template directory path
    template_dir = os.path.join(os.path.dirname(__file__), 'templates')
    # Update the template file on save
    if request.method == 'POST':
        # Update activation template
        activation_email_template = request.form['activation_email_template'].replace('\r', '')
        open(template_dir + '/activation-email-template.html', mode='w', encoding='utf-8').write(activation_email_template)
        # Update twofactor template
        twofactor_email_template = request.form['twofactor_email_template'].replace('\r', '')
        open(template_dir + '/twofactor-email-template.html', mode='w', encoding='utf-8').write(twofactor_email_template)
        # Redirect and output success message
        return redirect(url_for('admin_emailtemplate', msg='msg1'))
    # Read the activation email template
    activation_email_template = open(template_dir + '/activation-email-template.html', mode='r', encoding='utf-8').read()
    # Read the twofactor email template
    twofactor_email_template = open(template_dir + '/twofactor-email-template.html', mode='r', encoding='utf-8').read()
    # Handle output messages
    if msg and msg == 'msg1':
        msg = 'Email templates updated successfully!';
    else:
        msg = ''
    # Render template
    return render_template('admin/emailtemplates.html', selected='emailtemplate', selected_child='', msg=msg, activation_email_template=activation_email_template, twofactor_email_template=twofactor_email_template)

# Admin logged-in check function
def admin_loggedin():
    if loggedin() and session['role'] == 'Admin':
        # admin logged-in
        return True
    # admin not logged-in return false
    return False

# format settings key
def settings_format_key(key):
    key = key.lower().replace('_', ' ').replace('url', 'URL').replace('db ', 'Database ').replace(' pass', ' Password').replace(' user', ' Username')
    return key.title()

# Format settings variables in HTML format
def settings_format_var_html(key, value):
    html = ''
    type = 'text'
    type = 'password' if 'pass' in key else type
    type = 'checkbox' if value.lower() in ['true', 'false'] else type
    checked = ' checked' if value.lower() == 'true' else ''
    html += '<label for="' + key + '">' + settings_format_key(key) + '</label>'
    if (type == 'checkbox'):
        html += '<input type="hidden" name="' + key + '" value="false">'
    html += '<input type="' + type + '" name="' + key + '" id="' + key + '" value="' + value + '" placeholder="' + settings_format_key(key) + '"' + checked + '>'
    return html

# Format settings tabs
def settings_format_tabs(tabs):
    html = ''
    html += '<div class="tabs">'
    html += '<a href="#" class="active">General</a>'
    for tab in tabs:
        html += '<a href="#">' + tab + '</a>'
    html += '</div>'
    return html

# Format settings form
def settings_format_form(settings):
    html = ''
    html += '<div class="tab-content active">'
    category = ''
    for setting in settings:
        if category != '' and category != settings[setting]['category']:
            html += '</div><div class="tab-content">'
        category = settings[setting]['category']
        html += settings_format_var_html(settings[setting]['key'], settings[setting]['value'])
    html += '</div>'
    return html

# Get settings from database
def get_settings():
    conn = mysql.connection
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM settings ORDER BY id')
    settings = cursor.fetchall()

    settings2 = {}
    for setting in settings:
        settings2[setting[1]] = {'key': setting[1], 'value': setting[2], 'category': setting[3]}
    return settings2

# Format datetime
def time_elapsed_string(dt):
    d = datetime.datetime.strptime(str(dt), '%Y-%m-%d %H:%M:%S')
    dd = datetime.datetime.now()
    d = d.timestamp() - dd.timestamp()
    d = datetime.timedelta(seconds=d)
    timeDelta = abs(d)
    if timeDelta.days > 0:
        if timeDelta.days == 1:
            return '1 day ago'
        else:
            return '%s days ago' % timeDelta.days
    elif round(timeDelta.seconds / 3600) > 0:
        if round(timeDelta.seconds / 3600) == 1:
            return '1 hour ago'
        else:
            return '%s hours ago' % round(timeDelta.seconds / 3600)
    elif round(timeDelta.seconds / 60) < 2:
        return '1 minute ago'
    else:
        return '%s minutes ago' % round(timeDelta.seconds / 60)


if __name__ == '__main__':
    app.debug = True
    app.run()

