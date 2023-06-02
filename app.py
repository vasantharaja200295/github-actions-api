import hashlib
import os
import sqlite3
import uuid

from flask import Flask, render_template, request, redirect

app = Flask(__name__)


def __init__(self):
    connection = sqlite3.connect('users.db')
    c = connection.cursor()
    connection.commit()


def generate_api_key():
    return hashlib.sha256(os.urandom(32)).hexdigest()


@app.route('/')
def main():
    return render_template('index.html')


@app.route('/login', methods=['GET', "POST"])
def login():
    connection = sqlite3.connect('users.db')
    c = connection.cursor()

    if request.method == "POST":
        username = request.form.get('username')
        password = request.form.get('password')

        c.execute(f"select * from users where username='{username}'")
        res = c.fetchone()
        connection.close()
        currentPassword = hashlib.sha256(password.encode()).hexdigest()
        if res[2] == currentPassword:
            return redirect(f'profile/{res[0]}')
        else:
            return render_template('login.html', op="Invalid Username or Password!")

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    connection = sqlite3.connect('users.db')
    c = connection.cursor()

    if request.method == 'POST':
        username = request.form.get("username")
        password = request.form.get('password')
        con_password = request.form.get('conform_password')

        if username == "":
            return render_template('register.html', op="Enter Username")
        if password == "":
            return render_template('register.html', op="Enter Password")
        if password != con_password:
            return render_template('register.html', op="passwords not same!")

        c.execute(f"select * from users where username='{username}'")
        res = c.fetchone()
        api_key = generate_api_key()

        if res:
            return render_template('register.html', op="User already exist please Login")
        else:
            currentPassword = hashlib.sha256(password.encode()).hexdigest()
            user_id = uuid.uuid4().hex
            query = f"insert into users(user_id,username, password, api_key) values('{user_id}','{username}', '{currentPassword}','{api_key}')"
            c.execute(query)
            connection.commit()
            connection.close()
            return render_template('register.html', op="User successfully created please Login!")

    return render_template('register.html')


@app.route('/profile/<userid>', methods=['GET', 'POST'])
def profile(userid):
    user_data = {}
    connection = sqlite3.connect('users.db')
    c = connection.cursor()
    query = f'''
        SELECT Users.user_id, Users.username, Users.api_key , github_keys.github_auth_key, github_keys.expiry_date
        FROM Users
        LEFT JOIN github_keys ON Users.user_id = github_keys.user_id where Users.user_id = '{userid}'
    '''
    c.execute(query)
    row = c.fetchone()
    user_data['user_id'], user_data['username'], user_data['api_key'], user_data['github_key'], user_data[
        'expiry'] = row

    connection.commit()

    if request.method == 'POST':
        github_key = request.form.get('authkey')
        expiry = request.form.get('expiry')

        if github_key != "" and expiry != "":
            c.execute('''
                SELECT COUNT(*) FROM github_keys
                WHERE user_id = ? AND github_auth_key = ?
            ''', ('your_user_id', 'your_github_auth_key'))

            row_count = c.fetchone()[0]

            # If the row doesn't exist, insert it
            if row_count == 0:
                c.execute('''
                    INSERT INTO github_keys (user_id, github_auth_key, expiry_date)
                    VALUES (?, ?, ?)
                ''', (userid, github_key, expiry))

                query = f'''
                    SELECT Users.user_id, Users.username, Users.api_key , github_keys.github_auth_key, github_keys.expiry_date
                    FROM Users
                    LEFT JOIN github_keys ON Users.user_id = github_keys.user_id where Users.user_id = '{userid}'
                    '''
                c.execute(query)
                row = c.fetchone()
                user_data['user_id'], user_data['username'], user_data['api_key'], user_data['github_key'], user_data[
                    'expiry'] = row
                return render_template('profile.html', user_data=user_data)

            connection.commit()

    return render_template('profile.html', user_data=user_data)


if __name__ == "__main__":
    app.run(debug=True)
