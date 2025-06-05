from flask import Flask, render_template, request, redirect, session, url_for
from pymongo import MongoClient

app = Flask(__name__)
app.secret_key = "your_secret_key"  # Change this in production

# MongoDB connection
client = MongoClient("mongodb://localhost:27017")
db = client['caferadar']
users_col = db['users']


@app.route('/')
def home():
    return redirect('/login')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if users_col.find_one({'username': username}):
            return "Username already exists!"
        users_col.insert_one({'username': username, 'password': password, 'role': 'user'})
        return redirect('/login')
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = users_col.find_one({'username': username, 'password': password})
        if user:
            session['username'] = user['username']
            session['role'] = user['role']
            return redirect('/dashboard')
        return "Invalid credentials."
    return render_template('login.html')


@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect('/login')

    if session['role'] == 'admin':
        users = users_col.find({}, {'_id': 0, 'username': 1, 'role': 1})
        return render_template('admin_dashboard.html', users=users)
    else:
        return render_template('user_dashboard.html', username=session['username'])


@app.route('/profile')
def profile():
    if 'username' not in session:
        return redirect('/login')
    return render_template('profile.html', username=session['username'], role=session['role'])

@app.route('/admin/users')
def admin_users():
    if 'username' not in session or session['role'] != 'admin':
        return redirect('/login')

    all_users = users_col.find({}, {'_id': 0, 'username': 1, 'role': 1})
    return render_template('admin_users.html', users=all_users)


@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')


if __name__ == '__main__':
    app.run(debug=True)
