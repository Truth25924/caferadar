from flask import Flask, render_template, request, redirect, session, url_for, make_response, flash, jsonify
import sqlite3
from contextlib import closing
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
import os
from datetime import datetime

app = Flask(__name__)
app.secret_key = "your_secret_key"  

def init_db():
    with closing(sqlite3.connect('caferadar.db')) as conn:
        with conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    first_name TEXT NOT NULL,
                    last_name TEXT NOT NULL,
                    email TEXT NOT NULL,
                    gender TEXT NOT NULL,
                    birthday TEXT NOT NULL,
                    contactnumber TEXT,
                    role TEXT NOT NULL
                )
            ''')
            conn.execute('''
                CREATE TABLE IF NOT EXISTS cafes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    description TEXT,
                    maps_url TEXT,
                    address TEXT,
                    image_url TEXT
                )
            ''')
            conn.execute('''
                CREATE TABLE IF NOT EXISTS ratings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cafe_id INTEGER,
                    user TEXT,
                    rating INTEGER,
                    timestamp TEXT,
                    FOREIGN KEY (cafe_id) REFERENCES cafes(id)
                )
            ''')
            conn.execute('''
                CREATE TABLE IF NOT EXISTS comments (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cafe_id INTEGER,
                    user TEXT,
                    comment TEXT,
                    timestamp TEXT,
                    rating INTEGER,
                    FOREIGN KEY (cafe_id) REFERENCES cafes(id)
                )
            ''')
            conn.execute('''
            CREATE TABLE IF NOT EXISTS cafe_recommendations (
            cafe_id INTEGER PRIMARY KEY,
            is_recommended INTEGER DEFAULT 0,
            FOREIGN KEY (cafe_id) REFERENCES cafes(id)
                )
            ''')

try:
    with sqlite3.connect('caferadar.db') as conn:
        conn.execute('ALTER TABLE users ADD COLUMN profile_pic_url TEXT')
except sqlite3.OperationalError:
    # Column already exists
    pass


UPLOAD_FOLDER = os.path.join('static', 'uploads')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session or session.get('role') != 'admin':
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


@app.after_request
def add_cache_control(response):
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, post-check=0, pre-check=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "-1"
    return response

def get_cafes_with_details():
    with sqlite3.connect('caferadar.db') as conn:
        cur = conn.cursor()
        cur.execute('SELECT * FROM cafes')
        cafes = []
        for cafe_row in cur.fetchall():
            cafe = dict(zip([column[0] for column in cur.description], cafe_row))
            # Get ratings
            cur2 = conn.cursor()
            cur2.execute('SELECT user, rating, timestamp FROM ratings WHERE cafe_id=?', (cafe['id'],))
            cafe['ratings'] = [dict(zip(['user', 'rating', 'timestamp'], row)) for row in cur2.fetchall()]
            # Get comments
            cur2.execute('SELECT id, user, comment, timestamp, rating FROM comments WHERE cafe_id=?', (cafe['id'],))
            cafe['comments'] = [dict(zip(['id', 'user', 'comment', 'timestamp', 'rating'], row)) for row in cur2.fetchall()]
            # Recommendation
            cur2.execute('SELECT is_recommended FROM cafe_recommendations WHERE cafe_id=?', (cafe['id'],))
            rec = cur2.fetchone()
            cafe['is_recommended'] = bool(rec[0]) if rec else False
            cafes.append(cafe)
    return cafes


@app.route('/')
def home():
    if 'username' in session:
        return redirect('/dashboard')
    cafes = get_cafes_with_details()
    show_sign_in = request.args.get('show_sign_in', 'false').lower() == 'true'
    return render_template('home.html', cafes=cafes, show_sign_in=show_sign_in)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'username' in session:
        return redirect('/dashboard')
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        email = request.form['email']
        gender = request.form['gender']
        birthday = request.form['birthday']
        contactnumber = request.form.get('contactnumber', None)

        hashed_password = generate_password_hash(password)

        # Determine role
        with sqlite3.connect('caferadar.db') as conn:
            cur = conn.cursor()
            cur.execute('SELECT COUNT(*) FROM users')
            user_count = cur.fetchone()[0]
            role = 'admin' if user_count == 0 else 'user'

            # Check if username exists
            cur.execute('SELECT * FROM users WHERE username = ?', (username,))
            if cur.fetchone():
                flash("Username already exists!", "error")
                # You may want to reload cafes from MongoDB or SQLite as needed
                return render_template('home.html', show_sign_up=True, cafes=[])
            
            # Insert new user
            cur.execute('''
                INSERT INTO users (username, password, first_name, last_name, email, gender, birthday, contactnumber, role)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (username, hashed_password, first_name, last_name, email, gender, birthday, contactnumber, role))
            conn.commit()

        flash("Account Created Successfully.", "success")
        return render_template('home.html', show_sign_up=True, cafes=[])
    return render_template('home.html', cafes=[])

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'username' in session:
        return redirect('/dashboard')
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        with sqlite3.connect('caferadar.db') as conn:
            cur = conn.cursor()
            cur.execute('SELECT username, password, role FROM users WHERE username = ?', (username,))
            user = cur.fetchone()
            if user and check_password_hash(user[1], password):
                session['username'] = user[0]
                session['role'] = user[2]
                return redirect('/dashboard')
        flash("Invalid username or password.", "error")
        return render_template('home.html', show_sign_in=True, cafes=[])
    return render_template('home.html', cafes=[])

@app.route('/dashboard')
@login_required
def dashboard():
    cafes = get_cafes_with_details()
    if session['role'] == 'admin':
        with sqlite3.connect('caferadar.db') as conn:
            cur = conn.cursor()
            cur.execute('SELECT id, username FROM users')
            users = [dict(zip(['id', 'username'], row)) for row in cur.fetchall()]
        return render_template('admin_dashboard.html', cafes=cafes, users=users)
    else:
        with sqlite3.connect('caferadar.db') as conn:
            cur = conn.cursor()
            cur.execute('SELECT * FROM users WHERE username=?', (session['username'],))
            user_row = cur.fetchone()
            user = dict(zip([column[0] for column in cur.description], user_row)) if user_row else None
        return render_template('user_dashboard.html', user=user, cafes=cafes)

@app.route('/admin/recommendation')
@admin_required
def admin_recommendation():
    cafes = get_cafes_with_details()
    return render_template('admin_recommendation.html', cafes=cafes)

@app.route('/admin/recommendation/update', methods=['POST'])
@admin_required
def update_recommendation():
    recommended_ids = set(map(int, request.form.getlist('recommended_cafes')))
    with sqlite3.connect('caferadar.db') as conn:
        cur = conn.cursor()
        cur.execute('DELETE FROM cafe_recommendations')
        for cafe_id in recommended_ids:
            cur.execute('INSERT INTO cafe_recommendations (cafe_id, is_recommended) VALUES (?, ?)', (cafe_id, 1))
        conn.commit()
    flash('Recommendation settings updated successfully!', 'success')
    return redirect(url_for('admin_recommendation'))
    

    
@app.route('/edit_profile', methods=['POST'])
@login_required
def edit_profile():
    username = session['username']
    first_name = request.form.get('first_name')
    last_name = request.form.get('last_name')
    email = request.form.get('email')
    gender = request.form.get('gender')
    birthday = request.form.get('birthday')
    contactnumber = request.form.get('contactnumber')

    profile_pic_url = None
    if 'profile_pic' in request.files:
        file = request.files['profile_pic']
        if file and allowed_file(file.filename):
            filename = secure_filename(f"{username}_{file.filename}")
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            profile_pic_url = url_for('static', filename=f'uploads/{filename}')

    with sqlite3.connect('caferadar.db') as conn:
        cur = conn.cursor()
        if profile_pic_url:
            cur.execute('''
                UPDATE users
                SET first_name=?, last_name=?, email=?, gender=?, birthday=?, contactnumber=?, profile_pic_url=?
                WHERE username=?
            ''', (first_name, last_name, email, gender, birthday, contactnumber, profile_pic_url, username))
        else:
            cur.execute('''
                UPDATE users
                SET first_name=?, last_name=?, email=?, gender=?, birthday=?, contactnumber=?
                WHERE username=?
            ''', (first_name, last_name, email, gender, birthday, contactnumber, username))
        conn.commit()

    flash('Profile updated successfully!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/admin/users', methods=['GET'])
@admin_required
def admin_users():
    with sqlite3.connect('caferadar.db') as conn:
        cur = conn.cursor()
        cur.execute('SELECT id, username, role, first_name, last_name, email, gender, birthday, contactnumber FROM users')
        users = [
            dict(zip(['id', 'username', 'role', 'first_name', 'last_name', 'email', 'gender', 'birthday', 'contactnumber'], row))
            for row in cur.fetchall()
        ]
    return render_template('admin_users.html', users=users)

@app.route('/admin/user/edit/<int:user_id>', methods=['POST'])
@admin_required
def edit_user_role(user_id):
    new_role = request.form.get('role')
    if new_role not in ['admin', 'user']:
        flash('Invalid role selected.', 'danger')
        return redirect(url_for('admin_users'))
    with sqlite3.connect('caferadar.db') as conn:
        cur = conn.cursor()
        cur.execute('UPDATE users SET role=? WHERE id=?', (new_role, user_id))
        conn.commit()
    flash('User role updated successfully!', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/user/delete/<int:user_id>', methods=['POST'])
@admin_required
def delete_user(user_id):
    with sqlite3.connect('caferadar.db') as conn:
        cur = conn.cursor()
        cur.execute('DELETE FROM users WHERE id=?', (user_id,))
        conn.commit()
    flash('User deleted successfully!', 'danger')
    return redirect(url_for('admin_users'))

@app.route('/admin/user/details/<int:user_id>', methods=['GET'])
@admin_required
def user_details(user_id):
    with sqlite3.connect('caferadar.db') as conn:
        cur = conn.cursor()
        cur.execute('SELECT username, role, first_name, last_name, email, gender, birthday, contactnumber FROM users WHERE id=?', (user_id,))
        row = cur.fetchone()
        if not row:
            return jsonify({'error': 'User not found'}), 404
        user = dict(zip(['username', 'role', 'first_name', 'last_name', 'email', 'gender', 'birthday', 'contactnumber'], row))
    return jsonify(user)

@app.route('/logout')
@login_required
def logout():
    session.clear()
    return redirect(url_for('home'))

@app.route('/admin/cafe/add', methods=['POST'])
@admin_required
def add_cafe():
    name = request.form['name']
    description = request.form['description']
    maps_url = request.form['maps_url']
    address = request.form.get('address', '').strip()
    image = request.files.get('image')
    image_url = None
    if image and allowed_file(image.filename):
        filename = secure_filename(image.filename)
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        image.save(image_path)
        image_url = url_for('static', filename=f'uploads/{filename}')
    else:
        image_url = url_for('static', filename='default_cafe.jpg')
    with sqlite3.connect('caferadar.db') as conn:
        cur = conn.cursor()
        cur.execute('''
            INSERT INTO cafes (name, description, maps_url, address, image_url)
            VALUES (?, ?, ?, ?, ?)
        ''', (name, description, maps_url, address, image_url))
        conn.commit()
    flash('Cafe added successfully!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/admin/cafe/edit/<int:cafe_id>', methods=['GET', 'POST'])
@admin_required
def edit_cafe(cafe_id):
    with sqlite3.connect('caferadar.db') as conn:
        cur = conn.cursor()
        if request.method == 'POST':
            name = request.form['name']
            description = request.form['description']
            maps_url = request.form['maps_url']
            address = request.form.get('address', '').strip()
            image = request.files.get('image')
            cur.execute('SELECT image_url FROM cafes WHERE id=?', (cafe_id,))
            image_url = cur.fetchone()[0]
            if image and image.filename and allowed_file(image.filename):
                filename = secure_filename(image.filename)
                os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
                image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                image.save(image_path)
                image_url = url_for('static', filename=f'uploads/{filename}')
            cur.execute('''
                UPDATE cafes SET name=?, description=?, maps_url=?, address=?, image_url=?
                WHERE id=?
            ''', (name, description, maps_url, address, image_url, cafe_id))
            conn.commit()
            flash('Cafe updated successfully!', 'success')
            return redirect(url_for('dashboard'))
        # GET
        cur.execute('SELECT * FROM cafes WHERE id=?', (cafe_id,))
        cafe = cur.fetchone()
        if not cafe:
            return "Cafe not found.", 404
        cafe_dict = dict(zip([column[0] for column in cur.description], cafe))
    return render_template('edit_cafe.html', cafe=cafe_dict)

@app.route('/admin/cafe/delete/<int:cafe_id>', methods=['POST'])
@admin_required
def delete_cafe(cafe_id):
    with sqlite3.connect('caferadar.db') as conn:
        cur = conn.cursor()
        cur.execute('DELETE FROM cafes WHERE id=?', (cafe_id,))
        cur.execute('DELETE FROM ratings WHERE cafe_id=?', (cafe_id,))
        cur.execute('DELETE FROM comments WHERE cafe_id=?', (cafe_id,))
        cur.execute('DELETE FROM cafe_recommendations WHERE cafe_id=?', (cafe_id,))
        conn.commit()
    flash('Cafe deleted successfully!', 'danger')
    return redirect(url_for('dashboard'))

@app.route('/cafe/rate_and_comment/<int:cafe_id>', methods=['POST'])
def rate_and_comment_cafe(cafe_id):
    if 'username' not in session:
        return redirect(url_for('home', show_sign_in='true'))
    rating = request.form.get('rating')
    comment = request.form.get('comment')
    user = session['username']
    if not rating or not comment or not comment.strip():
        flash('Both rating and comment are required.', 'danger')
        return redirect(url_for('dashboard'))
    try:
        rating = int(rating)
        if rating < 1 or rating > 5:
            raise ValueError
    except ValueError:
        flash('Invalid rating value.', 'danger')
        return redirect(url_for('dashboard'))
    timestamp = datetime.utcnow().isoformat()
    with sqlite3.connect('caferadar.db') as conn:
        cur = conn.cursor()
        cur.execute('''
            INSERT INTO ratings (cafe_id, user, rating, timestamp)
            VALUES (?, ?, ?, ?)
        ''', (cafe_id, user, rating, timestamp))
        cur.execute('''
            INSERT INTO comments (cafe_id, user, comment, timestamp, rating)
            VALUES (?, ?, ?, ?, ?)
        ''', (cafe_id, user, comment.strip(), timestamp, rating))
        conn.commit()
    flash('Thank you for your feedback!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/delete_comment/<int:cafe_id>/<int:comment_id>', methods=['POST'])
@login_required
def delete_comment(cafe_id, comment_id):
    with sqlite3.connect('caferadar.db') as conn:
        cur = conn.cursor()
        cur.execute('SELECT user FROM comments WHERE id=? AND cafe_id=?', (comment_id, cafe_id))
        row = cur.fetchone()
        if not row:
            flash('Comment not found.', 'danger')
            return redirect(url_for('dashboard'))
        if row[0] != session['username']:
            flash('You can only delete your own comment.', 'danger')
            return redirect(url_for('dashboard'))
        cur.execute('DELETE FROM comments WHERE id=?', (comment_id,))
        conn.commit()
    flash('Comment deleted.', 'danger')
    return redirect(url_for('dashboard'))

@app.route('/admin_delete_comment/<int:cafe_id>/<int:comment_id>', methods=['POST'])
@admin_required
def admin_delete_comment(cafe_id, comment_id):
    with sqlite3.connect('caferadar.db') as conn:
        cur = conn.cursor()
        cur.execute('DELETE FROM comments WHERE id=? AND cafe_id=?', (comment_id, cafe_id))
        conn.commit()
    return jsonify({'success': True})

init_db()
if __name__ == '__main__':
    app.run(debug=True)