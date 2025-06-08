from flask import Flask, render_template, request, redirect, session, url_for, make_response, flash, jsonify
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
from bson.objectid import ObjectId
import os
from datetime import datetime

app = Flask(__name__)
app.secret_key = "your_secret_key"  
# MongoDB connection
client = MongoClient("mongodb://localhost:27017")
db = client['caferadar']
users_col = db['users']
cafes_col = db['cafes']

# Set upload folder and allowed extensions
UPLOAD_FOLDER = os.path.join('static', 'uploads')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# admin required decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session or session.get('role') != 'admin':
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Set cache-control headers to prevent back navigation to login after login/logout
@app.after_request
def add_cache_control(response):
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, post-check=0, pre-check=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "-1"
    return response

@app.route('/')
def home():
    if 'username' in session:
        return redirect('/dashboard')
    return redirect('/login')

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
        sex = request.form['sex']
        contactnumber = request.form.get('contactnumber', None)  # Optional

        if users_col.find_one({'username': username}):
            return "Username already exists!"

        hashed_password = generate_password_hash(password)

         # Check if this is the first user
        user_count = users_col.count_documents({})
        if user_count == 0:
            role = 'admin'
        else:
            role = 'user'

        user_data = {
            'username': username,
            'password': hashed_password,
            'first_name': first_name,
            'last_name': last_name,
            'email': email,
            'gender': gender,
            'birthday': birthday,
            'sex': sex,
            'role': role
        }
        if contactnumber:
            user_data['contactnumber'] = contactnumber

        users_col.insert_one(user_data)
        return redirect('/login')
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'username' in session:
        return redirect('/dashboard')
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = users_col.find_one({'username': username})
        if user and check_password_hash(user['password'], password):
            session['username'] = user['username']
            session['role'] = user['role']
            return redirect('/dashboard')
        return "Invalid credentials."
    return render_template('login.html')
@app.route('/dashboard')
@login_required
def dashboard():
    if session['role'] == 'admin':
        cafes = [serialize_cafe(cafe) for cafe in cafes_col.find()]
        for cafe in cafes:
            cafe['ratings'] = cafe.get('ratings', [])
            cafe['comments'] = cafe.get('comments', [])
        users = list(users_col.find({}, {'_id': 1})) # count how many users already had account
        return render_template('admin_dashboard.html', cafes=cafes, users=users)
    else:
        user = users_col.find_one({'username': session['username']})
        # Convert ObjectId to string
        if user and '_id' in user:
            user['_id'] = str(user['_id'])
        cafes = [serialize_cafe(cafe) for cafe in cafes_col.find()]
        cafes = normalize_cafe_ratings_comments(cafes) 
        return render_template('user_dashboard.html', user=user, cafes=cafes)
    
# 2ND PART OF DASHBOARD PY FUNCTION SERIALIZE CAFE(CLICK TO ENLARGE THE CAFE TABLE)
# Serialize_cafe to ensure ratings/comments are serializable
def serialize_cafe(cafe):
    cafe = dict(cafe)
    if '_id' in cafe and isinstance(cafe['_id'], ObjectId):
        cafe['_id'] = str(cafe['_id'])
    # Normalize ratings
    normalized_ratings = []
    for r in cafe.get('ratings', []):
        if isinstance(r, dict):
            normalized_ratings.append(r)
        else:
            normalized_ratings.append({'user': 'Unknown', 'rating': r, 'timestamp': None})
    cafe['ratings'] = normalized_ratings
    # Normalize comments
    normalized_comments = []
    for c in cafe.get('comments', []):
        if isinstance(c, dict):
            normalized_comments.append(c)
        else:
            normalized_comments.append({'user': 'Unknown', 'comment': c, 'timestamp': None})
    cafe['comments'] = normalized_comments
    return cafe
    
@app.route('/edit_profile', methods=['POST'])
@login_required
def edit_profile():
    # Fetch the current user
    user = users_col.find_one({'username': session['username']})
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('dashboard'))

    # DATA of the user
    first_name = request.form.get('first_name')
    last_name = request.form.get('last_name')
    email = request.form.get('email')
    gender = request.form.get('gender')
    birthday = request.form.get('birthday')
    sex = request.form.get('sex')
    contactnumber = request.form.get('contactnumber')

    # Handle profile picture upload
    profile_pic = request.files.get('profile_pic')
    profile_pic_url = user.get('profile_pic_url', None)
    if profile_pic and allowed_file(profile_pic.filename):
        filename = secure_filename(profile_pic.filename)
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        profile_pic.save(image_path)
        profile_pic_url = url_for('static', filename=f'uploads/{filename}')

    update_fields = {
        'first_name': first_name,
        'last_name': last_name,
        'email': email,
        'gender': gender,
        'birthday': birthday,
        'sex': sex,
        'contactnumber': contactnumber,
        'profile_pic_url': profile_pic_url
    }
    # This remove none values
    update_fields = {k: v for k, v in update_fields.items() if v is not None}

    users_col.update_one({'_id': user['_id']}, {'$set': update_fields})

    flash('Profile updated successfully!', 'success')
    return redirect(url_for('dashboard'))

# ----------- ADMIN CONTROL DELETE A USER OR MAKE A USER ADMIN (VICE VERSA) -----------

@app.route('/admin/users', methods=['GET'])
@admin_required
def admin_users():
    all_users = list(users_col.find({}, {'_id': 1, 'username': 1, 'role': 1, 'first_name': 1, 'last_name': 1, 'email': 1, 'gender': 1, 'birthday': 1, 'sex': 1, 'contactnumber': 1}))
    # Convert ObjectId to string for JSON serialization
    for user in all_users:
        user['_id'] = str(user['_id'])
    return render_template('admin_users.html', users=all_users)

@app.route('/admin/user/edit/<user_id>', methods=['POST'])
@admin_required
def edit_user_role(user_id):
    new_role = request.form.get('role')
    if new_role not in ['admin', 'user']:
        flash('Invalid role selected.', 'danger')
        return redirect(url_for('admin_users'))
    users_col.update_one({'_id': ObjectId(user_id)}, {'$set': {'role': new_role}})
    flash('User role updated successfully!', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/user/delete/<user_id>', methods=['POST'])
@admin_required
def delete_user(user_id):
    users_col.delete_one({'_id': ObjectId(user_id)})
    flash('User deleted successfully!', 'danger')
    return redirect(url_for('admin_users'))

@app.route('/admin/user/details/<user_id>', methods=['GET'])
@admin_required
def user_details(user_id):
    user = users_col.find_one({'_id': ObjectId(user_id)}, {'_id': 0, 'password': 0})
    if not user:
        return jsonify({'error': 'User not found'}), 404
    return jsonify(user)

@app.route('/logout')
@login_required
def logout():
    session.clear()
    return redirect('/login')

# ----------- Cafe Admin Features -----------

@app.route('/admin/cafe/add', methods=['POST'])
@admin_required
def add_cafe():
    name = request.form['name']
    description = request.form['description']
    maps_url = request.form['maps_url']

    # FOR handling image upload!!!
    image = request.files.get('image')
    image_url = None
    if image and allowed_file(image.filename):
        filename = secure_filename(image.filename)
        # Ensure upload folder exists
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        image.save(image_path)
        image_url = url_for('static', filename=f'uploads/{filename}')
    else:
        # Set default image if no image uploaded
        image_url = url_for('static', filename='default_cafe.jpg')

    cafe = {
        'name': name,
        'description': description,
        'maps_url': maps_url,
        'image_url': image_url,
        'ratings': [],
        'comments': []
    }

    #Inserts the image into database and dashboard
    cafes_col.insert_one(cafe)

    flash('Cafe added successfully!', 'success')
    return redirect(url_for('dashboard'))
@app.route('/admin/cafe/delete/<cafe_id>', methods=['POST'])
@admin_required
def delete_cafe(cafe_id):
    cafes_col.delete_one({'_id': ObjectId(cafe_id)})
    flash('Cafe deleted successfully!', 'danger')
    return redirect(url_for('dashboard'))

@app.route('/admin/cafe/edit/<cafe_id>', methods=['GET', 'POST'])
@admin_required
def edit_cafe(cafe_id):
    cafe = cafes_col.find_one({'_id': ObjectId(cafe_id)})
    if not cafe:
        return "Cafe not found.", 404

    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        maps_url = request.form['maps_url']

        # Handle image upload
        image = request.files.get('image')
        image_url = cafe.get('image_url')  # Default to existing image

        if image and image.filename and allowed_file(image.filename):
            filename = secure_filename(image.filename)
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            image.save(image_path)
            image_url = url_for('static', filename=f'uploads/{filename}')

        cafes_col.update_one(
            {'_id': ObjectId(cafe_id)},
            {'$set': {
                'name': name,
                'description': description,
                'maps_url': maps_url,
                'image_url': image_url
            }}
        )
        flash('Cafe updated successfully!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('edit_cafe.html', cafe=cafe)

# ----------- Rate and Comment -----------

# When a user rates a cafe
@app.route('/cafe/rate/<cafe_id>', methods=['POST'])
@login_required
def rate_cafe(cafe_id):
    rating = int(request.form['rating'])
    user = session['username']
    rating_obj = {
        'user': user,
        'rating': rating,
        'timestamp': datetime.utcnow().isoformat()
    }
    cafes_col.update_one({'_id': ObjectId(cafe_id)}, {'$push': {'ratings': rating_obj}})
    return redirect(url_for('dashboard'))

# When a user comments on a cafe
@app.route('/cafe/comment/<cafe_id>', methods=['POST'])
@login_required
def comment_cafe(cafe_id):
    comment = request.form['comment']
    user = session['username']
    comment_obj = {
        'user': user,
        'comment': comment,
        'timestamp': datetime.utcnow().isoformat()
    }
    cafes_col.update_one({'_id': ObjectId(cafe_id)}, {'$push': {'comments': comment_obj}})
    return redirect(url_for('dashboard'))

def normalize_cafe_ratings_comments(cafes):
    """
    Ensures all ratings are dicts with keys: user, rating, timestamp.
    Ensures all comments are dicts with keys: user, comment, timestamp.
    """
    for cafe in cafes:
        # Normalize ratings
        normalized_ratings = []
        for r in cafe.get('ratings', []):
            if isinstance(r, dict):
                normalized_ratings.append(r)
            else:
                normalized_ratings.append({'user': 'Unknown', 'rating': r, 'timestamp': None})
        cafe['ratings'] = normalized_ratings

        # Normalize comments
        normalized_comments = []
        for c in cafe.get('comments', []):
            if isinstance(c, dict):
                normalized_comments.append(c)
            else:
                normalized_comments.append({'user': 'Unknown', 'comment': c, 'timestamp': None})
        cafe['comments'] = normalized_comments
    return cafes

if __name__ == '__main__':
    app.run(debug=True)