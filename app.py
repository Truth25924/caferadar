from flask import Flask, render_template, request, redirect, session, url_for, make_response, flash, jsonify
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
from bson.objectid import ObjectId
import os
from datetime import datetime
from flask_login import current_user, login_required

app = Flask(__name__)
app.secret_key = "your_secret_key"  

client = MongoClient("mongodb://localhost:27017")
db = client['caferadar']
users_col = db['users']
cafes_col = db['cafes']


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

@app.route('/')
def home():
    if 'username' in session:
        return redirect('/dashboard')
    cafes = [serialize_cafe(cafe) for cafe in cafes_col.find()]
    cafes = normalize_cafe_ratings_comments(cafes)
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

        from flask import flash

        if users_col.find_one({'username': username}):
            flash("Username already exists!", "error")
            cafes = [serialize_cafe(cafe) for cafe in cafes_col.find()]
            cafes = normalize_cafe_ratings_comments(cafes)
            return render_template('home.html', show_sign_up=True, cafes=cafes)

        hashed_password = generate_password_hash(password)

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
            'role': role
        }
        if contactnumber:
            user_data['contactnumber'] = contactnumber

        users_col.insert_one(user_data)
        flash("Account Created Successfully.", "success")
        cafes = [serialize_cafe(cafe) for cafe in cafes_col.find()]
        cafes = normalize_cafe_ratings_comments(cafes)
        return render_template('home.html', show_sign_up=True, cafes=cafes)
    cafes = [serialize_cafe(cafe) for cafe in cafes_col.find()]
    cafes = normalize_cafe_ratings_comments(cafes)
    return render_template('home.html', cafes=cafes)

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
        
        flash("Invalid username or password.", "error")
        cafes = [serialize_cafe(cafe) for cafe in cafes_col.find()]
        cafes = normalize_cafe_ratings_comments(cafes)
        return render_template('home.html', show_sign_in=True, cafes=cafes)
    return render_template('home.html', cafes=[serialize_cafe(cafe) for cafe in cafes_col.find()])

@app.route('/dashboard')
@login_required
def dashboard():
    if session['role'] == 'admin':
        cafes = [serialize_cafe(cafe) for cafe in cafes_col.find()]
        for cafe in cafes:
            cafe['ratings'] = cafe.get('ratings', [])
            cafe['comments'] = cafe.get('comments', [])
        users = list(users_col.find({}, {'_id': 1}))
        return render_template('admin_dashboard.html', cafes=cafes, users=users)
    else:
        user = users_col.find_one({'username': session['username']})

        if user and '_id' in user:
            user['_id'] = str(user['_id'])
        cafes = [serialize_cafe(cafe) for cafe in cafes_col.find()]
        cafes = normalize_cafe_ratings_comments(cafes) 
        return render_template('user_dashboard.html', user=user, cafes=cafes)

@app.route('/admin/recommendation')
@admin_required
def admin_recommendation():
    cafes = [serialize_cafe(cafe) for cafe in cafes_col.find()]

    for cafe in cafes:
        if 'is_recommended' not in cafe:
            cafe['is_recommended'] = False
    return render_template('admin_recommendation.html', cafes=cafes)


@app.route('/admin/recommendation/update', methods=['POST'])
@admin_required
def update_recommendation():
    recommended_ids = request.form.getlist('recommended_cafes')
    all_cafes = cafes_col.find()
    for cafe in all_cafes:
        is_recommended = str(cafe['_id']) in recommended_ids
        cafes_col.update_one({'_id': cafe['_id']}, {'$set': {'is_recommended': is_recommended}})
    flash('Recommendation settings updated successfully!', 'success')
    return redirect(url_for('admin_recommendation'))
    

def serialize_cafe(cafe):
    cafe = dict(cafe)
    if '_id' in cafe and isinstance(cafe['_id'], ObjectId):
        cafe['_id'] = str(cafe['_id'])
    normalized_ratings = []
    for r in cafe.get('ratings', []):
        if isinstance(r, dict):
            normalized_ratings.append(r)
        else:
            normalized_ratings.append({'user': 'Unknown', 'rating': r, 'timestamp': None})
    cafe['ratings'] = normalized_ratings
    normalized_comments = []
    for c in cafe.get('comments', []):
        if isinstance(c, dict):
            normalized_comments.append(c)
        else:
            normalized_comments.append({'user': 'Unknown', 'comment': c, 'timestamp': None})
    cafe['comments'] = normalized_comments

    if 'address' not in cafe:
        cafe['address'] = ''
    return cafe
    
@app.route('/edit_profile', methods=['POST'])
@login_required
def edit_profile():

    user = users_col.find_one({'username': session['username']})
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('dashboard'))

    first_name = request.form.get('first_name')
    last_name = request.form.get('last_name')
    email = request.form.get('email')
    gender = request.form.get('gender')
    birthday = request.form.get('birthday')
    contactnumber = request.form.get('contactnumber')


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
        'contactnumber': contactnumber,
        'profile_pic_url': profile_pic_url
    }

    update_fields = {k: v for k, v in update_fields.items() if v is not None}

    users_col.update_one({'_id': user['_id']}, {'$set': update_fields})

    flash('Profile updated successfully!', 'success')
    return redirect(url_for('dashboard'))


@app.route('/admin/users', methods=['GET'])
@admin_required
def admin_users():
    all_users = list(users_col.find({}, {'_id': 1, 'username': 1, 'role': 1, 'first_name': 1, 'last_name': 1, 'email': 1, 'gender': 1, 'birthday': 1, 'sex': 1, 'contactnumber': 1}))

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

    cafe = {
        'name': name,
        'description': description,
        'maps_url': maps_url,
        'address': address,
        'image_url': image_url,
        'ratings': [],
        'comments': []
    }

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
        address = request.form.get('address', '').strip() 



        image = request.files.get('image')
        image_url = cafe.get('image_url')  
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
                'address': address,
                'image_url': image_url
            }}
        )
        flash('Cafe updated successfully!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('edit_cafe.html', cafe=cafe)



@app.route('/cafe/rate_and_comment/<cafe_id>', methods=['POST'])
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

    rating_obj = {
        'user': user,
        'rating': rating,
        'timestamp': timestamp
    }
    comment_obj = {
        '_id': str(ObjectId()),
        'user': user,
        'comment': comment.strip(),
        'timestamp': timestamp,
        'rating': rating  
    }

    cafes_col.update_one(
    {'_id': ObjectId(cafe_id)},
    {
        '$push': {
            'ratings': rating_obj,
            'comments': comment_obj
            }
        }
    )
    flash('Thank you for your feedback!', 'success')
    return redirect(url_for('dashboard'))


@app.route('/delete_comment/<cafe_id>/<comment_id>', methods=['POST'])
@login_required
def delete_comment(cafe_id, comment_id):
    cafe = db.cafes.find_one({'_id': ObjectId(cafe_id)})
    if not cafe:
        flash('Cafe not found.', 'danger')
        return redirect(url_for('dashboard'))
    
    comment = next((c for c in cafe['comments'] if c.get('_id') and str(c['_id']) == comment_id), None)
    if not comment or comment['user'] != session['username']:
        flash('You can only delete your own comment.', 'danger')
        return redirect(url_for('dashboard'))
    db.cafes.update_one(
        {'_id': ObjectId(cafe_id)},
        {'$pull': {'comments': {'_id': comment_id}}}
    )
    flash('Comment deleted.', 'danger')
    return redirect(url_for('dashboard'))

@app.route('/admin_delete_comment/<cafe_id>/<comment_id>', methods=['POST'])
def admin_delete_comment(cafe_id, comment_id):

    cafe = db.cafes.find_one({'_id': ObjectId(cafe_id)})
    if not cafe:
        return jsonify({'success': False, 'msg': 'Cafe not found.'}), 404
    db.cafes.update_one(
        {'_id': ObjectId(cafe_id)},
        {'$pull': {'comments': {'_id': comment_id}}}
    )
    return jsonify({'success': True})

def normalize_cafe_ratings_comments(cafes):
    """
    Ensures all ratings are dicts with keys: user, rating, timestamp.
    Ensures all comments are dicts with keys: user, comment, timestamp, rating.
    """
    for cafe in cafes:

        normalized_ratings = []
        for r in cafe.get('ratings', []):
            if isinstance(r, dict):
                normalized_ratings.append(r)
            else:
                normalized_ratings.append({'user': 'Unknown', 'rating': r, 'timestamp': None})
        cafe['ratings'] = normalized_ratings


        normalized_comments = []
        for c in cafe.get('comments', []):
            if isinstance(c, dict):

                if 'rating' not in c or c['rating'] is None:
                    c['rating'] = 0
                normalized_comments.append(c)
            else:
                normalized_comments.append({'user': 'Unknown', 'comment': c, 'timestamp': None, 'rating': 0})
        cafe['comments'] = normalized_comments
    return cafes

if __name__ == '__main__':
    app.run(debug=True)