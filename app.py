from flask import Flask, render_template, request, redirect, url_for, jsonify, flash
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from database import db, User, Product, Message
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'manipal-secret-key-2024'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///manipal_market.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'index'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

with app.app_context():
    db.create_all()
    admin = User.query.filter_by(email='admin@manipal.com').first()
    if not admin:
        admin = User(
            email='admin@manipal.com',
            username='admin',
            password=generate_password_hash('admin123'),
            is_admin=True
        )
        db.session.add(admin)
        db.session.commit()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/dashboard')
@login_required
def dashboard():
    my_products = Product.query.filter_by(user_id=current_user.id).all()
    my_messages = Message.query.filter_by(recipient_id=current_user.id).order_by(Message.created_at.desc()).all()
    unread_count = Message.query.filter_by(recipient_id=current_user.id, is_read=False).count()
    return render_template('dashboard.html', products=my_products, messages=my_messages, unread_count=unread_count)

@app.route('/admin')
@login_required
def admin_panel():
    if not current_user.is_admin:
        flash('Access denied. Admin only.')
        return redirect(url_for('index'))
    all_products = Product.query.order_by(Product.created_at.desc()).all()
    all_users = User.query.all()
    stats = {
        'total_products': Product.query.count(),
        'total_users': User.query.count(),
        'flagged_products': Product.query.filter_by(status='flagged').count(),
        'active_products': Product.query.filter_by(status='active').count()
    }
    return render_template('admin.html', products=all_products, users=all_users, stats=stats)

@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    email = data.get('email')
    password = data.get('password')
    username = data.get('username')
    if User.query.filter_by(email=email).first():
        return jsonify({'success': False, 'message': 'Email already exists'}), 400
    hashed_password = generate_password_hash(password)
    new_user = User(email=email, username=username, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    login_user(new_user)
    return jsonify({'success': True, 'username': new_user.username})

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')
    user = User.query.filter_by(email=email).first()
    if user and check_password_hash(user.password, password):
        login_user(user)
        return jsonify({'success': True, 'username': user.username, 'is_admin': user.is_admin})
    return jsonify({'success': False, 'message': 'Invalid credentials'}), 401

@app.route('/api/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return jsonify({'success': True})

@app.route('/api/current-user')
def current_user_api():
    if current_user.is_authenticated:
        unread = Message.query.filter_by(recipient_id=current_user.id, is_read=False).count()
        return jsonify({'loggedIn': True, 'username': current_user.username, 'is_admin': current_user.is_admin, 'unread_messages': unread})
    return jsonify({'loggedIn': False})

@app.route('/api/products')
def get_products():
    category = request.args.get('category', 'All')
    search = request.args.get('search', '').lower()
    query = Product.query.filter_by(status='active')
    if category != 'All':
        query = query.filter_by(category=category)
    products = query.order_by(Product.created_at.desc()).all()
    if search:
        products = [p for p in products if search in p.title.lower() or search in p.description.lower()]
    return jsonify([{
        'id': p.id, 'title': p.title, 'price': p.price, 'category': p.category,
        'description': p.description, 'seller': p.owner.username, 'seller_id': p.user_id,
        'views': p.views, 'created_at': p.created_at.strftime('%Y-%m-%d')
    } for p in products])

@app.route('/api/add-product', methods=['POST'])
@login_required
def add_product():
    data = request.json
    new_product = Product(
        title=data.get('title'), price=int(data.get('price')),
        category=data.get('category'), description=data.get('description'),
        user_id=current_user.id
    )
    db.session.add(new_product)
    db.session.commit()
    return jsonify({'success': True, 'product_id': new_product.id})

@app.route('/api/delete-product/<int:product_id>', methods=['DELETE'])
@login_required
def delete_product(product_id):
    product = Product.query.get_or_404(product_id)
    if product.user_id != current_user.id and not current_user.is_admin:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    db.session.delete(product)
    db.session.commit()
    return jsonify({'success': True})

@app.route('/api/flag-product/<int:product_id>', methods=['POST'])
@login_required
def flag_product(product_id):
    if not current_user.is_admin:
        return jsonify({'success': False, 'message': 'Admin only'}), 403
    product = Product.query.get_or_404(product_id)
    product.status = 'flagged'
    db.session.commit()
    return jsonify({'success': True})

@app.route('/api/send-message', methods=['POST'])
@login_required
def send_message():
    data = request.json
    message = Message(
        content=data.get('content'), sender_id=current_user.id,
        sender_name=current_user.username, recipient_id=data.get('recipient_id'),
        product_id=data.get('product_id')
    )
    db.session.add(message)
    db.session.commit()
    return jsonify({'success': True})

@app.route('/api/mark-read/<int:message_id>', methods=['POST'])
@login_required
def mark_read(message_id):
    message = Message.query.get_or_404(message_id)
    if message.recipient_id != current_user.id:
        return jsonify({'success': False}), 403
    message.is_read = True
    db.session.commit()
    return jsonify({'success': True})

@app.route('/api/increment-view/<int:product_id>', methods=['POST'])
def increment_view(product_id):
    product = Product.query.get_or_404(product_id)
    product.views += 1
    db.session.commit()
    return jsonify({'success': True})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=8080)