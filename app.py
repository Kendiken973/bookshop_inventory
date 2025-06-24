from flask import Flask, render_template, request, redirect, session, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from sqlalchemy import func, extract
from collections import defaultdict
from flask import session,redirect,url_for
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
from flask import Flask

app = Flask(__name__)
app.secret_key = 'yoursecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///bookshop.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
from itsdangerous import URLSafeTimedSerializer

s = URLSafeTimedSerializer(app.secret_key)

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your_email@gmail.com'
app.config['MAIL_PASSWORD'] = 'your_app_password'
app.config['MAIL_DEFAULT_SENDER'] = 'your_email@gmail.com'

mail = Mail(app)

db = SQLAlchemy(app)

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            flash('Please log in to continue.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Product model
class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    brand = db.Column(db.String(50), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    price = db.Column(db.Float, nullable=False)
    stock = db.Column(db.Integer, nullable=False)
    sold = db.Column(db.Integer, default=0)
    description = db.Column(db.Text)

class Sale(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    product_name = db.Column(db.String(100))
    quantity = db.Column(db.Integer)
    price = db.Column(db.Float)
    total = db.Column(db.Float)
    date = db.Column(db.DateTime, default=datetime.utcnow)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False, unique=True)
    email = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='employee')  # either 'admin' or 'employee'

with app.app_context():
    db.create_all()

@app.route('/home')
@login_required
def home():
    products = Product.query.all()
    return render_template('home.html', products=products)

#@app.route('/')
#def index():
    #return render_template('index.html', year=datetime.now().year)

#@app.route('/')
#@login_required
#def index():
    #products = Product.query.all()
   # return render_template('index.html', products=products)

@app.route('/add', methods=['GET', 'POST'])
@login_required
def add_product():
    if request.method == 'POST':
        name = request.form['name'].strip().lower()
        category = request.form['category'].strip().lower()
        brand = request.form['brand'].strip().lower()
        price = float(request.form['price'])
        stock = int(request.form['stock'])

        existing_product = Product.query.filter_by(name=name, category=category, brand=brand).first()

        if existing_product:
            existing_product.stock += stock
            db.session.commit()
            flash('Stock updated for existing product.', 'info')
        else:
            new_product = Product(
                name=name,
                category=category,
                brand=brand,
                price=price,
                stock=stock
            )
            db.session.add(new_product)
            db.session.commit()
            flash('New product added.', 'success')

        return redirect(url_for('home'))  # ✅ This is correct redirect *after* adding
    return render_template('add_product.html')  # ✅ Show form on GET

@app.route('/sales-by-date')
@login_required
def sales_by_date():
    daily_summary = db.session.query(
        func.date(Sale.date).label('sale_date'),
        func.sum(Sale.quantity).label('total_quantity'),
        func.sum(Sale.total).label('total_income')
    ).group_by(func.date(Sale.date)).order_by(func.date(Sale.date).desc()).all()

    return render_template('sales_by_date.html', summary=daily_summary)

@app.route('/sales-summary')
@login_required
def sales_summary():
    summary = db.session.query(
        Sale.product_name,
        func.sum(Sale.quantity).label('total_quantity'),
        func.sum(Sale.total).label('total_income')
    ).group_by(Sale.product_name).all()

    return render_template('sales_summary.html', summary=summary)

@app.route('/sell/<int:id>')
@login_required
def sell_product(id):
    product = Product.query.get_or_404(id)
    if product.stock > 0:
        product.stock -= 1
        product.sold += 1

        new_sale = Sale(
            product_name=product.name,
            quantity=1,
            price=product.price,
            total=product.price
        )

        db.session.add(new_sale)
        db.session.commit()
        flash('Product sold and recorded!', 'sales')
    return redirect('/')

@app.route('/sales-weekly')
@login_required
def sales_weekly():
    summary = db.session.query(
        extract('year', Sale.date).label('year'),
        extract('week', Sale.date).label('week'),
        func.sum(Sale.quantity).label('total_quantity'),
        func.sum(Sale.total).label('total_income')
    ).group_by('year', 'week').order_by('year', 'week').all()

    return render_template('sales_weekly.html', summary=summary)

@app.route('/sales-monthly')
@login_required
def sales_monthly():
    summary = db.session.query(
        extract('year', Sale.date).label('year'),
        extract('month', Sale.date).label('month'),
        func.sum(Sale.quantity).label('total_quantity'),
        func.sum(Sale.total).label('total_income')
    ).group_by('year', 'month').order_by('year', 'month').all()

    return render_template('sales_monthly.html', summary=summary)

@app.route('/sales-chart')
@login_required
def sales_chart():
    sales = Sale.query.all()
    data = defaultdict(float)
    for s in sales:
        day = s.date.strftime('%Y-%m-%d')
        data[day] += s.price

    labels = list(data.keys())
    values = list(data.values())

    return render_template('sales_chart.html', labels=labels, values=values)

@app.route('/out-of-stock')
@login_required
def out_of_stock():
    products = Product.query.filter_by(stock=0).all()
    return render_template('out_of_stock.html', products=products)

@app.route('/dashboard')
@login_required
def dashboard():
    total_products = Product.query.count()
    out_of_stock = Product.query.filter_by(stock=0).count()
    in_stock = Product.query.filter(Product.stock > 0).count()

    return render_template('dashboard.html', total=total_products, in_stock=in_stock, out_of_stock=out_of_stock)

@app.route('/delete/<int:id>')
@login_required
def delete_product(id):
    if session.get('role') != 'admin':
        flash('Only admin can delete products.', 'danger')
        return redirect('/')
    product = Product.query.get_or_404(id)
    db.session.delete(product)
    db.session.commit()
    flash('Product deleted.', 'inventory')
    return redirect('/')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        role = request.form['role']

        if not role:
            flash('Please select a role.', 'danger')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password)

        if User.query.filter_by(email=email).first():
            flash('Email already registered.', 'danger')
            return redirect(url_for('register'))

        new_user = User(username=username, email=email, password=hashed_password, role=role)
        db.session.add(new_user)
        db.session.commit()
        flash ('Registration successful. You can now log in.', 'login')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/edit/<int:id>', methods=['GET', 'POST'])
def edit_product(id):
    product = Product.query.get_or_404(id)
    if request.method == 'POST':
        product.name = request.form['name']
        product.category = request.form['category']
        product.brand = request.form.get('brand')
        product.price = float(request.form['price'])
        product.stock = int(request.form['stock'])
        product.description = request.form.get('description')
        
        db.session.commit()
        flash('Product updated successfully.', 'success')
        return redirect(url_for('home'))

    return render_template('edit_product.html', product=product)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email_or_username = request.form['username']
        password = request.form['password']

        user = User.query.filter(
            (User.username == email_or_username) |
            (User.email == email_or_username)
        ).first()

        if user and check_password_hash(user.password, password):
            session['user'] = user.username
            session['role'] = user.role
            flash('Login successful!', 'login')
            return redirect(url_for('home'))
        else:
            flash('Invalid credentials', 'login')

    return render_template('login.html', year=datetime.now().year)

@app.route('/logout')
def logout():
    session.pop('user', None)
    flash('Logged out successfully', 'info')
    return redirect('/login')

@app.route('/')
def index():
    if 'user' in session:
        return redirect(url_for('home'))  # Redirect logged-in users to /home
    year = datetime.now().year
    return render_template('index.html', year=year)

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if user:
            token = s.dumps(user.email, salt='password-reset')
            reset_link = url_for('reset_password', token=token, _external=True)
            msg = Message('Reset your password', recipients=[email])
            msg.body = f"Click here to reset your password: {reset_link}"
            mail.send(msg)
            flash('Password reset email sent!', 'info')
        return redirect('/login')
    return render_template('forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = s.loads(token, salt='password-reset', max_age=3600)  # 1 hour validity
    except:
        flash('Token is invalid or expired', 'danger')
        return redirect('/forgot-password')

    if request.method == 'POST':
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        user.password = generate_password_hash(password)
        db.session.commit()
        flash('Password reset successfully!', 'success')
        return redirect('/login')
    return render_template('reset_password.html')

@app.route('/sales')
@login_required
def sales():
    sales = Sale.query.order_by(Sale.date.desc()).all()
    return render_template('sales.html', sales=sales)

@app.after_request
def add_header(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

#with app.app_context():
    #db.create_all()

#@app.route('/create_db')
#def create_db():
  #  db.create_all()
   # return "✅ PostgreSQL tables created!"

#@app.route('/check-tables')
#def check_tables():
    #from sqlalchemy import inspect
    #inspector = inspect(db.engine)
    #return {'tables': inspector.get_table_names()}


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0')
