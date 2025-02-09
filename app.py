from flask import Flask, render_template, request, redirect, url_for, session, flash
import requests
import psycopg2
from psycopg2.extras import RealDictCursor
from flask_bcrypt import Bcrypt
from urllib.parse import unquote

app = Flask(__name__)
app.secret_key = 'supersecretkey'
bcrypt = Bcrypt(app)

def get_connection():
    return psycopg2.connect(
        host='localhost', 
        database='book_app', 
        user='postgres', 
        password='23Shruti07#'
    )

def fetch_openlibrary_books(query, limit=30):
    """Fetch books from OpenLibrary API based on a query."""
    url = f"http://openlibrary.org/search.json?q={query}&limit={limit}"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            books_data = response.json().get('docs', [])
            books = []
            for book in books_data:
                title = book.get('title', 'No title available')
                author = ', '.join(book.get('author_name', ['Unknown author']))
                cover_id = book.get('cover_i')  # Cover ID for images
                image_url = f"http://covers.openlibrary.org/b/id/{cover_id}-L.jpg" if cover_id else None
                books.append({
                    'title': title,
                    'author': author,
                    'image_url': image_url
                })
            return books
        else:
            print(f"Error: {response.status_code}")
    except requests.exceptions.Timeout:
        print(f"Request to {url} timed out.")
    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")
    return []

@app.route('/')
def index():
    """Main route to display book recommendations."""
    query = request.args.get('query', '').strip()  # Use a single input for any type of search
    limit = 30

    recommendations = []
    if query:
        recommendations = fetch_openlibrary_books(query, limit)

    return render_template('index.html', recommendations=recommendations, query=query)


@app.route('/save_book', methods=['GET','POST'])
def save_book():
    if request.method == 'POST':
        title = request.form['title']
        author = request.form['author']
        image_url = request.form['image_url']
        
        user_id = session['user']['id']
        add_book(title, author, user_id, image_url)
        flash(f'Book "{title}" has been saved to your collection.')
        return redirect(request.referrer)

@app.route('/delete_book', methods=['POST'])
def delete_book():
    if 'user' not in session:
        return redirect(url_for('auth'))
    
    user_id = session['user']['id']
    title = request.form['title']
    
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "DELETE FROM books WHERE user_id = %s AND title = %s",
        (user_id, title)
    )
    conn.commit()
    cursor.close()
    conn.close()
    
    flash(f'Book "{title}" has been removed from your collection.')
    return redirect(url_for('my_books'))

@app.route('/auth', methods=['GET', 'POST'])
def auth():
    if request.method == 'POST':
        action = request.form.get('action')
        username = request.form['username']
        password = request.form['password']
        
        if action == 'login':
            # Handle login logic
            user = authenticate_user(username, password)
            if user:
                session['user'] = user
                next_page = request.args.get('next')
                return redirect(next_page or url_for('index'))
            else:
                flash('Invalid credentials')
                return redirect(url_for('auth'))
        
        elif action == 'signup':
            # Handle signup logic
            email = request.form['email']  # Email is only in the signup form
            result = create_user(username, email, password)
            if result == "Email already exists":
                flash('Email already exists. Please use a different email.')
                return redirect(url_for('auth'))
            else:
                flash('Account created successfully. Please log in.')
                return redirect(url_for('auth'))

    return render_template('auth.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']

        user = find_user_by_username_and_email(username, email)

        if user:
            return redirect(url_for('reset_password', user_id=user['id']))
        else:
            flash('Username and email do not match.')
            return redirect(url_for('forgot_password'))

    return render_template('forgot_password.html')

@app.route('/reset_password/<int:user_id>', methods=['GET', 'POST'])
def reset_password(user_id):
    if request.method == 'POST':
        new_password = request.form['password']
        confirm_password = request.form['confirm_password']

        if new_password == confirm_password:
            update_password(user_id, new_password)
            flash('Your password has been reset successfully.')
            return redirect(url_for('auth'))
        else:
            flash('Passwords do not match.')
            return redirect(url_for('reset_password', user_id=user_id))

    return render_template('reset_password.html')

@app.route('/my_books', methods=['GET', 'POST'])
def my_books():
    if 'user' not in session:
        return redirect(url_for('auth'))
    user_id = session['user']['id']
    if request.method == 'POST':
        title = request.form['title']
        author = request.form['author']
        # Get the image URL (if provided)
        image_url = request.form.get('image_url')  # Make sure the name matches the form input field
        print(f"received : {image_url}")
        add_book(title, author, user_id, image_url)
    user_books = get_user_books(user_id)
    return render_template('my_books.html', books=user_books)

@app.route('/update_status', methods=['POST'])
def update_status():
    if 'user' not in session:
        return redirect(url_for('auth'))

    user_id = session['user']['id']
    title = request.form['title']
    status = request.form['status']
    
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE books SET status = %s WHERE user_id = %s AND title = %s",
        (status, user_id, title)
    )
    conn.commit()
    cursor.close()
    conn.close()
    
    return redirect(url_for('my_books'))

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('index'))

def create_user(username, email, password):
    conn = get_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)

    # Check if the email is already used
    cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
    existing_user = cursor.fetchone()

    if existing_user:
        conn.close()
        return "Email already exists"

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    cursor.execute("INSERT INTO users (username, email, password) VALUES (%s, %s, %s)", (username, email, hashed_password))
    conn.commit()
    cursor.close()
    conn.close()
    return "User created successfully"

def authenticate_user(username, password):
    conn = get_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
    user = cursor.fetchone()
    cursor.close()
    conn.close()
    if user and bcrypt.check_password_hash(user['password'], password):
        return user
    return None

import requests

def add_book(title, author, user_id, image_url = None, status = "To Read"):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO books (title, author, user_id, image_url, status) VALUES (%s, %s, %s, %s, %s)", (title, author, user_id, image_url, status))
    conn.commit()
    print("Book added with image_url:", image_url)
    cursor.close()
    conn.close()

def get_user_books(user_id):
    conn = get_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute("SELECT title, author, image_url, status FROM books WHERE user_id = %s", (user_id,))
    books = cursor.fetchall()
    cursor.close()
    conn.close()
    return books

def find_user_by_username_and_email(username, email):
    conn = get_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute("SELECT * FROM users WHERE username = %s AND email = %s", (username, email))
    user = cursor.fetchone()
    cursor.close()
    conn.close()
    return user

def update_password(user_id, new_password):
    hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET password = %s WHERE id = %s", (hashed_password, user_id))
    conn.commit()
    cursor.close()
    conn.close()

if __name__ == '__main__':
    app.run(debug=True)
