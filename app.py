# app.py

from flask import Flask, render_template, request, redirect, url_for, flash, session, g
import sqlite3
from datetime import datetime, timedelta
import random
import string
import smtplib
from email.mime.text import MIMEText
from apscheduler.schedulers.background import BackgroundScheduler
import atexit
import csv
import os
import json

# --- Tambahan: Flask-Login dan Werkzeug Security ---
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import secrets # Import secrets untuk pembuatan token yang lebih aman

# --- Google Sheets Integration START ---
import gspread
from google.oauth2.service_account import Credentials
# --- Google Sheets Integration END ---

app = Flask(__name__)
app.secret_key = 'ecf8effde95b9a1f5e1540276df8cd4d00638d81b8d0ed91'

# --- Konfigurasi Flask-Login ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# --- Konfigurasi File Upload START ---
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'csv'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
# --- Konfigurasi File Upload END ---

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATABASE = os.path.join(BASE_DIR, 'perpustakaan.db')

# --- Konfigurasi Email ---
# Pastikan variabel lingkungan ini diset atau gunakan nilai default yang kuat
SMTP_SERVER = os.environ.get('SMTP_SERVER', 'smtp.gmail.com')
SMTP_PORT = int(os.environ.get('SMTP_PORT', 587))
SMTP_USERNAME = os.environ.get('SMTP_USERNAME', 'notifikasisistempinjambuku@gmail.com') # Ganti dengan email pengirim Anda
SMTP_PASSWORD = os.environ.get('SMTP_PASSWORD', 'cqet ipux kllz ldjh') # Ganti dengan App Password Gmail Anda
PETUGAS_NOTIFICATION_EMAIL = os.environ.get('PETUGAS_NOTIFICATION_EMAIL', 'alif.bomantara3@mail.com')
DEVELOPER_NOTIFICATION_EMAIL = os.environ.get('DEVELOPER_NOTIFICATION_EMAIL', 'kiflirahim281@gmail.com')

# --- DEBUGGING EMAIL CONFIG ---
print(f"SMTP Username: {SMTP_USERNAME}")
print(f"SMTP Password (sebagian): {SMTP_PASSWORD[:3]}...")
print(f"Dev Notif Email: {DEVELOPER_NOTIFICATION_EMAIL}")
# --- END DEBUGGING EMAIL CONFIG ---

# --- Google Sheets Configuration START ---
CREDENTIALS_FILE = 'credentials.json'
SPREADSHEET_NAME = 'Data Peminjam Buku Gramedia'
GOOGLE_SHEETS_WORKSHEET = None
# --- Google Sheets Configuration END ---

# --- Konfigurasi Reset Password ---
MAX_LOGIN_ATTEMPTS = 2 # Tombol lupa password akan muncul setelah 2 kali salah
RESET_TOKEN_EXPIRATION_MINUTES = 60 # Token berlaku 1 jam

# --- Fungsi Database ---
def init_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS books (
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            author TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'Tersedia'
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT,
            role TEXT DEFAULT 'peminjam',
            registration_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            full_name TEXT,
            reset_token TEXT,             -- Kolom untuk token reset password
            reset_token_expiration TEXT   -- Kolom untuk masa berlaku token
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS loans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            book_id TEXT NOT NULL,
            user_id INTEGER,
            borrower_name_manual TEXT,
            borrower_email TEXT,
            petugas_id INTEGER,
            petugas_name_manual TEXT,
            loan_date TEXT NOT NULL,
            due_date TEXT NOT NULL,
            return_date TEXT,
            recorded_by TEXT, -- Tambah kolom recorded_by
            FOREIGN KEY (book_id) REFERENCES books(id),
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (petugas_id) REFERENCES users(id)
        )
    ''')
    conn.commit()

    # --- Tambahkan kolom baru jika belum ada (untuk database yang sudah ada) ---
    def add_column_if_not_exists(table_name, column_name, column_type, default_value=None):
        try:
            cursor.execute(f"PRAGMA table_info({table_name});")
            columns = [col[1] for col in cursor.fetchall()]
            if column_name not in columns:
                cursor.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_type}")
                if default_value is not None:
                    cursor.execute(f"UPDATE {table_name} SET {column_name} = ? WHERE {column_name} IS NULL", (default_value,))
                print(f"Kolom '{column_name}' berhasil ditambahkan ke tabel '{table_name}'.")
            else:
                print(f"Kolom '{column_name}' di tabel '{table_name}' sudah ada.")
        except sqlite3.OperationalError as e:
            # Handle the case where the column already exists but an error might be thrown due to unique constraint etc.
            if "duplicate column name" not in str(e):
                print(f"Error menambahkan kolom {column_name} ke {table_name}: {e}")
            else:
                print(f"Kolom '{column_name}' di tabel '{table_name}' sudah ada.")

    add_column_if_not_exists('users', 'email', 'TEXT')
    add_column_if_not_exists('users', 'role', "TEXT DEFAULT 'peminjam'", 'peminjam')
    add_column_if_not_exists('users', 'registration_date', 'TIMESTAMP', datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f'))
    add_column_if_not_exists('users', 'full_name', 'TEXT')
    add_column_if_not_exists('users', 'reset_token', 'TEXT')
    add_column_if_not_exists('users', 'reset_token_expiration', 'TEXT')

    add_column_if_not_exists('loans', 'borrower_email', 'TEXT')
    add_column_if_not_exists('loans', 'petugas_id', 'INTEGER')
    add_column_if_not_exists('loans', 'petugas_name_manual', 'TEXT')
    add_column_if_not_exists('loans', 'recorded_by', 'TEXT')

    # Pastikan kolom 'role' memiliki nilai default 'peminjam' jika kosong (untuk data lama)
    cursor.execute("UPDATE users SET role = 'peminjam' WHERE role IS NULL OR role = ''")

    conn.commit()
    conn.close()

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

# --- USER MODEL UNTUK FLASK-LOGIN ---
class User(UserMixin):
    def __init__(self, id, username, password, email, role, full_name=None, registration_date=None, reset_token=None, reset_token_expiration=None):
        self.id = id
        self.username = username
        self.password = password
        self.email = email
        self.role = role
        self.full_name = full_name
        if isinstance(registration_date, str):
            try:
                self.registration_date = datetime.strptime(registration_date, '%Y-%m-%d %H:%M:%S.%f')
            except ValueError:
                self.registration_date = datetime.strptime(registration_date, '%Y-%m-%d %H:%M:%S')
        else:
            self.registration_date = registration_date
        self.reset_token = reset_token
        self.reset_token_expiration = reset_token_expiration

    def get_id(self):
        return str(self.id)

    def is_admin(self):
        return self.role == 'admin'

    def is_peminjam(self):
        return self.role == 'peminjam'

    def is_developer(self):
        return self.role == 'developer'

@login_manager.user_loader
def load_user(user_id):
    conn = get_db_connection()
    user_data = conn.execute('SELECT id, username, password, email, role, full_name, registration_date, reset_token, reset_token_expiration FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()
    if user_data:
        return User(user_data['id'], user_data['username'], user_data['password'], user_data['email'], user_data['role'], user_data['full_name'], user_data['registration_date'], user_data['reset_token'], user_data['reset_token_expiration'])
    return None

# Menambahkan fungsi `now` sebagai global di Jinja environment
app.jinja_env.globals['now'] = datetime.now

app.jinja_env.filters['is_overdue'] = lambda date_str: datetime.now().date() > datetime.strptime(date_str, '%Y-%m-%d').date()

# Filter Jinja baru untuk format datetime (YYYY-MM-DD HH:MM:SS ke DD/MM/YYYY HH:MM)
def datetimeformat(value, format_string='%d/%m/%Y %H:%M'):
    if value:
        if isinstance(value, datetime):
            return value.strftime(format_string)
        try:
            dt_obj = datetime.strptime(value, '%Y-%m-%d %H:%M:%S.%f')
        except ValueError:
            try:
                dt_obj = datetime.strptime(value, '%Y-%m-%d %H:%M:%S')
            except ValueError:
                try:
                    dt_obj = datetime.strptime(value, '%Y-%m-%d')
                except ValueError:
                    return value
        return dt_obj.strftime(format_string)
    return "-"

app.jinja_env.filters['datetimeformat'] = datetimeformat


def generate_random_id(length=6):
    characters = string.ascii_uppercase + string.digits
    return ''.join(random.choice(characters) for i in range(length))

def generate_reset_token():
    return secrets.token_urlsafe(32)

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# --- Fungsi Pengiriman Email ---
def send_email(recipient_email, subject, body):
    if not recipient_email or not SMTP_USERNAME or not SMTP_PASSWORD:
        print("Konfigurasi email pengirim tidak lengkap atau email penerima kosong. Pengiriman dibatalkan.")
        return False

    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = SMTP_USERNAME
    msg['To'] = recipient_email

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.send_message(msg)
        print(f"Email '{subject}' berhasil dikirim ke {recipient_email}")
        return True
    except Exception as e:
        print(f"Pengiriman email gagal ke {recipient_email}: {e}")
        return False

# --- Fungsi Penjadwalan Email Otomatis ---
def check_and_send_reminders():
    print("Menjalankan pengecekan dan pengiriman pengingat/notifikasi email...")
    conn = get_db_connection()
    today = datetime.now().date()

    loans = conn.execute('''
        SELECT
            l.id as loan_id,
            b.title,
            b.author,
            l.borrower_name_manual,
            l.borrower_email,
            l.due_date
        FROM loans l
        JOIN books b ON l.book_id = b.id
        WHERE l.return_date IS NULL
    ''').fetchall()

    for loan in loans:
        due_date_obj = datetime.strptime(loan['due_date'], '%Y-%m-%d').date()

        # Pengingat: 1 hari sebelum jatuh tempo
        if (due_date_obj - today).days == 1:
            if loan['borrower_email']:
                subject = f'Pengingat: Batas Waktu Pengembalian Buku "{loan["title"]}" Besok!'
                body = f"""
Halo {loan['borrower_name_manual']},

Kami ingin mengingatkan bahwa batas waktu pengembalian buku "{loan['title']}" oleh {loan['author']}" adalah besok, tanggal {loan['due_date']}.

Mohon segera kembalikan buku Anda, Jika terlambat atau tidak mengembalikan, buku harus dibayar.

Terima kasih,
Sistem Pinjam Buku Gramedia
"""
                send_email(loan['borrower_email'], subject, body)
            else:
                print(f"Peminjam {loan['borrower_name_manual']} tidak memiliki email untuk pengingat buku {loan['title']}.")

        # Notifikasi Keterlambatan: Sudah melewati batas waktu
        elif today > due_date_obj:
            if loan['borrower_email']:
                subject = f'PENTING: Buku "{loan["title"]}" Anda Sudah Terlambat Dikembalikan!'
                body = f"""
Halo {loan['borrower_name_manual']},

Kami ingin memberitukan bahwa buku "{loan['title']}" oleh {loan['author']}" yang Anda pinjam sudah melewati batas waktu pengembalian.

Batas waktu pengembalian adalah tanggal {loan['due_date']}.

Mohon segera kembalikan buku Anda untuk menghindari denda atau sanksi lainnya, yaitu membayar buku yang dipinjam.

Terima kasih,
Sistem Pinjam Buku Gramedia
"""
                send_email(loan['borrower_email'], subject, body)
            else:
                print(f"Peminjam {loan['borrower_name_manual']} tidak memiliki email untuk notifikasi keterlambatan buku {loan['title']}.")

    conn.close()
    print("Pengecekan dan pengiriman pengingat/notifikasi email selesai.")

# --- Google Sheets Functions START ---
def initialize_gspread_connection():
    global GOOGLE_SHEETS_WORKSHEET
    try:
        scope = [
            'https://www.googleapis.com/auth/spreadsheets',
            'https://www.googleapis.com/auth/drive'
        ]
        creds_json_str = os.environ.get('GSPREAD_CREDENTIALS')
        if creds_json_str:
            creds_info = json.loads(creds_json_str)
            creds = Credentials.from_service_account_info(creds_info, scopes=scope)
            print("Menggunakan kredensial dari environment variable.")
        else:
            if not os.path.exists(CREDENTIALS_FILE):
                print(f"File '{CREDENTIALS_FILE}' tidak ditemukan dan GSPREAD_CREDENTIALS env var tidak diset. Google Sheets integration skipped.")
                GOOGLE_SHEETS_WORKSHEET = None
                return
            creds = Credentials.from_service_account_file(CREDENTIALS_FILE, scopes=scope)
            print(f"Menggunakan kredensial dari file lokal '{CREDENTIALS_FILE}'.")

        gc = gspread.authorize(creds)
        spreadsheet = gc.open(SPREADSHEET_NAME)
        GOOGLE_SHEETS_WORKSHEET = spreadsheet.sheet1
        print(f"Berhasil terhubung ke Google Sheet: {SPREADSHEET_NAME}")
    except Exception as e:
        print(f"Error saat menginisialisasi Google Sheets: {e}")
        print("Pastikan:")
        print(f"1. File '{CREDENTIALS_FILE}' ada dan berisi kredensial yang valid ATAU GSPREAD_CREDENTIALS env var diset.")
        print(f"2. Google Sheet dengan nama '{SPREADSHEET_NAME}' ada di akun Google Anda.")
        print("3. Anda telah berbagi Google Sheet tersebut dengan 'Client email' dari service account Anda.")
        GOOGLE_SHEETS_WORKSHEET = None

def add_loan_to_gsheet(book_id, title, author, borrower_name, borrower_email, petugas_name, loan_datetime, due_date):
    if GOOGLE_SHEETS_WORKSHEET is None:
        print("Koneksi Google Sheet belum terinisialisasi. Data tidak dapat ditambahkan.")
        return False

    loan_date_str_with_time = loan_datetime.strftime('%d/%m/%Y %H:%M')

    data_row = [
        book_id,
        title,
        author,
        borrower_name,
        borrower_email,
        petugas_name,
        loan_date_str_with_time,
        due_date,
        ''
    ]
    try:
        GOOGLE_SHEETS_WORKSHEET.append_row(data_row)
        print(f"Data peminjaman buku '{title}' berhasil ditambahkan ke Google Sheet.")
        return True
    except Exception as e:
        print(f"Gagal menambahkan data peminjaman ke Google Sheet: {e}")
        return False

def update_return_in_gsheet(book_id, borrower_name, loan_date_str, return_datetime):
    if GOOGLE_SHEETS_WORKSHEET is None:
        print("Koneksi Google Sheet belum terinisialisasi. Data tidak dapat diupdate.")
        return False

    return_date_str_with_time = return_datetime.strftime('%d/%m/%Y %H:%M')

    try:
        all_data = GOOGLE_SHEETS_WORKSHEET.get_all_values()

        header = all_data[0]
        data_rows = all_data[1:]

        id_buku_col = header.index('ID Buku')
        nama_peminjam_col = header.index('Nama Peminjam')
        tanggal_pinjam_col = header.index('Tanggal Pinjam (beserta jam)')
        tanggal_kembali_col = header.index('Tanggal Pengembalian (beserta jam)')

        row_index_to_update = -1

        for i, row in enumerate(data_rows):
            if (len(row) > max(id_buku_col, nama_peminjam_col, tanggal_pinjam_col, tanggal_kembali_col)):

                gsheet_loan_date_part = row[tanggal_pinjam_col].split(' ')[0]
                loan_date_for_comparison = datetime.strptime(loan_date_str, '%Y-%m-%d %H:%M:%S').strftime('%d/%m/%Y')

                if (row[id_buku_col] == book_id and
                    row[nama_peminjam_col] == borrower_name and
                    gsheet_loan_date_part == loan_date_for_comparison and
                    row[tanggal_kembali_col] == ''):

                    row_index_to_update = i + 2
                    break

        if row_index_to_update != -1:
            GOOGLE_SHEETS_WORKSHEET.update_cell(row_index_to_update, tanggal_kembali_col + 1, return_date_str_with_time)
            print(f"Data pengembalian buku '{book_id}' oleh '{borrower_name}' berhasil diupdate di Google Sheet.")
            return True
        else:
            print(f"Peminjaman buku '{book_id}' oleh '{borrower_name}' pada tanggal '{loan_date_str}' tidak ditemukan di Google Sheet untuk diupdate.")
            return False

    except Exception as e:
        print(f"Gagal mengupdate data pengembalian di Google Sheet: {e}")
        return False
# --- Google Sheets Functions END ---


# --- Routes Aplikasi ---

@app.before_request
def before_request():
    pass


@app.route('/')
def index():
    if current_user.is_authenticated:
        if current_user.is_admin():
            return redirect(url_for('admin_dashboard'))
        elif current_user.is_developer():
            return redirect(url_for('developer_dashboard'))
        else:
            return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

# --- ROUTE LOGIN YANG DIPERBARUI ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        if current_user.is_admin():
            return redirect(url_for('admin_dashboard'))
        elif current_user.is_developer():
            return redirect(url_for('developer_dashboard'))
        else:
            return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = get_db_connection()
        user_data = conn.execute('SELECT id, username, password, email, role, full_name, registration_date, reset_token, reset_token_expiration FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()

        # Mendapatkan nilai failed_attempts saat ini dari session, default ke 0
        current_failed_attempts = session.get('failed_attempts', 0)
        print(f"DEBUG_LOGIN: Sebelum update, failed_attempts = {current_failed_attempts}") # DEBUG PRINT

        if user_data:
            if check_password_hash(user_data['password'], password):
                # Login berhasil, reset percobaan gagal
                session['failed_attempts'] = 0
                print(f"DEBUG_LOGIN: Login BERHASIL untuk {username}. failed_attempts direset: {session['failed_attempts']}") # DEBUG PRINT
                user_obj = User(user_data['id'], user_data['username'], user_data['password'], user_data['email'], user_data['role'], user_data['full_name'], user_data['registration_date'], user_data['reset_token'], user_data['reset_token_expiration'])
                login_user(user_obj)
                flash(f'Login berhasil sebagai {user_obj.username}!', 'success')

                if user_obj.is_admin():
                    return redirect(url_for('admin_dashboard'))
                elif user_obj.is_developer():
                    return redirect(url_for('developer_dashboard'))
                else:
                    return redirect(url_for('dashboard'))
            else:
                # Password salah
                session['failed_attempts'] = current_failed_attempts + 1 # Menggunakan current_failed_attempts
                print(f"DEBUG_LOGIN: Password SALAH untuk {username}. failed_attempts sekarang: {session['failed_attempts']}") # DEBUG PRINT
                flash('Username atau password salah.', 'danger')
        else:
            # Username tidak ditemukan
            session['failed_attempts'] = current_failed_attempts + 1 # Menggunakan current_failed_attempts
            print(f"DEBUG_LOGIN: Username TIDAK DITEMUKAN: {username}. failed_attempts sekarang: {session['failed_attempts']}") # DEBUG PRINT
            flash('Username atau password salah.', 'danger')

    # <<< PERHATIKAN PERUBAHAN DI SINI >>>
    # Definisikan whatsapp_message sebelum render_template
    whatsapp_message = "Halo%2C%20saya%20memiliki%20kendala%20pada%20saat%20login%2C%20tolong%20perbaiki%20masalah%20loginnya."

    # Gabungkan semua argumen ke dalam SATU panggilan render_template
    print(f"DEBUG_LOGIN: Mengirim ke template login.html dengan failed_attempts = {session.get('failed_attempts', 0)}") # DEBUG PRINT
    return render_template('login.html',
                           failed_attempts=session.get('failed_attempts', 0),
                           max_attempts=MAX_LOGIN_ATTEMPTS,
                           whatsapp_message=whatsapp_message) # whatsapp_message ditambahkan di sini


# --- Rute untuk meminta reset password (langkah 1) ---
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email').strip()
        conn = get_db_connection()
        user = conn.execute('SELECT id, username, email FROM users WHERE email = ?', (email,)).fetchone()

        if user:
            token = secrets.token_urlsafe(32)
            expiration = datetime.now() + timedelta(minutes=RESET_TOKEN_EXPIRATION_MINUTES)

            conn.execute('UPDATE users SET reset_token = ?, reset_token_expiration = ? WHERE id = ?',
                         (token, expiration.strftime('%Y-%m-%d %H:%M:%S.%f'), user['id']))
            conn.commit()

            reset_link = url_for('reset_password_confirm', token=token, _external=True)
            subject = 'Permintaan Reset Password Sistem Pinjam Buku Gramedia'
            body = f"""
Halo {user['username']},

Anda telah meminta reset password untuk akun Anda di Sistem Pinjam Buku Gramedia.

Untuk mereset password Anda, klik tautan berikut:
{reset_link}

Tautan ini akan kedaluwarsa dalam {RESET_TOKEN_EXPIRATION_MINUTES} menit.

Jika Anda tidak meminta reset password ini, mohon abaikan email ini.

Terima kasih,
Sistem Pinjam Buku Gramedia
"""
            if send_email(user['email'], subject, body):
                flash('Link reset password telah dikirim ke email Anda. Silakan cek inbox (dan folder spam).', 'success')
            else:
                flash('Gagal mengirim email reset password. Silakan coba lagi nanti.', 'danger')
        else:
            flash('Email tidak ditemukan.', 'danger')

        conn.close()
        return redirect(url_for('login'))

    return render_template('forgot_password.html')

# --- Rute untuk mengkonfirmasi reset password (langkah 2) ---
@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password_confirm(token):
    conn = get_db_connection()
    user = conn.execute('SELECT id, username, email, reset_token, reset_token_expiration FROM users WHERE reset_token = ?', (token,)).fetchone()

    if not user:
        flash('Token reset tidak valid atau sudah digunakan.', 'danger')
        conn.close()
        return redirect(url_for('login'))

    try: # Tambahkan try-except untuk parsing datetime
        expiration_time = datetime.strptime(user['reset_token_expiration'], '%Y-%m-%d %H:%M:%S.%f')
    except (ValueError, TypeError): # Tangani jika format tidak sesuai atau None
        flash('Format waktu kedaluwarsa token tidak valid. Mohon minta reset password baru.', 'danger')
        conn.close()
        return redirect(url_for('forgot_password'))

    if datetime.now() > expiration_time:
        flash('Token reset telah kedaluwarsa. Mohon minta reset password baru.', 'danger')
        conn.close()
        # Bersihkan token yang kedaluwarsa dari DB
        conn = get_db_connection()
        conn.execute('UPDATE users SET reset_token = NULL, reset_token_expiration = NULL WHERE id = ?', (user['id'],))
        conn.commit()
        conn.close()
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if not new_password or not confirm_password:
            flash('Password baru dan konfirmasi password harus diisi.', 'danger')
            conn.close()
            return render_template('reset_password_confirm.html', token=token)

        if new_password != confirm_password:
            flash('Password baru dan konfirmasi password tidak cocok.', 'danger')
            conn.close()
            return render_template('reset_password_confirm.html', token=token)

        hashed_password = generate_password_hash(new_password, method='pbkdf2:sha256')

        try:
            conn.execute('UPDATE users SET password = ?, reset_token = NULL, reset_token_expiration = NULL WHERE id = ?',
                         (hashed_password, user['id']))
            conn.commit()

            subject_success = 'Password Akun Sistem Pinjam Buku Gramedia Anda Berhasil Direset'
            body_success = f"""
Halo {user['username']},

Password untuk akun Anda di Sistem Pinjam Buku Gramedia telah berhasil direset pada {datetime.now().strftime('%d-%m-%Y %H:%M:%S')}.

Jika Anda tidak melakukan perubahan ini, mohon segera hubungi administrator sistem.

Terima kasih,
Sistem Pinjam Buku Gramedia
"""
            send_email(user['email'], subject_success, body_success)
            flash('Password Anda berhasil direset! Silakan login dengan password baru Anda. Notifikasi telah dikirim ke email Anda.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            conn.rollback()
            flash(f'Terjadi kesalahan saat mereset password: {e}', 'danger')
        finally:
            conn.close()

    conn.close()
    return render_template('reset_password_confirm.html', token=token)

# --- LOGOUT ---
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Anda telah logout.', 'info')
    return redirect(url_for('login'))

# --- REGISTER USER BARU (Peminjam Default) ---
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        if current_user.is_admin():
            return redirect(url_for('admin_dashboard'))
        elif current_user.is_developer():
            return redirect(url_for('developer_dashboard'))
        else:
            return redirect(url_for('dashboard'))

    if request.method == 'POST':
        full_name = request.form['full_name'].strip()
        username = request.form['username'].strip()
        password = request.form['password'].strip()
        email = request.form['email'].strip()

        if not full_name or not username or not password or not email:
            flash('Nama Lengkap, Username, password, dan email harus diisi.', 'error')
            return render_template('register.html', full_name=full_name, username=username, email=email)

        conn = get_db_connection()
        cursor = conn.cursor()

   #     cursor.execute('SELECT id FROM users WHERE nik = ?', (nik,))
   #     existing_nik = cursor.fetchone()
   #     if existing_nik:
   #         flash('NIK sudah terdaftar. Silakan gunakan NIK lain atau login.', 'error')
   #         conn.close()
    #        return render_template('register.html', nik=nik, full_name=full_name, username=username, email=email)

        cursor.execute('SELECT id FROM users WHERE username = ?', (username,))
        existing_user = cursor.fetchone()
        if existing_user:
            flash('Username sudah digunakan. Silakan pilih username lain.', 'error')
            conn.close()
            return render_template('register.html', full_name=full_name, username=username, email=email)

        cursor.execute('SELECT id FROM users WHERE email = ?', (email,))
        existing_email = cursor.fetchone()
        if existing_email:
            flash('Email ini sudah terdaftar. Silakan gunakan email lain atau login.', 'error')
            conn.close()
            return render_template('register.html', full_name=full_name, username=username, email=email)

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        try:
            cursor.execute('INSERT INTO users (full_name, username, password, email, role, registration_date) VALUES (?, ?, ?, ?, ?, ?)',
                           (full_name, username, hashed_password, email, 'peminjam', datetime.now()))
            conn.commit()
            flash('Registrasi berhasil! Silakan login.', 'success')
            return redirect(url_for('login'))
        except sqlite3.Error as e:
            flash(f'Terjadi kesalahan database: {e}', 'error')
            conn.rollback()
        finally:
            conn.close()

    return render_template('register.html')

# --- ROUTE PROFIL ---
@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', user=current_user)


# --- DASHBOARD PEMINJAM ---
@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.is_admin():
        flash("Anda adalah Admin. Silakan gunakan Dashboard Admin.", 'info')
        return redirect(url_for('admin_dashboard'))
    elif current_user.is_developer():
        flash("Anda adalah Developer. Silakan gunakan Dashboard Developer.", 'info')
        return redirect(url_for('developer_dashboard'))
    # No else here, as the user is automatically redirected if not admin/developer
    # The current user (peminjam) will proceed with the dashboard logic below

    conn = get_db_connection()

    # Query untuk Daftar Buku
    books = conn.execute('''
        SELECT
            b.id,
            b.title,
            b.author,
            b.status,
            -- Prioritize borrower_name_manual, then full_name, then username
            COALESCE(l.borrower_name_manual, u.full_name, u.username) AS current_borrower_name
        FROM books b
        LEFT JOIN loans l ON b.id = l.book_id AND l.return_date IS NULL
        LEFT JOIN users u ON l.user_id = u.id
        ORDER BY b.title ASC
    ''').fetchall()

    # Query untuk Daftar Peminjaman Aktif (milik peminjam yang login)
    loans = conn.execute('''
        SELECT
            l.id as loan_id,
            b.title,
            b.author,
            l.loan_date,
            l.due_date,
            l.return_date,
            b.id as book_id,
            l.recorded_by,
            -- Prioritize borrower_name_manual, then full_name, then username
            COALESCE(l.borrower_name_manual, bu.full_name, bu.username) AS borrower_display_name,
            l.borrower_email,
            -- Prioritize recorded_by, then petugas_name_manual, then username
            COALESCE(l.recorded_by, l.petugas_name_manual, pu.username, 'Tidak Diketahui') AS petugas_display_name
        FROM loans l
        JOIN books b ON l.book_id = b.id
        LEFT JOIN users bu ON l.user_id = bu.id -- Alias for Borrower User
        LEFT JOIN users pu ON l.petugas_id = pu.id -- Alias for Petugas User
        WHERE (l.user_id = ? OR (l.user_id IS NULL AND l.borrower_email = ?)) AND l.return_date IS NULL
        ORDER BY l.due_date ASC
    ''', (current_user.id, current_user.email)).fetchall()
    conn.close()

    today = datetime.now().date()
    overdue_loans = []
    for loan in loans:
        due_date_obj = datetime.strptime(loan['due_date'], '%Y-%m-%d').date()
        if today > due_date_obj:
            overdue_loans.append(loan)

    # Definisikan whatsapp_message untuk dashboard peminjam
    whatsapp_message = "Halo%2C%20saya%20ingin%20melaporkan%20masalah%20terkait%20peminjaman%20buku%20terjadi%20error%20atau%20gagal%20meminjam%20buku."

    # Kirimkan whatsapp_message ke template
    return render_template('dashboard.html',
                           books=books,
                           loans=loans,
                           overdue_loans=overdue_loans,
                           current_user=current_user,
                           whatsapp_message=whatsapp_message) # Tambahan ini

# --- DASHBOARD ADMIN ---
@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    if not current_user.is_admin():
        flash('Anda tidak memiliki izin untuk mengakses halaman ini.', 'danger')
        if current_user.is_developer():
            return redirect(url_for('developer_dashboard'))
        else:
            return redirect(url_for('dashboard'))

    conn = get_db_connection()

    # Query untuk Daftar Buku
    books = conn.execute('''
        SELECT
            b.id,
            b.title,
            b.author,
            b.status,
            -- Prioritize borrower_name_manual, then full_name, then username
            COALESCE(l.borrower_name_manual, u.full_name, u.username) AS current_borrower_name
        FROM books b
        LEFT JOIN loans l ON b.id = l.book_id AND l.return_date IS NULL
        LEFT JOIN users u ON l.user_id = u.id
        ORDER BY b.title ASC
    ''').fetchall()

    # Query untuk Daftar Peminjaman Aktif
    loans = conn.execute('''
        SELECT
            l.id as loan_id,
            b.title,
            b.author,
            l.loan_date,
            l.due_date,
            l.return_date,
            l.recorded_by,
            b.id as book_id,
            -- Prioritize borrower_name_manual, then full_name, then username
            COALESCE(l.borrower_name_manual, bu.full_name, bu.username) AS borrower_display_name,
            l.borrower_email,
            -- Prioritize recorded_by, then petugas_name_manual, then username
            COALESCE(l.recorded_by, l.petugas_name_manual, pu.username, 'Tidak Diketahui') AS petugas_display_name
        FROM loans l
        JOIN books b ON l.book_id = b.id
        LEFT JOIN users bu ON l.user_id = bu.id -- Alias for Borrower User
        LEFT JOIN users pu ON l.petugas_id = pu.id -- Alias for Petugas User
        WHERE l.return_date IS NULL
        ORDER BY l.due_date ASC
    ''').fetchall()
    conn.close()

    today = datetime.now().date()
    overdue_loans = []
    for loan in loans:
        due_date_obj = datetime.strptime(loan['due_date'], '%Y-%m-%d').date()
        if today > due_date_obj:
            overdue_loans.append(loan)

    # Definisikan whatsapp_message untuk admin dashboard
    whatsapp_message = "Halo%2C%20saya%20ingin%20melaporkan%20masalah%20terkait%20penambahan%20id%20dan%20judul%20buku%20baru%20kedalam%20daftar%20buku."

    # Kirimkan whatsapp_message ke template
    return render_template('admin_dashboard.html',
                           books=books,
                           loans=loans,
                           overdue_loans=overdue_loans,
                           current_user=current_user,
                           whatsapp_message=whatsapp_message) # Tambahan ini

# --- ROUTE DASHBOARD DEVELOPER ---
@app.route('/developer_dashboard')
@login_required
def developer_dashboard():
    if not current_user.is_developer():
        flash('Anda tidak memiliki izin untuk mengakses halaman ini.', 'danger')
        if current_user.is_admin():
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('dashboard'))

    conn = get_db_connection()

    # Query untuk Daftar Buku
    books = conn.execute('''
        SELECT
            b.id,
            b.title,
            b.author,
            b.status,
            -- Prioritize borrower_name_manual, then full_name, then username
            COALESCE(l.borrower_name_manual, u.full_name, u.username) AS current_borrower_name
        FROM books b
        LEFT JOIN loans l ON b.id = l.book_id AND l.return_date IS NULL
        LEFT JOIN users u ON l.user_id = u.id
        ORDER BY b.title ASC
    ''').fetchall()

    # Query untuk Daftar Peminjaman Aktif
    loans = conn.execute('''
        SELECT
            l.id as loan_id,
            b.title,
            b.author,
            l.loan_date,
            l.due_date,
            l.return_date,
            l.recorded_by,
            b.id as book_id,
            -- Prioritize borrower_name_manual, then full_name, then username
            COALESCE(l.borrower_name_manual, bu.full_name, bu.username) AS borrower_display_name,
            l.borrower_email,
            -- Prioritize recorded_by, then petugas_name_manual, then username
            COALESCE(l.recorded_by, l.petugas_name_manual, pu.username, 'Tidak Diketahui') AS petugas_display_name
        FROM loans l
        JOIN books b ON l.book_id = b.id
        LEFT JOIN users bu ON l.user_id = bu.id -- Alias for Borrower User
        LEFT JOIN users pu ON l.petugas_id = pu.id -- Alias for Petugas User
        WHERE l.return_date IS NULL
        ORDER BY l.due_date ASC
    ''').fetchall()
    conn.close()

    today = datetime.now().date()
    overdue_loans = []
    for loan in loans:
        due_date_obj = datetime.strptime(loan['due_date'], '%Y-%m-%d').date()
        if today > due_date_obj:
            overdue_loans.append(loan)

    # Definisikan whatsapp_message untuk developer dashboard
    whatsapp_message = "Halo%2C%20saya%20ingin%20melaporkan%20masalah%20terkait%20penambahan%20id%20dan%20judul%20buku%20baru%20kedalam%20daftar%20buku%20dan%20user%20peminjam%20yang%20gagal%20di%20akses."

    # Kirimkan whatsapp_message ke template
    return render_template('developer_dashboard.html',
                           books=books,
                           loans=loans,
                           overdue_loans=overdue_loans,
                           current_user=current_user,
                           whatsapp_message=whatsapp_message) # Tambahan ini


@app.route('/add_book', methods=['POST'])
@login_required
def add_book():
    if not current_user.is_admin() and not current_user.is_developer():
        flash('Anda tidak memiliki izin untuk menambahkan buku.', 'danger')
        return redirect(url_for('dashboard'))

    book_id = request.form['book_id'].strip()
    title = request.form['title'].strip()
    author = request.form['author'].strip()

    conn = get_db_connection()

    if not book_id:
        book_id = generate_random_id()
        while conn.execute('SELECT 1 FROM books WHERE id = ?', (book_id,)).fetchone():
            book_id = generate_random_id()
    else:
        existing_book = conn.execute('SELECT 1 FROM books WHERE id = ?', (book_id,)).fetchone()
        if existing_book:
            flash(f'ID buku "{book_id}" sudah ada. Mohon gunakan ID lain.', 'danger')
            conn.close()
            return redirect(url_for('admin_dashboard') if current_user.is_admin() else url_for('developer_dashboard'))

    try:
        conn.execute('INSERT INTO books (id, title, author) VALUES (?, ?, ?)', (book_id, title, author))
        conn.commit()
        flash(f'Buku "{title}" dengan ID "{book_id}" berhasil ditambahkan!', 'success')
    except sqlite3.IntegrityError:
        flash('Terjadi kesalahan saat menambahkan buku. Mungkin ID sudah ada.', 'danger')
    except Exception as e:
        flash(f'Terjadi kesalahan tak terduga: {e}', 'danger')
    finally:
        conn.close()

    return redirect(url_for('admin_dashboard') if current_user.is_admin() else url_for('developer_dashboard'))

# --- Rute Impor Buku dari CSV ---
@app.route('/import_books', methods=['GET', 'POST'])
@login_required
def import_books():
    if not current_user.is_admin() and not current_user.is_developer():
        flash('Anda tidak memiliki izin untuk mengimpor buku.', 'danger')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        if 'file' not in request.files:
            flash('Tidak ada bagian file.', 'danger')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('Tidak ada file yang dipilih.', 'danger')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
            file.save(filename)

            imported_count = 0
            skipped_count = 0
            conn = get_db_connection()
            try:
                with open(filename, 'r', encoding='utf-8') as csvfile:
                    reader = csv.reader(csvfile)
                    header = next(reader)

                    if header != ['id_buku', 'judul_buku', 'penulis']:
                        flash("Format header CSV tidak sesuai. Harusnya: id_buku,judul_buku,penulis", 'danger')
                        conn.close()
                        os.remove(filename)
                        return redirect(request.url)

                    for row in reader:
                        if len(row) == 3:
                            book_id, title, author = [item.strip() for item in row]

                            existing_book = conn.execute('SELECT 1 FROM books WHERE id = ?', (book_id,)).fetchone()
                            if existing_book:
                                skipped_count += 1
                                print(f"Melewatkan buku dengan ID '{book_id}': sudah ada.")
                                continue

                            try:
                                conn.execute('INSERT INTO books (id, title, author) VALUES (?, ?, ?)', (book_id, title, author))
                                imported_count += 1
                            except sqlite3.IntegrityError as e:
                                skipped_count += 1
                                print(f"Error insert buku ID '{book_id}': {e}")
                            except Exception as e:
                                skipped_count += 1
                                print(f"Error tak terduga pada baris '{row}': {e}")
                        else:
                            skipped_count += 1
                            print(f"Melewatkan baris tidak valid: {row}")
                    conn.commit()
                    flash(f'Impor selesai! {imported_count} buku berhasil ditambahkan, {skipped_count} dilewati (ID duplikat/format salah).', 'success')
            except Exception as e:
                flash(f'Terjadi kesalahan saat membaca file CSV: {e}', 'danger')
            finally:
                conn.close()
                os.remove(filename)
            return redirect(url_for('admin_dashboard') if current_user.is_admin() else url_for('developer_dashboard'))
        else:
            flash('Jenis file tidak diizinkan. Hanya file CSV.', 'danger')
            return redirect(request.url)

    return render_template('import_books.html', current_user=current_user)

# --- Rute Pinjam Buku (Diakses oleh Admin, Developer, dan Peminjam) ---
@app.route('/borrow_book/<string:book_id>', methods=['GET', 'POST'])
@login_required
def borrow_book(book_id):
    conn = get_db_connection()
    book = conn.execute('SELECT * FROM books WHERE id = ?', (book_id,)).fetchone()

    if not book:
        flash('Buku tidak ditemukan.', 'danger')
        conn.close()
        if current_user.is_admin():
            return redirect(url_for('admin_dashboard'))
        elif current_user.is_developer():
            return redirect(url_for('developer_dashboard'))
        else:
            return redirect(url_for('dashboard'))

    if book['status'] == 'Dipinjam':
        flash('Buku ini sedang dipinjam.', 'danger')
        conn.close()
        if current_user.is_admin():
            return redirect(url_for('admin_dashboard'))
        elif current_user.is_developer():
            return redirect(url_for('developer_dashboard'))
        else:
            return redirect(url_for('dashboard'))

    if request.method == 'POST':
        borrower_name = request.form.get('borrower_name', '').strip()
        borrower_email = request.form.get('borrower_email', '').strip()
        petugas_name_manual = request.form.get('petugas_name_manual', '').strip()
        recorded_by = request.form.get('recorded_by', '').strip()

        user_id = current_user.id # ID user yang sedang login (bisa peminjam atau admin/developer)

        # Logika untuk menentukan nama petugas yang akan disimpan
        # Prioritaskan recorded_by dari form, jika kosong, gunakan username petugas yang login
        petugas_name_to_save = recorded_by # Gunakan recorded_by sebagai prioritas utama
        if not petugas_name_to_save:
            petugas_name_to_save = petugas_name_manual # Jika recorded_by kosong, coba petugas_name_manual
        if not petugas_name_to_save:
            petugas_name_to_save = current_user.username # Jika keduanya kosong, gunakan username petugas yang login

        notification_recipients = [PETUGAS_NOTIFICATION_EMAIL]
  #      if DEVELOPER_NOTIFICATION_EMAIL and DEVELOPER_NOTIFICATION_EMAIL not in notification_recipients:
  #          notification_recipients.append(DEVELOPER_NOTIFICATION_EMAIL)

        if not borrower_name:
            flash('Nama peminjam tidak boleh kosong. Silakan isi.', 'danger')
            conn.close()
            default_email_val_on_fail = request.form.get('borrower_email', '')
            return render_template('borrow_confirm.html', book=book, default_borrower=borrower_name, default_email=default_email_val_on_fail, default_petugas=petugas_name_manual, recorded_by_value=recorded_by, current_user=current_user)

        if not recorded_by: # Pastikan recorded_by wajib diisi
            flash('Nama Petugas yang Mencatat wajib diisi.', 'danger')
            conn.close()
            return render_template('borrow_confirm.html', book=book, default_borrower=borrower_name, default_email=borrower_email, default_petugas=petugas_name_manual, recorded_by_value=recorded_by, current_user=current_user)

        current_datetime_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        due_date_obj = datetime.now() + timedelta(days=4)
        due_date_str = due_date_obj.strftime('%Y-%m-%d')

        try:
            # Simpan user_id dari peminjam yang login jika ada, atau NULL jika peminjam non-user
            # Simpan petugas_id dari petugas yang login
            conn.execute('''
                INSERT INTO loans (book_id, user_id, borrower_name_manual, borrower_email, petugas_id, petugas_name_manual, loan_date, due_date, recorded_by)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (book_id, user_id if current_user.is_peminjam() else None, borrower_name, borrower_email, current_user.id, petugas_name_to_save, current_datetime_str, due_date_str, recorded_by))

            conn.execute('UPDATE books SET status = "Dipinjam" WHERE id = ?', (book_id,))
            conn.commit()
            flash(f'Buku "{book["title"]}" berhasil dipinjam oleh {borrower_name}!', 'success')

            add_loan_to_gsheet(
                book_id,
                book['title'],
                book['author'],
                borrower_name,
                borrower_email,
                petugas_name_to_save,
                datetime.strptime(current_datetime_str, '%Y-%m-%d %H:%M:%S'),
                due_date_str
            )

            if borrower_email:
                subject_peminjam = f'Konfirmasi Peminjaman Buku: {book["title"]}'
                body_peminjam = f"""
Halo {borrower_name},

Anda telah berhasil meminjam buku dari sistem Pinjam Buku kami. Berikut detail peminjaman Anda:

ID Buku: {book_id}
Judul Buku: {book['title']}
Penulis: {book['author']}
Tanggal Pinjam: {datetime.strptime(current_datetime_str, '%Y-%m-%d %H:%M:%S').strftime('%d/%m/%Y %H:%M')}
Batas Waktu Pengembalian: {due_date_str}
Petugas yang Mencatat: {recorded_by}

Mohon kembalikan buku tepat waktu, Jika tidak dikembalikan sesuai waktu yang ditentukan anda akan dikenakan denda.
dan jika buku yang di pinjam rusak maka buku harus dibayar.

Terima kasih,
Sistem Pinjam Buku Gramedia
"""
                email_sent_peminjam = send_email(borrower_email, subject_peminjam, body_peminjam)
                if email_sent_peminjam:
                    flash('Email konfirmasi peminjaman berhasil dikirim ke peminjam.', 'info')
                else:
                    flash('Gagal mengirim email konfirmasi peminjaman ke peminjam. Cek konfigurasi SMTP.', 'warning')
            else:
                flash('Email peminjam tidak disediakan, tidak dapat mengirim konfirmasi email ke peminjam.', 'warning')

            subject_notif = f'Notifikasi Peminjaman Baru: {book["title"]}'
            body_notif = f"""
Halo, PIC Book

Sebuah buku baru saja dipinjam dari sistem Pinjam Buku Gramedia:

ID Buku: {book_id}
Judul Buku: {book['title']}
Penulis: {book['author']}
Dipinjam Oleh: {borrower_name} (Email: {borrower_email if borrower_email else 'Tidak Ada'})
Tanggal Pinjam: {datetime.strptime(current_datetime_str, '%Y-%m-%d %H:%M:%S').strftime('%d/%m/%Y %H:%M')}
Batas Waktu Pengembalian: {due_date_str}
Dicatat oleh Petugas: {recorded_by}

Ini adalah notifikasi otomatis.

Terima kasih,
Sistem Pinjam Buku Gramedia
"""
            for recipient in notification_recipients:
                email_sent_notif = send_email(recipient, subject_notif, body_notif)
                if email_sent_notif:
                    flash(f'Notifikasi peminjaman berhasil dikirim ke Admin', 'info')
                else:
                    flash(f'Gagal mengirim notifikasi peminjaman ke Admin. Cek konfigurasi SMTP.', 'warning')

        except Exception as e:
            flash(f'Terjadi kesalahan saat memproses peminjaman: {e}', 'danger')
        finally:
            conn.close()

        if current_user.is_admin():
            return redirect(url_for('admin_dashboard', loan_success='true'))
        elif current_user.is_developer():
            return redirect(url_for('developer_dashboard', loan_success='true'))
        else:
            return redirect(url_for('dashboard', loan_success='true'))

    conn.close()
    # Default values for the borrow form
    default_borrower_val = current_user.full_name if current_user.full_name else current_user.username if current_user.is_peminjam() else ""
    default_email_val = current_user.email if current_user.is_peminjam() else ""
    default_petugas_val = current_user.full_name if current_user.full_name else current_user.username # Petugas default ke nama petugas yang login

    return render_template('borrow_confirm.html',
                           book=book,
                           default_borrower=default_borrower_val,
                           default_email=default_email_val,
                           default_petugas=default_petugas_val, # Menggunakan default_petugas_val
                           recorded_by_value=default_petugas_val, # Menggunakan default_petugas_val untuk recorded_by juga
                           current_user=current_user)


@app.route('/return_book/<int:loan_id>')
@login_required
def return_book(loan_id):
    if not current_user.is_admin() and not current_user.is_peminjam() and not current_user.is_developer():
        flash('Anda tidak memiliki izin untuk mencatat pengembalian buku.', 'danger')
        return redirect(url_for('dashboard'))

    conn = get_db_connection()

    loan_details = conn.execute('''
        SELECT
            l.id AS loan_id,
            b.title,
            b.author,
            l.borrower_name_manual,
            l.borrower_email,
            l.loan_date,
            l.due_date,
            -- Prioritize recorded_by, then petugas_name_manual, then username
            COALESCE(l.recorded_by, l.petugas_name_manual, pu.username) AS petugas_display_name,
            b.id AS book_id,
            l.user_id as loan_user_id,
            l.recorded_by -- Pastikan kolom recorded_by diambil
        FROM loans l
        JOIN books b ON l.book_id = b.id
        LEFT JOIN users pu ON l.petugas_id = pu.id -- Alias for Petugas User
        WHERE l.id = ? AND l.return_date IS NULL
    ''', (loan_id,)).fetchone()

    if loan_details:
        if current_user.is_peminjam() and (loan_details['loan_user_id'] != current_user.id and loan_details['borrower_email'] != current_user.email):
             flash('Anda hanya dapat mengembalikan buku yang Anda pinjam.', 'danger')
             conn.close()
             return redirect(url_for('dashboard'))

        try:
            book_id = loan_details['book_id']
            current_return_datetime_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

            conn.execute('UPDATE loans SET return_date = ? WHERE id = ?', (current_return_datetime_str, loan_id))
            conn.execute('UPDATE books SET status = "Tersedia" WHERE id = ?', (book_id,))
            conn.commit()
            flash('Buku berhasil dikembalikan!', 'success')

            update_return_in_gsheet(
                loan_details['book_id'],
                loan_details['borrower_name_manual'],
                loan_details['loan_date'],
                datetime.strptime(current_return_datetime_str, '%Y-%m-%d %H:%M:%S')
            )

            borrower_email = loan_details['borrower_email']
            if borrower_email:
                subject_peminjam_kembali = f'Konfirmasi Pengembalian Buku: {loan_details["title"]}'
                body_peminjam_kembali = f"""
Halo {loan_details['borrower_name_manual']},

Buku "{loan_details['title']}" oleh {loan_details['author']} yang Anda pinjam telah berhasil dikembalikan.

Detail Peminjaman:
ID Buku: {book_id}
Tanggal Pinjam: {loan_details['loan_date']}
Tanggal Dikembalikan: {datetime.strptime(current_return_datetime_str, '%Y-%m-%d %H:%M:%S').strftime('%d/%m/%Y %H:%M')}
Petugas yang Mencatat: {loan_details['recorded_by']}

Terima kasih telah menggunakan layanan Sistem Pinjam kami.

Hormat kami,
Sistem Pinjam Buku Gramedia
"""
                email_sent_peminjam_kembali = send_email(borrower_email, subject_peminjam_kembali, body_peminjam_kembali)
                if email_sent_peminjam_kembali:
                    flash('Email konfirmasi pengembalian berhasil dikirim ke peminjam.', 'info')
                else:
                    flash('Gagal mengirim email konfirmasi pengembalian ke peminjam. Cek konfigurasi SMTP.', 'warning')
            else:
                flash('Email peminjam tidak tersedia untuk konfirmasi pengembalian.', 'warning')

            subject_notif_kembali = f'Notifikasi Pengembalian Buku: {loan_details["title"]}'
            body_notif_kembali = f"""
Halo, PIC Book

Buku berikut telah dikembalikan ke sistem Pinjam Buku Gramedia:

ID Buku: {book_id}
Judul Buku: {loan_details['title']}
Penulis: {loan_details['author']}
Dipinjam Oleh: {loan_details['borrower_name_manual']} (Email: {borrower_email if borrower_email else 'Tidak Ada'})
Tanggal Pinjam: {loan_details['loan_date']}
Tanggal Dikembalikan: {datetime.strptime(current_return_datetime_str, '%Y-%m-%d %H:%M:%S').strftime('%d/%m/%Y %H:%M')}
Dicatat oleh Petugas (Peminjaman): {loan_details['recorded_by']}
Dikembalikan oleh Petugas (Saat Ini): {current_user.username}

Ini adalah notifikasi otomatis.

Terima kasih,
Sistem Pinjam Buku Gramedia
"""
            notification_recipients = [PETUGAS_NOTIFICATION_EMAIL]
  #          if DEVELOPER_NOTIFICATION_EMAIL and DEVELOPER_NOTIFICATION_EMAIL not in notification_recipients:
  #              notification_recipients.append(DEVELOPER_NOTIFICATION_EMAIL)

            for recipient in notification_recipients:
                email_sent_notif_kembali = send_email(recipient, subject_notif_kembali, body_notif_kembali)
                if email_sent_notif_kembali:
                    flash(f'Notifikasi pengembalian buku berhasil dikirim ke Admin.', 'info')
                else:
                    flash(f'Gagal mengirim notifikasi pengembalian buku ke Admin. Cek konfigurasi SMTP.', 'warning')

        except Exception as e:
            flash(f'Terjadi kesalahan saat memproses pengembalian: {e}', 'danger')
        finally:
            conn.close()
    else:
        flash('Peminjaman tidak ditemukan atau sudah dikembalikan.', 'danger')
        conn.close()

    if current_user.is_admin():
        return redirect(url_for('admin_dashboard', return_success='true'))
    elif current_user.is_developer():
        return redirect(url_for('developer_dashboard', return_success='true'))
    else:
        return redirect(url_for('dashboard', return_success='true'))

# --- MODIFIKASI UNTUK FILTER RIWAYAT PEMINJAMAN ---
@app.route('/loan_history')
@login_required
def loan_history():
    conn = get_db_connection()

    filter_book_id = request.args.get('book_id', '').strip()
    filter_book_title = request.args.get('book_title', '').strip()
    filter_book_author = request.args.get('book_author', '').strip()
    filter_borrower_name = request.args.get('borrower_name', '').strip()
    filter_borrower_email = request.args.get('borrower_email', '').strip()
    filter_petugas = request.args.get('petugas', '').strip()
    filter_status = request.args.get('status', '').strip()
    filter_loan_date_start = request.args.get('loan_date_start', '').strip()
    filter_loan_date_end = request.args.get('loan_date_end', '').strip()


    query = '''
        SELECT
            l.id,
            b.title AS book_title,
            b.id AS book_id,
            b.author AS book_author,
            -- Prioritize borrower_name_manual, then full_name, then username
            COALESCE(l.borrower_name_manual, bu.full_name, bu.username) AS borrower_name,
            l.borrower_email,
            l.loan_date,
            l.due_date,
            l.return_date,
            l.recorded_by,
            -- Prioritize recorded_by, then petugas_name_manual, then username
            COALESCE(l.recorded_by, l.petugas_name_manual, pu.username, 'Tidak Diketahui') AS petugas_name_display,
            CASE
                WHEN l.return_date IS NOT NULL AND DATE(l.return_date) > DATE(l.due_date) THEN 'Dikembalikan (Terlambat)'
                WHEN l.return_date IS NOT NULL THEN 'Dikembalikan'
                WHEN DATE(l.due_date) < DATE('now', 'localtime') AND l.return_date IS NULL THEN 'Terlambat'
                ELSE 'Dipinjam'
            END AS status_display
        FROM
            loans l
        JOIN
            books b ON l.book_id = b.id
        LEFT JOIN
            users bu ON l.user_id = bu.id -- Alias for Borrower User (peminjam)
        LEFT JOIN
            users pu ON l.petugas_id = pu.id -- Alias for Petugas User (petugas yang mencatat)
        WHERE 1=1
    '''
    params = []

    if not current_user.is_admin() and not current_user.is_developer():
        query += " AND (l.user_id = ? OR (l.user_id IS NULL AND l.borrower_email = ?))"
        params.append(current_user.id)
        params.append(current_user.email)


    if filter_book_id:
        query += " AND b.id LIKE ?"
        params.append(f'%{filter_book_id}%')
    if filter_book_title:
        query += " AND b.title LIKE ?"
        params.append(f'%{filter_book_title}%')
    if filter_book_author:
        query += " AND b.author LIKE ?"
        params.append(f'%{filter_book_author}%')
    if filter_borrower_name:
        # Adjusted filter to use the new borrower alias 'bu' and prioritize borrower_name_manual
        query += " AND (l.borrower_name_manual LIKE ? OR bu.full_name LIKE ? OR bu.username LIKE ?)"
        params.append(f'%{filter_borrower_name}%')
        params.append(f'%{filter_borrower_name}%')
        params.append(f'%{filter_borrower_name}%')
    if filter_borrower_email:
        query += " AND l.borrower_email LIKE ?"
        params.append(f'%{filter_borrower_email}%')
    if filter_petugas:
        # Adjusted filter to use the new petugas alias 'pu' and recorded_by
        query += " AND (l.recorded_by LIKE ? OR l.petugas_name_manual LIKE ? OR pu.username LIKE ?)"
        params.append(f'%{filter_petugas}%')
        params.append(f'%{filter_petugas}%')
        params.append(f'%{filter_petugas}%')

    if filter_status:
        if filter_status == 'Dipinjam':
            query += " AND l.return_date IS NULL AND DATE(l.due_date) >= DATE('now', 'localtime')"
        elif filter_status == 'Dikembalikan':
            query += " AND l.return_date IS NOT NULL AND DATE(l.return_date) <= DATE(l.due_date)"
        elif filter_status == 'Terlambat':
            query += " AND (DATE(l.due_date) < DATE('now', 'localtime') AND l.return_date IS NULL)"
        elif filter_status == 'Dikembalikan (Terlambat)':
             query += " AND l.return_date IS NOT NULL AND DATE(l.return_date) > DATE(l.due_date)"


    query += " ORDER BY l.loan_date DESC, l.id DESC"

    loans = conn.execute(query, params).fetchall()
    conn.close()

    applied_filters = {
        'book_id': filter_book_id,
        'book_title': filter_book_title,
        'book_author': filter_book_author,
        'borrower_name': filter_borrower_name,
        'borrower_email': filter_borrower_email,
        'petugas': filter_petugas,
        'status': filter_status,
        'loan_date_start': filter_loan_date_start,
        'loan_date_end': filter_loan_date_end
    }

    return render_template('loan_history.html', loans=loans, applied_filters=applied_filters, current_user=current_user)

# --- Rute Manajemen Pengguna ---
@app.route('/manage_users', methods=['GET', 'POST'])
@login_required
def manage_users():
    if not current_user.is_admin() and not current_user.is_developer():
        flash('Akses ditolak. Anda tidak memiliki izin.', 'error')
        if current_user.is_admin():
            return redirect(url_for('admin_dashboard'))
        elif current_user.is_developer():
            return redirect(url_for('developer_dashboard'))
        else:
            return redirect(url_for('dashboard'))

    conn = get_db_connection()
    cursor = conn.cursor()

    form_full_name = request.form.get('full_name', '')
    form_username = request.form.get('username', '')
    form_email = request.form.get('email', '')

    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'add_user':
            full_name = request.form['full_name'].strip()
            username = request.form['username'].strip()
            password = request.form['password'].strip()
            email = request.form.get('email', '').strip()
            role = request.form.get('role', 'peminjam').strip()

            form_full_name = full_name
            form_username = username
            form_email = email

            if not full_name or not username or not password or not email:
                flash('Nama Lengkap, Username, password, dan email wajib diisi untuk pengguna baru.', 'error')
                cursor.execute("SELECT id, full_name, username, email, role, registration_date FROM users ORDER BY registration_date DESC")
                users_on_error_raw = cursor.fetchall()
                users_on_error = []
                for user_item_raw in users_on_error_raw:
                    user_item_dict = dict(user_item_raw)
                    if user_item_dict['registration_date']:
                        try:
                            user_item_dict['registration_date'] = datetime.strptime(user_item_dict['registration_date'], '%Y-%m-%d %H:%M:%S.%f')
                        except ValueError:
                            user_item_dict['registration_date'] = datetime.strptime(user_item_dict['registration_date'], '%Y-%m-%d %H:%M:%S')
                    users_on_error.append(user_item_dict)
                conn.close()
                return render_template('manage_users.html', users=users_on_error, current_user=current_user,
                                       full_name=form_full_name, username=form_username, email=form_email)

      #      cursor.execute("SELECT id FROM users WHERE nik = ?", (nik,))
      #      existing_nik = cursor.fetchone()
      #      if existing_nik:
      #          flash('NIK sudah terdaftar untuk pengguna lain. Silakan gunakan NIK lain.', 'error')
      #          conn.close()
      #          return redirect(url_for('manage_users'))

            cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
            existing_user = cursor.fetchone()
            if existing_user:
                flash('Username sudah digunakan. Silakan pilih username lain.', 'error')
            else:
                cursor.execute("SELECT id FROM users WHERE email = ?", (email,))
                existing_email = cursor.fetchone()
                if existing_email:
                    flash('Email ini sudah terdaftar untuk pengguna lain. Silakan gunakan email lain.', 'error')
                    conn.close()
                    return redirect(url_for('manage_users'))

                hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
                try:
                    cursor.execute(
                        'INSERT INTO users (full_name, username, password, email, role, registration_date) VALUES (?, ?, ?, ?, ?, ?)',
                        (full_name, username, hashed_password, email, role, datetime.now())
                    )
                    conn.commit()
                    flash(f'Pengguna {username} berhasil ditambahkan.', 'success')
                except Exception as e:
                    conn.rollback()
                    flash(f'Gagal menambahkan pengguna: {e}', 'error')

        elif action == 'delete_user':
            user_id_to_delete = request.form['user_id']
            try:
                if str(user_id_to_delete) == str(current_user.id):
                    flash('Anda tidak bisa menghapus akun Anda sendiri.', 'error')
                else:
                    cursor.execute("DELETE FROM loans WHERE user_id = ?", (user_id_to_delete,))
                    conn.commit()

                    cursor.execute("DELETE FROM users WHERE id = ?", (user_id_to_delete,))
                    conn.commit()
                    flash('Pengguna berhasil dihapus.', 'success')
            except Exception as e:
                conn.rollback()
                flash(f'Gagal menghapus pengguna: {e}', 'error')

    cursor.execute("SELECT id, full_name, username, email, role, registration_date FROM users ORDER BY registration_date DESC")
    users_raw = cursor.fetchall()

    users = []
    for user_item_raw in users_raw:
        user_item_dict = dict(user_item_raw)
        if user_item_dict['registration_date']:
            try:
                user_item_dict['registration_date'] = datetime.strptime(user_item_dict['registration_date'], '%Y-%m-%d %H:%M:%S.%f')
            except ValueError:
                user_item_dict['registration_date'] = datetime.strptime(user_item_dict['registration_date'], '%Y-%m-%d %H:%M:%S')
        users.append(user_item_dict)

    conn.close()

    return render_template('manage_users.html', users=users, current_user=current_user,
                           full_name=form_full_name, username=form_username, email=form_email)


if __name__ == '__main__':
    with app.app_context():
        init_db()
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            user_10459 = cursor.execute("SELECT id, full_name, username, password, email, role, registration_date, reset_token, reset_token_expiration FROM users WHERE username = '10459'").fetchone()

            if user_10459:
                hashed_password_for_admin = generate_password_hash('rkgp10459', method='pbkdf2:sha256')
                cursor.execute('''
            UPDATE users SET password = ?, email = ?, role = ?, registration_date = COALESCE(registration_date, ?), full_name = COALESCE(full_name, ?) WHERE username = '10459'
                ''', (hashed_password_for_admin, PETUGAS_NOTIFICATION_EMAIL, 'admin', datetime.now(), 'Admin Petugas'))
                print("User '10459' (admin) dipastikan ada dan informasinya terupdate.")
            else:
                hashed_password_for_admin = generate_password_hash('rkgp10459', method='pbkdf2:sha256')
                cursor.execute('''
                    INSERT INTO users (full_name, username, password, email, role, registration_date)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', ('Admin Petugas', '10459', hashed_password_for_admin, PETUGAS_NOTIFICATION_EMAIL, 'admin', datetime.now()))
                print("User '10459' berhasil ditambahkan sebagai admin.")

            user_developer = cursor.execute("SELECT id, full_name, username, password, email, role, registration_date, reset_token, reset_token_expiration FROM users WHERE username = 'developer'").fetchone()
            if user_developer:
                hashed_password_for_developer = generate_password_hash('Store4dm1n', method='pbkdf2:sha256')
                cursor.execute('''
    UPDATE users SET password = ?, email = ?, role = ?, registration_date = COALESCE(registration_date, ?), full_name = COALESCE(full_name, ?) WHERE username = 'developer'
''', (hashed_password_for_developer, DEVELOPER_NOTIFICATION_EMAIL, 'developer', datetime.now(), 'SAC Developer'))
                print("User 'developer' dipastikan ada dan informasinya terupdate.")
            else:
                hashed_password_for_developer = generate_password_hash('Store4dm1n', method='pbkdf2:sha256')
                cursor.execute('''
                    INSERT INTO users (full_name, username, password, email, role, registration_date)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', ('SAC Developer', 'developer', hashed_password_for_developer, DEVELOPER_NOTIFICATION_EMAIL, 'developer', datetime.now()))
                print("User 'developer' berhasil ditambahkan.")

            conn.commit()
        except Exception as e:
            print(f"Error saat memastikan atau membuat user: {e}")
        finally:
            conn.close()

    scheduler = BackgroundScheduler()
    # Pengecekan dan pengiriman pengingat setiap hari pukul 08:00
    scheduler.add_job(func=check_and_send_reminders, trigger='cron', hour=8, minute=0)
    scheduler.start()
    atexit.register(lambda: scheduler.shutdown())

    initialize_gspread_connection()

    app.run(debug=True, host='0.0.0.0')
