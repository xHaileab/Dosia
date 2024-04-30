from . import app, db
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from .models import User, File, FileRequest, FileTransaction, AuditLog
from flask import request, jsonify, session
import os

# Helper function to check allowed file types
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ['jpg']

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data['username']
    plain_password = data['password']
    role = data['role']
    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        return jsonify({'message': 'Username already exists'}), 409
    hashed_password = generate_password_hash(plain_password, method='pbkdf2:sha256')
    new_user = User(username=username, password=hashed_password, role=role)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'User registered successfully!'}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data['username']
    password = data['password']
    user = User.query.filter_by(username=username).first()
    if user and check_password_hash(user.password, password):
        session['user_id'] = user.user_id
        app.logger.info("Session created for user_id: %s", user.user_id)
        return jsonify({'success': True, 'role': user.role}), 200
    else:
        return jsonify({'success': False, 'message': 'Invalid credentials'}), 401


@app.route('/add_file', methods=['POST'])
def add_file():
    if 'user_id' not in session:
        return jsonify({'message': 'Authentication required'}), 401
    if 'file' not in request.files or request.files['file'].filename == '':
        return jsonify({'message': 'No file part or selected file'}), 400
    file = request.files['file']
    if allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file_path = os.path.join('C:/DEVELOPMENT/Dosia/Storage For jpg files', filename)
        file.save(file_path)
        file_name = request.form.get('file_name')
        shelf_number = request.form.get('shelf_number')
        scanner_user_id = session.get('user_id')
        new_file = File(file_name=file_name, shelf_number=shelf_number, scanner_user_id=scanner_user_id, file_path=file_path)
        db.session.add(new_file)
        db.session.commit()
        return jsonify({'message': 'File uploaded successfully!'}), 201
    else:
        return jsonify({'message': 'Invalid file type'}), 400

@app.route('/users')
def get_users():
    users = User.query.all()
    user_data = [{'username': user.username, 'role': user.role, 'created_at': user.created_at} for user in users]
    return jsonify(user_data)

@app.route('/files')
def get_files():
    files = File.query.all()
    file_data = [{'file_name': file.file_name, 'shelf_number': file.shelf_number, 'scanner_user_id': file.scanner_user_id, 'date_created': file.date_created} for file in files]
    return jsonify(file_data)

@app.route('/add_file_request', methods=['POST'])
def add_file_request():
    file_id = request.json['file_id']
    dispatcher_user_id = request.json['dispatcher_user_id']
    new_request = FileRequest(file_id=file_id, dispatcher_user_id=dispatcher_user_id)
    db.session.add(new_request)
    db.session.commit()
    return jsonify({'message': 'File request added successfully!'}), 201

@app.route('/add_transaction', methods=['POST'])
def add_transaction():
    file_id = request.json['file_id']
    action_type = request.json['action_type']
    user_id = request.json['user_id']
    notes = request.json.get('notes', None)
    new_transaction = FileTransaction(file_id=file_id, action_type=action_type, user_id=user_id, notes=notes)
    db.session.add(new_transaction)
    db.session.commit()
    return jsonify({'message': 'Transaction added successfully!'}), 201

@app.route('/transactions')
def get_transactions():
    transactions = FileTransaction.query.all()
    transaction_data = [{ 'transaction_id': transaction.transaction_id, 'file_id': transaction.file_id, 'action_type': transaction.action_type, 'user_id': transaction.user_id, 'transaction_date': transaction.transaction_date, 'notes': transaction.notes } for transaction in transactions]
    return jsonify(transaction_data)

@app.route('/add_audit_log', methods=['POST'])
def add_audit_log():
    user_id = request.json['user_id']
    action = request.json['action']
    new_log = AuditLog(user_id=user_id, action=action)
    db.session.add(new_log)
    db.session.commit()
    return jsonify({'message': 'Audit log entry added successfully!'}), 201
