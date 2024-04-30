from . import db
from sqlalchemy.sql import func

class User(db.Model):
    __tablename__ = 'users'
    user_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True)
    password = db.Column(db.String(128))
    role = db.Column(db.Enum('Admin', 'Scanner', 'Dispatcher', 'Storage_Runner', name='user_roles'), nullable=False)
    created_at = db.Column(db.DateTime, default=func.now())

    def __repr__(self):
        return f'<User {self.username}>'


class File(db.Model):
    __tablename__ = 'files'
    
    file_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    file_name = db.Column(db.String(255), nullable=False)
    shelf_number = db.Column(db.String(50))
    scanner_user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'))
    date_created = db.Column(db.DateTime, default=func.now())

    def __repr__(self):
        return f'<File {self.file_name}>'
    

class FileRequest(db.Model):
    __tablename__ = 'file_requests'
    
    request_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    file_id = db.Column(db.Integer, db.ForeignKey('files.file_id'), nullable=False)
    dispatcher_user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    storage_runner_user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=True)
    request_date = db.Column(db.DateTime, default=func.now())
    status = db.Column(db.Enum('Pending', 'Approved', 'Rejected', name='request_status'), default='Pending')

    def __repr__(self):
        return f'<FileRequest {self.request_id}>'
    
class FileTransaction(db.Model):
    __tablename__ = 'file_transactions'
    
    transaction_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    file_id = db.Column(db.Integer, db.ForeignKey('files.file_id'), nullable=False)
    action_type = db.Column(db.Enum('Withdraw', 'Return', name='action_types'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    transaction_date = db.Column(db.DateTime, default=func.now())
    notes = db.Column(db.Text, nullable=True)

    def __repr__(self):
        return f'<FileTransaction {self.transaction_id} {self.action_type}>'


class AuditLog(db.Model):
    __tablename__ = 'audit_logs'
    
    log_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    action = db.Column(db.Text, nullable=False)
    action_date = db.Column(db.DateTime, default=func.now())

    def __repr__(self):
        return f'<AuditLog {self.log_id} by User {self.user_id}>'
