

from flask import Flask, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_cors import CORS

app = Flask(__name__)
app.secret_key = 'geheim123'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///spielesystem.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
CORS(app)  # für zukünftiges Frontend

# Datenbank-Modelle
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

class Spielstand(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    spiel_name = db.Column(db.String(80), nullable=False)
    daten = db.Column(db.Text, nullable=False)

# Registrierung
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    hashed = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    user = User(username=data['username'], password_hash=hashed)
    db.session.add(user)
    db.session.commit()
    return jsonify({"message": "Benutzer erstellt"})

# Login
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    user = User.query.filter_by(username=data['username']).first()
    if user and bcrypt.check_password_hash(user.password_hash, data['password']):
        session['user_id'] = user.id
        session['is_admin'] = user.is_admin
        return jsonify({"message": "Login erfolgreich", "admin": user.is_admin})
    return jsonify({"message": "Login fehlgeschlagen"}), 401

# Spielstand speichern
@app.route('/spielstand', methods=['POST'])
def speichere_spielstand():
    if 'user_id' not in session:
        return jsonify({"message": "Nicht eingeloggt"}), 401
    data = request.json
    stand = Spielstand(user_id=session['user_id'], spiel_name=data['spiel_name'], daten=data['daten'])
    db.session.add(stand)
    db.session.commit()
    return jsonify({"message": "Spielstand gespeichert"})

# Spielstände abrufen
@app.route('/spielstand/<spiel_name>', methods=['GET'])
def lade_spielstand(spiel_name):
    if 'user_id' not in session:
        return jsonify({"message": "Nicht eingeloggt"}), 401
    stände = Spielstand.query.filter_by(user_id=session['user_id'], spiel_name=spiel_name).all()
    return jsonify([{"id": s.id, "daten": s.daten} for s in stände])

# Admin-Funktion: Alle Nutzer anzeigen
@app.route('/admin/users', methods=['GET'])
def alle_benutzer():
    if not session.get('is_admin'):
        return jsonify({"message": "Nicht autorisiert"}), 403
    users = User.query.all()
    return jsonify([{"id": u.id, "username": u.username, "admin": u.is_admin} for u in users])

if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)
