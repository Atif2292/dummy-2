# app.py
from dotenv import load_dotenv
from sentence_transformers import util  
import os
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from sentence_transformers import SentenceTransformer, util

from werkzeug.exceptions import HTTPException
from flask_jwt_extended.exceptions import NoAuthorizationError, InvalidHeaderError
app = Flask(__name__)
CORS(app, supports_credentials=True,origins=["https://inreal-assign.netlify.app"])

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///jobmatch.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'super-secret-key-123'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
model = SentenceTransformer('all-MiniLM-L6-v2')

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(200))
    location = db.Column(db.String(100))
    experience = db.Column(db.Integer)
    skills = db.Column(db.String(300))
    job_type = db.Column(db.String(50))

class Job(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100))
    company = db.Column(db.String(100))
    location = db.Column(db.String(100))
    skills = db.Column(db.String(300))
@app.errorhandler(NoAuthorizationError)
def handle_missing_token(e):
    return jsonify({"error": "Missing Authorization Header"}), 401

@app.errorhandler(InvalidHeaderError)
def handle_invalid_header(e):
    return jsonify({"error": "Invalid Authorization Header"}), 422
@app.errorhandler(Exception)
def handle_exception(e):
    if isinstance(e, HTTPException):
        return jsonify(error=str(e)), e.code
    return jsonify(error="Internal server error"), 500
@app.route('/')
def home():
    return "Backend is running!"

@app.route('/api/signup', methods=['POST'])
def signup():
    data = request.json
    hashed_pw = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    user = User(name=data['name'], email=data['email'], password=hashed_pw)
    db.session.add(user)
    db.session.commit()
    return jsonify(message='User created'), 201

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    user = User.query.filter_by(email=data['email']).first()
    if user and bcrypt.check_password_hash(user.password, data['password']):
        token = create_access_token(identity=str(user.id))
        return jsonify(token=token)
    return jsonify(message='Invalid credentials'), 401
@app.route('/api/profile', methods=['POST'])
@jwt_required()
def update_profile():
    try:
        user_id = get_jwt_identity()
        user = User.query.get(int(user_id))
        data = request.json

        user.location = data.get('location', '')
        user.experience = data.get('experience', '')
        skills = data.get('skills', [])
        if isinstance(skills, str):
            skills = [s.strip() for s in skills.split(',')]
        user.skills = ','.join(skills)
        user.job_type = data.get('job_type', 'any')

        db.session.commit()
        return jsonify(message='Profile updated')

    except Exception as e:
        print("🔥 Profile Update Error:", str(e))
        return jsonify(error=str(e)), 500



@app.route('/api/jobs', methods=['GET'])
@jwt_required()
def get_jobs():
    # DEBUG
    # auth_header = request.headers.get('Authorization')
    # print("Authorization Header:", auth_header)

    try:
        #  Fetch all jobs
        jobs = Job.query.all()
        print(f"Jobs fetched: {len(jobs)}")

        job_list = [{
            'title': job.title,
            'company': job.company,
            'location': job.location,
            'skills': job.skills.split(',') if job.skills else []
        } for job in jobs]

        return jsonify(jobs=job_list), 200

    except Exception as e:
        print("Error fetching jobs:", e)
        return jsonify({"error": "Something went wrong"}), 500

 
@app.route('/api/recommendations', methods=['GET'])
@jwt_required()
def get_recommendations():
    try:
        user_id = get_jwt_identity()
        user = User.query.get(int(user_id))
        if not user:
            return jsonify({"error": "User not found"}), 404

        user_skills_text = user.skills if user.skills else ''
        user_embedding = model.encode(user_skills_text, convert_to_tensor=True)

        all_jobs = Job.query.all()

        matched_jobs = []
        for job in all_jobs:
            job_skills_text = job.skills if job.skills else ''
            job_embedding = model.encode(job_skills_text, convert_to_tensor=True)

            similarity = util.pytorch_cos_sim(user_embedding, job_embedding).item()

            # Adjust  as needed
            if similarity > 0.4:
                matched_jobs.append({
                    'title': job.title,
                    'company': job.company,
                    'location': job.location,
                    'skills': job.skills.split(',') if job.skills else [],
                    'similarity': round(similarity, 2)
                })

        # Sort matched jobs by similarity descending
        matched_jobs.sort(key=lambda x: x['similarity'], reverse=True)

        return jsonify(jobs=matched_jobs)
    
    except Exception as e:
        print("🔥 Error in recommendations:", str(e))
        return jsonify({"error": str(e)}), 500
if __name__ == '__main__':
    import os
    with app.app_context():
        db.create_all()
    port = int(os.environ.get("PORT", 5000))
   
