from app import db, Job, app  # also import app

def seed_jobs():
    jobs = [
        Job(title="Frontend Developer", company="Tech Corp", location="Remote", skills="React,JavaScript,HTML,CSS"),
        Job(title="Backend Developer", company="Innovate Ltd", location="New York", skills="Python,Flask,SQL"),
        Job(title="Data Scientist", company="DataX", location="San Francisco", skills="Python,Machine Learning,Statistics"),
        Job(title="Full-Stack Engineer", company="DevWorks", location="Remote", skills="React,Node.js,SQL"),
        Job(title="AI Engineer", company="Smart AI", location="Boston", skills="Python,Deep Learning,TensorFlow")
    ]
    for job in jobs:
        db.session.add(job)
    db.session.commit()
    print("Seeded jobs successfully.")

if __name__ == '__main__':
    with app.app_context():  
        seed_jobs()
