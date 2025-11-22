from sqlmodel import select, Session
from app.database import engine
from app.db_models import JobDB

with Session(engine) as session:
    jobs = session.exec(select(JobDB).where(JobDB.status == "failed")).all()
    for job in jobs:
        print(f"Job ID: {job.id}")
        print(f"Error: {job.error_message}")
        print("-" * 20)
