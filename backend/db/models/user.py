from db.base import Base
from sqlalchemy import Column, Integer, String

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    email = Column(String, unique=True, nullable=False, index=True)
    password_hash = Column(String, nullable=True)
    google_id = Column(String, nullable=True, unique=True, index=True)
    profile_pic = Column(String, nullable=True)
