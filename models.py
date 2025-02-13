from sqlalchemy import Boolean, Column, ForeignKey, Integer, String
from sqlalchemy.orm import relationship
from database import Base

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    email = Column(String, unique=True, index=True)
    password_hash = Column(String)
    is_admin = Column(Boolean, default=False)
    is_super_admin = Column(Boolean, default=False)
    is_student = Column(Boolean, default=False)
    is_teacher = Column(Boolean, default=False)
    branch_id = Column(Integer, ForeignKey("branches.id"))
    branch = relationship("Branch",back_populates='users')
    group = relationship("Group",back_populates='teacher')

class Branch(Base):
    __tablename__ = "branches"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True,unique=True)
    users = relationship("User",back_populates='branch')

class Group(Base):
    __tablename__ = "groups"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    teaacher = relationship("User", back_populates="groups")
    students = relationship("StudentGroup", back_populates="group")

class StudentGroup(Base):
    __tablename__ = "student_groups"
    id = Column(Integer, primary_key=True, index=True)
    student_id = Column(Integer, ForeignKey("users.id"))
    group_id = Column(Integer, ForeignKey("groups.id"))
    group = relationship("Group", back_populates="students")
    
