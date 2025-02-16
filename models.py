from sqlalchemy import Boolean, Column, ForeignKey, Integer, String, DateTime
from sqlalchemy.orm import relationship
from datetime import datetime
from database import Base

class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(100), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(20), nullable=False)  # teacher, admin, superadmin
    branch_id = Column(Integer, ForeignKey("branches.id"), nullable=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    branch = relationship("Branch", back_populates="users")
    teacher_groups = relationship("Group", back_populates="teacher", foreign_keys="Group.teacher_id")
    student_groups = relationship("StudentGroup", back_populates="student")
    
    def __repr__(self):
        return f"User(id={self.id}, username={self.username}, role={self.role})"

class Branch(Base):
    __tablename__ = "branches"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), unique=True, index=True, nullable=False)
    address = Column(String(255))
    phone = Column(String(20))
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    users = relationship("User", back_populates="branch")
    groups = relationship("Group", back_populates="branch")
    
    def __repr__(self):
        return f"Branch(id={self.id}, name={self.name})"

class Group(Base):
    __tablename__ = "groups"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), index=True, nullable=False)
    branch_id = Column(Integer, ForeignKey("branches.id"), nullable=False)
    teacher_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    capacity = Column(Integer, default=30)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    branch = relationship("Branch", back_populates="groups")
    teacher = relationship("User", back_populates="teacher_groups", foreign_keys=[teacher_id])
    student_groups = relationship("StudentGroup", back_populates="group")
    
    def __repr__(self):
        return f"Group(id={self.id}, name={self.name})"

class StudentGroup(Base):
    __tablename__ = "student_groups"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String)
    student_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    group_id = Column(Integer, ForeignKey("groups.id"), nullable=False)
    joined_date = Column(DateTime, default=datetime.utcnow)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    student = relationship("User", back_populates="student_groups")
    group = relationship("Group", back_populates="student_groups")
    
    def __repr__(self):
        return f"StudentGroup(student_id={self.student_id}, group_id={self.group_id})"