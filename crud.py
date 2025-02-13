from sqlalchemy.orm import Session
from models import User, Branch, Group, StudentGroup
from schemas import UserCreate, BranchCreate, GroupCreate, StudentGroupCreate

def create_user(db: Session, user: UserCreate):
    new_user = User(
        name=user.name,
        email=user.email,
        password_hash=user.password,
        is_admin=user.is_admin,
        is_super_admin=user.is_super_admin,
        is_student=user.is_student,
        is_teacher=user.is_teacher,
        branch_id=user.branch_id
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

def get_user(db: Session, user_id: int):
    return db.query(User).filter(User.id == user_id).first()

def get_users(db: Session, skip: int = 0, limit: int = 10):
    return db.query(User).offset(skip).limit(limit).all()

def delete_user(db: Session, user_id: int):
    user = db.query(User).filter(User.id == user_id).first()
    if user:
        db.delete(user)
        db.commit()
        return {"message": "User deleted successfully"}
    return None

def create_branch(db: Session, branch: BranchCreate):
    new_branch = Branch(name=branch.name)
    db.add(new_branch)
    db.commit()
    db.refresh(new_branch)
    return new_branch

def get_branches(db: Session):
    return db.query(Branch).all()

def get_branch(db: Session, branch_id: int):
    return db.query(Branch).filter(Branch.id == branch_id).first()

def create_group(db: Session, group: GroupCreate):
    new_group = Group(name=group.name, teacher_id=group.teacher_id)
    db.add(new_group)
    db.commit()
    db.refresh(new_group)
    return new_group

def get_groups(db: Session):
    return db.query(Group).all()

def get_group(db: Session, group_id: int):
    return db.query(Group).filter(Group.id == group_id).first()

def add_student_to_group(db: Session, student_group: StudentGroupCreate):
    new_student_group = StudentGroup(student_id=student_group.student_id, group_id=student_group.group_id)
    db.add(new_student_group)
    db.commit()
    db.refresh(new_student_group)
    return new_student_group

def get_students_by_group(db: Session, group_id: int):
    return db.query(StudentGroup).filter(StudentGroup.group_id == group_id).all()
