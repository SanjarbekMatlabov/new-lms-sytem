# from fastapi import FastAPI, Depends, HTTPException, status
# from sqlalchemy.orm import Session
# from database import get_db
# from crud import create_user, get_users, get_user, delete_user, create_branch, get_branches, get_branch, create_group, get_groups, get_group, add_student_to_group, get_students_by_group
# from schemas import UserCreate, UserResponse, BranchCreate, BranchResponse, GroupCreate, GroupResponse, StudentGroupCreate, StudentGroupResponse
# from auth import get_current_user
# from fastapi.security import OAuth2PasswordRequestForm
# from sqlalchemy.orm import Session
# from auth import create_access_token, verify_password, get_password_hash
# from crud import get_user_by_username
# from schemas import Token

# app = FastAPI()

# def check_role(required_roles: list):
#     def role_checker(user: UserResponse = Depends(get_current_user)):
#         if user.role not in required_roles:
#             raise HTTPException(
#                 status_code=status.HTTP_403_FORBIDDEN, 
#                 detail=f"Access denied. You need one of these roles: {required_roles}"
#             )
#         return user
#     return role_checker
# @app.post("/login", response_model=Token)
# def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
#     user = get_user_by_username(db, form_data.username)
#     if not user or not verify_password(form_data.password, user.password):
#         raise HTTPException(
#             status_code=status.HTTP_401_UNAUTHORIZED,
#             detail="Incorrect username or password",
#             headers={"WWW-Authenticate": "Bearer"},
#         )
    
#     access_token = create_access_token(data={"sub": user.username})
#     return {"access_token": access_token, "token_type": "bearer"}
# @app.post("/users/", response_model=UserResponse, dependencies=[Depends(check_role(["superadmin", "admin"]))])
# def create_new_user(user: UserCreate, db: Session = Depends(get_db)):
#     return create_user(db, user)

# @app.get("/users/", response_model=list[UserResponse], dependencies=[Depends(check_role(["superadmin"]))])
# def read_users(db: Session = Depends(get_db)):
#     return get_users(db)

# @app.get("/users/{user_id}", response_model=UserResponse, dependencies=[Depends(check_role(["superadmin", "admin"]))])
# def read_user(user_id: int, db: Session = Depends(get_db)):
#     user = get_user(db, user_id)
#     if user is None:
#         raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
#     return user

# @app.delete("/users/{user_id}", dependencies=[Depends(check_role(["superadmin"]))])
# def remove_user(user_id: int, db: Session = Depends(get_db)):
#     result = delete_user(db, user_id)
#     if result is None:
#         raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
#     return result

# @app.post("/branches/", response_model=BranchResponse, dependencies=[Depends(check_role(["superadmin"]))])
# def create_new_branch(branch: BranchCreate, db: Session = Depends(get_db)):
#     return create_branch(db, branch)

# @app.get("/branches/", response_model=list[BranchResponse], dependencies=[Depends(check_role(["superadmin"]))])
# def read_branches(db: Session = Depends(get_db)):
#     return get_branches(db)

# @app.get("/branches/{branch_id}", response_model=BranchResponse, dependencies=[Depends(check_role(["superadmin"]))])
# def read_branch(branch_id: int, db: Session = Depends(get_db)):
#     branch = get_branch(db, branch_id)
#     if branch is None:
#         raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Branch not found")
#     return branch

# @app.post("/groups/", response_model=GroupResponse, dependencies=[Depends(check_role(["admin"]))])
# def create_new_group(group: GroupCreate, db: Session = Depends(get_db)):
#     return create_group(db, group)

# @app.get("/groups/", response_model=list[GroupResponse], dependencies=[Depends(check_role(["admin", "teacher"]))])
# def read_groups(db: Session = Depends(get_db)):
#     return get_groups(db)

# @app.get("/groups/{group_id}", response_model=GroupResponse, dependencies=[Depends(check_role(["admin", "teacher"]))])
# def read_group(group_id: int, db: Session = Depends(get_db)):
#     group = get_group(db, group_id)
#     if group is None:
#         raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Group not found")
#     return group

# @app.post("/student-groups/", response_model=StudentGroupResponse, dependencies=[Depends(check_role(["teacher"]))])
# def add_student(student_group: StudentGroupCreate, db: Session = Depends(get_db)):
#     return add_student_to_group(db, student_group)

# @app.get("/groups/{group_id}/students", response_model=list[StudentGroupResponse], dependencies=[Depends(check_role(["teacher"]))])
# def get_students_in_group(group_id: int, db: Session = Depends(get_db)):
#     return get_students_by_group(db, group_id)
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from typing import List
from datetime import datetime, timedelta
from jose import JWTError, jwt
import bcrypt
from pydantic import BaseModel

# Project files
from database import Base, engine, SessionLocal
from models import User, Branch, Group, StudentGroup
from constants import ROLE_TEACHER, ROLE_ADMIN, ROLE_SUPERADMIN

# Constants
SECRET_KEY = "your-secret-key-here"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

app = FastAPI(title="LMS API")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Create database tables
Base.metadata.create_all(bind=engine)

# Pydantic models
class Token(BaseModel):
    access_token: str
    token_type: str

class UserCreate(BaseModel):
    username: str
    email: str
    password: str
    role: str
    branch_id: int = None

class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    role: str
    branch_id: int = None

    class Config:
        orm_mode = True

# Database dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(
        plain_password.encode('utf-8'),
        hashed_password.encode('utf-8')
    )

def get_password_hash(password: str) -> str:
    return bcrypt.hashpw(
        password.encode('utf-8'),
        bcrypt.gensalt()
    ).decode()

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def authenticate_user(db: Session, username: str, password: str):
    user = db.query(User).filter(User.username == username).first()
    if not user or not verify_password(password, user.hashed_password):
        return False
    return user

async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.JWTError:
        raise credentials_exception

    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise credentials_exception
    return user

# Endpoints
@app.post("/token", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/users/", response_model=UserResponse)
async def create_user(
    user: UserCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # Check permissions
    if current_user.role == ROLE_TEACHER:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Teachers cannot create users"
        )
    
    if user.role == ROLE_ADMIN and current_user.role != ROLE_SUPERADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only superadmin can create admin users"
        )
    
    # For admin users, check if they're creating users in their own branch
    if current_user.role == ROLE_ADMIN and user.branch_id != current_user.branch_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin can only create users in their own branch"
        )
    db_user = db.query(User).filter(User.username == user.username).first()
    if db_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered"
        )
    hashed_password = get_password_hash(user.password)
    db_user = User(
        username=user.username,
        email=user.email,
        hashed_password=hashed_password,
        role=user.role,
        branch_id=user.branch_id
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

@app.get("/users/me", response_model=UserResponse)
async def read_users_me(current_user: User = Depends(get_current_user)):
    return current_user

@app.get("/users/", response_model=List[UserResponse])
async def get_users(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if current_user.role == ROLE_SUPERADMIN:
        users = db.query(User).all()
    elif current_user.role == ROLE_ADMIN:
        users = db.query(User).filter(User.branch_id == current_user.branch_id).all()
    elif current_user.role == ROLE_TEACHER:
        # Get students from teacher's groups
        student_ids = (
            db.query(StudentGroup.student_id)
            .join(Group)
            .filter(Group.teacher_id == current_user.id)
            .distinct()
        )
        users = db.query(User).filter(User.id.in_(student_ids)).all()
    else:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions"
        )
    return users

@app.get("/groups/", response_model=List[dict])
async def get_groups(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if current_user.role == ROLE_SUPERADMIN:
        groups = db.query(Group).all()
    elif current_user.role == ROLE_ADMIN:
        groups = db.query(Group).filter(Group.branch_id == current_user.branch_id).all()
    elif current_user.role == ROLE_TEACHER:
        groups = db.query(Group).filter(Group.teacher_id == current_user.id).all()
    else:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions"
        )
    return groups

@app.post("/groups/", response_model=dict)
async def create_group(
    group_data: dict,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if current_user.role == ROLE_TEACHER:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Teachers cannot create groups"
        )
    
    if current_user.role == ROLE_ADMIN and group_data["branch_id"] != current_user.branch_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin can only create groups in their own branch"
        )

    new_group = Group(**group_data)
    db.add(new_group)
    db.commit()
    db.refresh(new_group)
    return new_group

@app.post("/groups/{group_id}/students/{student_id}")
async def add_student_to_group(
    group_id: int,
    student_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # Check if group exists
    group = db.query(Group).filter(Group.id == group_id).first()
    if not group:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Group not found"
        )

    # Check permissions
    if current_user.role == ROLE_TEACHER and group.teacher_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Teachers can only add students to their own groups"
        )
    
    if current_user.role == ROLE_ADMIN and group.branch_id != current_user.branch_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin can only add students to groups in their branch"
        )

    # Add student to group
    student_group = StudentGroup(student_id=student_id, group_id=group_id)
    db.add(student_group)
    db.commit()
    return {"message": "Student added to group successfully"}