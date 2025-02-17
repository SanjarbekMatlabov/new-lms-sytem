from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from typing import List
from datetime import datetime, timedelta
from jose import JWTError, jwt
import bcrypt

from database import Base, engine, SessionLocal
from models import User, Branch, Group, StudentGroup
from constants import ROLE_TEACHER, ROLE_ADMIN, ROLE_SUPERADMIN
from schemas import BranchCreate, BranchResponse, BranchUpdate, GroupCreate, GroupResponse, StudentGroupCreate, StudentGroupResponse, SuperAdminCreate, Token, UserCreate, UserResponse

SECRET_KEY = "a"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

app = FastAPI(title="LMS API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

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


@app.get("/groups/", response_model=List[GroupResponse])
def get_groups(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
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

@app.post("/groups/", response_model=GroupResponse)
def create_group(group_data: GroupCreate, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if current_user.role == ROLE_TEACHER:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Teachers cannot create groups"
        )
    
    if current_user.role == ROLE_ADMIN and group_data.branch_id != current_user.branch_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin can only create groups in their own branch"
        )

    new_group = Group(**group_data.dict(), is_active=True, created_at=datetime.utcnow(), updated_at=datetime.utcnow())
    db.add(new_group)
    db.commit()
    db.refresh(new_group)
    return new_group

# @app.post("/create-first-admin/", response_model=UserResponse)
# def create_first_admin(admin: SuperAdminCreate, db: Session = Depends(get_db)):
#     if db.query(User).filter(User.role == "superadmin").first():
#         raise HTTPException(
#             status_code=status.HTTP_400_BAD_REQUEST,
#             detail="Admin already exists"
#         )
    
#     hashed_password = get_password_hash(admin.password)
#     db_admin = User(
#         username=admin.username,
#         email=admin.email,
#         hashed_password=hashed_password,
#         role="superadmin",
#         branch_id=admin.branch_id,
#         is_active=True
#     )
    
#     try:
#         db.add(db_admin)
#         db.commit()
#         db.refresh(db_admin)
#         return db_admin
#     except Exception as e:
#         db.rollback()
#         raise HTTPException(
#             status_code=status.HTTP_400_BAD_REQUEST,
#             detail=str(e)
#         )

@app.post("/branches/", response_model=BranchResponse)
def create_branch(
   branch: BranchCreate,
   db: Session = Depends(get_db),
   current_user: User = Depends(get_current_user)
):
   if current_user.role not in ["superadmin"]:
       raise HTTPException(
           status_code=status.HTTP_403_FORBIDDEN,
           detail="Only admin can create branches"
       )
   
   if db.query(Branch).filter(Branch.name == branch.name).first():
       raise HTTPException(
           status_code=status.HTTP_400_BAD_REQUEST,
           detail="Branch with this name already exists"
       )
   
   db_branch = Branch(
       name=branch.name,
       address=branch.address,
       phone=branch.phone,
       is_active=True
   )
   
   try:
       db.add(db_branch)
       db.commit()
       db.refresh(db_branch)
       return db_branch
   except Exception as e:
       db.rollback()
       raise HTTPException(
           status_code=status.HTTP_400_BAD_REQUEST,
           detail=str(e)
       )

@app.get("/branches/", response_model=List[BranchResponse])
def get_branches(
   skip: int = 0,
   limit: int = 100,
   db: Session = Depends(get_db),
   current_user: User = Depends(get_current_user)
):
   branches = db.query(Branch).offset(skip).limit(limit).all()
   return branches

@app.get("/branches/{branch_id}", response_model=BranchResponse)
def get_branch(
   branch_id: int,
   db: Session = Depends(get_db),
   current_user: User = Depends(get_current_user)
):
   branch = db.query(Branch).filter(Branch.id == branch_id).first()
   if not branch:
       raise HTTPException(
           status_code=status.HTTP_404_NOT_FOUND,
           detail="Branch not found"
       )
   return branch

@app.put("/branches/{branch_id}", response_model=BranchResponse)
def update_branch(
   branch_id: int,
   branch_update: BranchUpdate,
   db: Session = Depends(get_db),
   current_user: User = Depends(get_current_user)
):
   if current_user.role not in [ "superadmin"]:
       raise HTTPException(
           status_code=status.HTTP_403_FORBIDDEN,
           detail="Only admins can update branches"
       )

   db_branch = db.query(Branch).filter(Branch.id == branch_id).first()
   if not db_branch:
       raise HTTPException(
           status_code=status.HTTP_404_NOT_FOUND,
           detail="Branch not found"
       )
   
   if branch_update.name is not None:
       existing_branch = db.query(Branch).filter(
           Branch.name == branch_update.name,
           Branch.id != branch_id
       ).first()
       if existing_branch:
           raise HTTPException(
               status_code=status.HTTP_400_BAD_REQUEST,
               detail="Branch with this name already exists"
           )
       db_branch.name = branch_update.name
   
   if branch_update.address is not None:
       db_branch.address = branch_update.address
   if branch_update.phone is not None:
       db_branch.phone = branch_update.phone
   if branch_update.is_active is not None:
       db_branch.is_active = branch_update.is_active

   try:
       db.commit()
       db.refresh(db_branch)
       return db_branch
   except Exception as e:
       db.rollback()
       raise HTTPException(
           status_code=status.HTTP_400_BAD_REQUEST,
           detail=str(e)
       )

@app.delete("/branches/{branch_id}", response_model=BranchResponse)
def delete_branch(
   branch_id: int,
   db: Session = Depends(get_db),
   current_user: User = Depends(get_current_user)
):
   if current_user.role not in ["admin", "superadmin"]:
       raise HTTPException(
           status_code=status.HTTP_403_FORBIDDEN,
           detail="Only admins can delete branches"
       )

   branch = db.query(Branch).filter(Branch.id == branch_id).first()
   if not branch:
       raise HTTPException(
           status_code=status.HTTP_404_NOT_FOUND,
           detail="Branch not found"
       )
   branch.is_active = False
   
   try:
       db.commit()
       db.refresh(branch)
       return branch
   except Exception as e:
       db.rollback()
       raise HTTPException(
           status_code=status.HTTP_400_BAD_REQUEST,
           detail=str(e)
       )
@app.post("/students/", response_model=StudentGroupResponse)
def create_student(student_data: StudentGroupCreate, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if current_user.role not in [ROLE_SUPERADMIN, ROLE_ADMIN]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admins and superadmins can create students"
        )
    
    new_student = StudentGroup(**student_data.dict(), created_at=datetime.utcnow(), updated_at=datetime.utcnow(), is_active=True)
    db.add(new_student)
    db.commit()
    db.refresh(new_student)
    return new_student


@app.get("/branches/{branch_id}/students/{group_id}")
def get_students_in_group(
    branch_id: int,
    group_id: int, 
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required"
        )
    if current_user.role not in ["superadmin", "admin"] or current_user.branch_id != branch_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: You can only access students in your own branch"
        )

    students = db.query(StudentGroup).filter(StudentGroup.group_id == group_id).all()
    return students
