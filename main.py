from fastapi import FastAPI, Depends, HTTPException, status
from sqlalchemy.orm import Session
from database import get_db
from crud import create_user, get_users, get_user, delete_user, create_branch, get_branches, get_branch, create_group, get_groups, get_group, add_student_to_group, get_students_by_group
from schemas import UserCreate, UserResponse, BranchCreate, BranchResponse, GroupCreate, GroupResponse, StudentGroupCreate, StudentGroupResponse
from auth import get_current_user

app = FastAPI()

def check_role(required_roles: list):
    def role_checker(user: UserResponse = Depends(get_current_user)):
        if user.role not in required_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, 
                detail=f"Access denied. You need one of these roles: {required_roles}"
            )
        return user
    return role_checker

@app.post("/users/", response_model=UserResponse, dependencies=[Depends(check_role(["superadmin", "admin"]))])
def create_new_user(user: UserCreate, db: Session = Depends(get_db)):
    return create_user(db, user)

@app.get("/users/", response_model=list[UserResponse], dependencies=[Depends(check_role(["superadmin"]))])
def read_users(db: Session = Depends(get_db)):
    return get_users(db)

@app.get("/users/{user_id}", response_model=UserResponse, dependencies=[Depends(check_role(["superadmin", "admin"]))])
def read_user(user_id: int, db: Session = Depends(get_db)):
    user = get_user(db, user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return user

@app.delete("/users/{user_id}", dependencies=[Depends(check_role(["superadmin"]))])
def remove_user(user_id: int, db: Session = Depends(get_db)):
    result = delete_user(db, user_id)
    if result is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return result

@app.post("/branches/", response_model=BranchResponse, dependencies=[Depends(check_role(["superadmin"]))])
def create_new_branch(branch: BranchCreate, db: Session = Depends(get_db)):
    return create_branch(db, branch)

@app.get("/branches/", response_model=list[BranchResponse], dependencies=[Depends(check_role(["superadmin"]))])
def read_branches(db: Session = Depends(get_db)):
    return get_branches(db)

@app.get("/branches/{branch_id}", response_model=BranchResponse, dependencies=[Depends(check_role(["superadmin"]))])
def read_branch(branch_id: int, db: Session = Depends(get_db)):
    branch = get_branch(db, branch_id)
    if branch is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Branch not found")
    return branch

@app.post("/groups/", response_model=GroupResponse, dependencies=[Depends(check_role(["admin"]))])
def create_new_group(group: GroupCreate, db: Session = Depends(get_db)):
    return create_group(db, group)

@app.get("/groups/", response_model=list[GroupResponse], dependencies=[Depends(check_role(["admin", "teacher"]))])
def read_groups(db: Session = Depends(get_db)):
    return get_groups(db)

@app.get("/groups/{group_id}", response_model=GroupResponse, dependencies=[Depends(check_role(["admin", "teacher"]))])
def read_group(group_id: int, db: Session = Depends(get_db)):
    group = get_group(db, group_id)
    if group is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Group not found")
    return group

@app.post("/student-groups/", response_model=StudentGroupResponse, dependencies=[Depends(check_role(["teacher"]))])
def add_student(student_group: StudentGroupCreate, db: Session = Depends(get_db)):
    return add_student_to_group(db, student_group)

@app.get("/groups/{group_id}/students", response_model=list[StudentGroupResponse], dependencies=[Depends(check_role(["teacher"]))])
def get_students_in_group(group_id: int, db: Session = Depends(get_db)):
    return get_students_by_group(db, group_id)
