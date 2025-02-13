from pydantic import BaseModel, EmailStr
from typing import Optional, List

class UserBase(BaseModel):
    name: str
    email: EmailStr

class UserCreate(UserBase):
    password: str
    is_admin: bool = False
    is_super_admin: bool = False
    is_student: bool = False
    is_teacher: bool = False
    branch_id: int

class UserResponse(UserBase):
    id: int
    is_admin: bool
    is_super_admin: bool
    is_student: bool
    is_teacher: bool
    branch_id: Optional[int]

class BranchBase(BaseModel):
    name: str

class BranchCreate(BranchBase):
    pass

class BranchResponse(BranchBase):
    id: int
class GroupBase(BaseModel):
    name: str
    teacher_id: int

class GroupCreate(GroupBase):
    pass

class GroupResponse(GroupBase):
    id: int

class StudentGroupBase(BaseModel):
    student_id: int
    group_id: int

class StudentGroupCreate(StudentGroupBase):
    pass

class StudentGroupResponse(StudentGroupBase):
    id: int
