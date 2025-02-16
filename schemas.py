from pydantic import BaseModel, EmailStr, validator, Field
from typing import Optional, List
from datetime import datetime

class Token(BaseModel):
    access_token: str
    token_type: str

class SuperAdminCreate(BaseModel):
    username: str
    email: EmailStr
    password: str
    branch_id: Optional[int] = None

class TokenData(BaseModel):
    username: Optional[str] = None

class UserBase(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    role: str
    branch_id: Optional[int] = None
    
    @validator('role')
    def validate_role(cls, v):
        allowed_roles = ['teacher', 'admin', 'superadmin']
        if v.lower() not in allowed_roles:
            raise ValueError('Invalid role')
        return v.lower()

class UserCreate(UserBase):
    password: str = Field(..., min_length=6, max_length=50)

class UserUpdate(BaseModel):
    username: Optional[str] = Field(None, min_length=3, max_length=50)
    email: Optional[EmailStr] = None
    branch_id: Optional[int] = None
    is_active: Optional[bool] = None

class UserResponse(UserBase):
    id: int
    is_active: bool
    created_at: datetime
    updated_at: datetime

    class Config:
        orm_mode = True

class BranchBase(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    address: Optional[str] = Field(None, max_length=255)
    phone: Optional[str] = Field(None, max_length=20)

class BranchCreate(BranchBase):
    pass

class BranchUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=2, max_length=100)
    address: Optional[str] = Field(None, max_length=255)
    phone: Optional[str] = Field(None, max_length=20)
    is_active: Optional[bool] = None

class BranchResponse(BranchBase):
    id: int
    is_active: bool
    created_at: datetime
    updated_at: datetime

    class Config:
        orm_mode = True

class GroupBase(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    branch_id: int
    teacher_id: int
    capacity: Optional[int] = Field(30, ge=1, le=100)

class GroupCreate(GroupBase):
    pass

class GroupUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=2, max_length=100)
    teacher_id: Optional[int] = None
    capacity: Optional[int] = Field(None, ge=1, le=100)
    is_active: Optional[bool] = None

class GroupResponse(GroupBase):
    id: int
    is_active: bool
    created_at: datetime
    updated_at: datetime
    students_count: Optional[int] = None

    class Config:
        orm_mode = True

class StudentGroupBase(BaseModel):
    name:str
    student_id: int
    group_id: int

class StudentGroupCreate(StudentGroupBase):
    pass

class StudentGroupUpdate(BaseModel):
    is_active: bool

class StudentGroupResponse(StudentGroupBase):
    id: int
    joined_date: datetime
    is_active: bool
    created_at: datetime
    updated_at: datetime

    class Config:
        orm_mode = True

class UserList(BaseModel):
    total: int
    items: List[UserResponse]

class BranchList(BaseModel):
    total: int
    items: List[BranchResponse]

class GroupList(BaseModel):
    total: int
    items: List[GroupResponse]

class HTTPError(BaseModel):
    detail: str

    class Config:
        schema_extra = {
            "example": {"detail": "Error message here"}
        }

class PaginationParams(BaseModel):
    skip: int = Field(0, ge=0)
    limit: int = Field(10, ge=1, le=100)

class UserFilter(PaginationParams):
    role: Optional[str] = None
    branch_id: Optional[int] = None
    is_active: Optional[bool] = None
    search: Optional[str] = None

class GroupFilter(PaginationParams):
    branch_id: Optional[int] = None
    teacher_id: Optional[int] = None
    is_active: Optional[bool] = None
    search: Optional[str] = None