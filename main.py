from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from passlib.context import CryptContext
from datetime import datetime, timedelta
import jwt
from typing import List

# Initialize FastAPI app
app = FastAPI()

# Secret key for JWT token (replace with a secure secret key)
SECRET_KEY = "6e78b9efca208f719314a73c8cbf5adeb890ea221b8a160ec365df569cf07b31"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Database to store users and blogs (for simplicity, using in-memory storage)
users_db = {}
blogs_db = {}
token_db = {}


# Pydantic models
class User(BaseModel):
    name: str
    email: str
    phone_number: str
    password: str


class UserInDB(User):
    hashed_password: str


class Blog(BaseModel):
    title: str
    description: str


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: str | None = None


# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# Function to create a new user
def create_user(user: User):
    hashed_password = pwd_context.hash(user.password)
    db_user = UserInDB(**user.model_dump(), hashed_password=hashed_password)
    users_db[user.email] = db_user
    return db_user


# Function to verify user credentials
def verify_user(email: str, password: str):
    user = users_db.get(email)
    if user and pwd_context.verify(password, user.hashed_password):
        return user


# Function to create JWT token
def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


# Dependency for getting the current user
def get_current_user(token: str = Depends(OAuth2PasswordBearer(tokenUrl="token"))):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate credentials")
        token_data = TokenData(username=username)
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has expired")
    except jwt.DecodeError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not decode token")

    if token_data.username not in users_db:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")

    return token_data


# Route to create a new user
@app.post("/register", response_model=UserInDB)
def register(user: User):
    if user.email in users_db:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered")
    return create_user(user)


# Route to log in and generate JWT token
@app.post("/token", response_model=Token)
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = verify_user(form_data.username, form_data.password)
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect email or password")

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": user.email}, expires_delta=access_token_expires)

    return {"access_token": access_token, "token_type": "bearer"}


# Route to create a new blog
@app.post("/blogs/", response_model=Blog)
def create_blog(blog: Blog, current_user: TokenData = Depends(get_current_user)):
    blog_id = len(blogs_db) + 1
    blogs_db[blog_id] = blog
    return blog


# Route to get all blogs
@app.get("/blogs/", response_model=List[Blog])
def get_blogs():
    return list(blogs_db.values())


# Route to update a blog
@app.put("/blogs/{blog_id}/", response_model=Blog)
def update_blog(blog_id: int, updated_blog: Blog, current_user: TokenData = Depends(get_current_user)):
    if blog_id not in blogs_db:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Blog not found")
    blogs_db[blog_id] = updated_blog
    return updated_blog


# Route to delete a blog
@app.delete("/blogs/{blog_id}/", response_model=None)
def delete_blog(blog_id: int, current_user: TokenData = Depends(get_current_user)):
    if blog_id not in blogs_db:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Blog not found")
    del blogs_db[blog_id]
    return None

# Run the app with Uvicorn..
