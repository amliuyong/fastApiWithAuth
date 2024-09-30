import random
import string
import time
from collections import defaultdict
from typing import Dict

from fastapi import FastAPI, Depends, HTTPException, status, Request, Response
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from datetime import datetime, timedelta, timezone
from jose import JWTError, jwt
from passlib.context import CryptContext
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.types import ASGIApp

#  openssl rand -hex 32
SECRET_KEY = "832d55111dbaac9337cf8bd8a4b63a10f4d69a3da3b0b88222e0571673d1ce7e"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

app: FastAPI = FastAPI()

fake_db = {
    "johndoe": {
        "username": "johndoe",
        "full_name": "John Doe",
        "email": "johndoe@example.com",
        "hashed_password": "$2b$12$C6zEtWCtAsOzznXfPFcpdelnhZwNFrBleYybClPqKM3uS93976F4S",
        "disabled": False,
    }
}


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: str | None = None


class User(BaseModel):
    username: str
    email: str | None = None
    full_name: str | None = None
    disabled: bool | None = None


class UserInDB(User):
    hashed_password: str


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# pwd = get_password_hash("xxxx")
# print(pwd)


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI()

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def get_user(db, username: str) -> UserInDB | None:
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)


def authenticate_user(fake_db, username: str, password: str) -> UserInDB | None:
    user = get_user(fake_db, username)
    if not user:
        return None
    if not verify_password(password, user.hashed_password):
        return None
    return user


def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(token: str = Depends(oauth2_scheme)) -> User | None:
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
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = get_user(fake_db, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user


async def get_current_active_user(current_user: User = Depends(get_current_user)) -> User | None:
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(fake_db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/")
async def read_root() -> dict:
    return {"Hello": "World"}

@app.get("/users/me", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_active_user)):
    return current_user

@app.get("/users/me/items/")
async def read_own_items(curren_user: User = Depends(get_current_active_user)):
    return [{"item_id": "Foo", "owner": curren_user.username}]


@app.middleware("http")
async def request_id_logging_middleware(request: Request, call_next: callable):
    response = await call_next(request)
    random_letters = ''.join(random.choices(string.ascii_uppercase + string.digits, k=12))
    print(f"Request ID: {random_letters}")
    response.headers["X-Request-ID"] = random_letters
    return response


async def log_message(message: str) -> None:
    print(message)


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(
            self,
            app: ASGIApp,
            limit: int = 1,
            window: float = 1.0,
            headers: bool = True
    ):
        super().__init__(app)
        self.rate_limit_records: Dict[str, float] = defaultdict(float)
        self.limit = limit
        self.window = window
        self.add_headers = headers

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        client_host = request.client.host
        current_time = time.time()

        # Check if the request exceeds the rate limit
        if current_time - self.rate_limit_records[client_host] < self.window:
            if self.add_headers:
                headers = {
                    "X-RateLimit-Limit": str(self.limit),
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": str(int(self.rate_limit_records[client_host] + self.window))
                }
            else:
                headers = {}
            return Response("Too many requests", status_code=429, headers=headers)

        self.rate_limit_records[client_host] = current_time

        response = await call_next(request)

        if self.add_headers:
            response.headers["X-RateLimit-Limit"] = str(self.limit)
            response.headers["X-RateLimit-Remaining"] = str(self.limit - 1)
            response.headers["X-RateLimit-Reset"] = str(int(current_time + self.window))

        return response

# noinspection PyTypeChecker
app.add_middleware(RateLimitMiddleware, limit=1, window=0.2, headers=False)