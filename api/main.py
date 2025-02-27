from datetime import datetime, timedelta

import boto3
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel

# Configurações
SECRET_KEY = "AKIAT4GVRUIND35POQUB"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Configurações do S3
S3_BUCKET_NAME = "securittas-prod"
# s3_client = boto3.client('s3')
s3_client = boto3.client(
    's3',
    aws_access_key_id="AKIAT4GVRUIND35POQUB666",
    aws_secret_access_key="BXH5EOHbcwbFQSviupsqeOn1VwP8bsyhzzZZI+TYboll",
    region_name="us-east-1"  # Defina a região desejada
)
# Modelo de usuário
class User(BaseModel):
    username: str
    password: str

# Modelo de token
class Token(BaseModel):
    access_token: str
    token_type: str

# Modelo de dados do token
class TokenData(BaseModel):
    username: str = None

# Configurações de segurança
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Dados de usuário fictícios (em um ambiente real, isso viria de um banco de dados)
fake_users_db = {
    "johndoe": {
        "username": "johndoe",
        "hashed_password": pwd_context.hash("secret"),
    }
}

# Função para verificar a senha
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

# Função para autenticar o usuário
def authenticate_user(username: str, password: str):
    user = fake_users_db.get(username)
    if not user:
        return False
    if not verify_password(password, user["hashed_password"]):
        return False
    return user

# Função para criar o token JWT
def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Função para obter o usuário atual
async def get_current_user(token: str = Depends(oauth2_scheme)):
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
    user = fake_users_db.get(token_data.username)
    if user is None:
        raise credentials_exception
    return user

# Inicialização do FastAPI
app = FastAPI()

# Rota para obter o token JWT
@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user["username"]}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

# Rota para listar arquivos no S3
@app.get("/list-files")
async def list_files(current_user: User = Depends(get_current_user)):
    try:
        response = s3_client.list_objects_v2(Bucket=S3_BUCKET_NAME)
        files = []
        if 'Contents' in response:
            for item in response['Contents']:
                file_info = {
                    "key": item['Key'],
                    "last_modified": item['LastModified'].isoformat(),
                    "size": item['Size']
                }
                files.append(file_info)
        return {"files": files}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Rota para listar versões de um arquivo no S3
@app.get("/list-file-versions/{file_key}")
async def list_file_versions(file_key: str, current_user: User = Depends(get_current_user)):
    try:
        response = s3_client.list_object_versions(Bucket=S3_BUCKET_NAME, Prefix=file_key)
        versions = []
        if 'Versions' in response:
            for version in response['Versions']:
                version_info = {
                    "key": version['Key'],
                    "version_id": version['VersionId'],
                    "last_modified": version['LastModified'].isoformat(),
                    "is_latest": version['IsLatest']
                }
                versions.append(version_info)
        return {"versions": versions}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))