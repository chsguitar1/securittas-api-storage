import boto3
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext

from api.main import TokenData

# Configurações do JWT
SECRET_KEY = "your-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Configurações do S3
S3_BUCKET_NAME = "your-s3-bucket-name"
s3_client = boto3.client('s3', region_name="us-east-1")  # Configuração do cliente S3

# Configurações de segurança
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Dados de usuário fictícios
fake_users_db = {
    "johndoe": {
        "username": "johndoe",
        "hashed_password": pwd_context.hash("secret"),
    }
}

# Funções de autenticação e JWT (mantidas do exemplo anterior)
# ...

# Inicialização do FastAPI
app = FastAPI()

# Rotas (mantidas do exemplo anterior)
# ...
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


# Rota para listar arquivos no S3
@app.get("/list-files")
async def list_files(current_user: dict = Depends(get_current_user)):
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
async def list_file_versions(file_key: str, current_user: dict = Depends(get_current_user)):
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