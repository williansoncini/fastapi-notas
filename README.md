![](https://media.giphy.com/media/gG9fVWJdN41NeiHhzk/giphy.gif)

- [FastAPI](#fastapi)
- [Venv](#venv)
  - [**Criando ambiente** virtual](#criando-ambiente-virtual)
  - [**Ativando o ambiente virtual**](#ativando-o-ambiente-virtual)
  - [**Desativando o ambiente** virtual](#desativando-o-ambiente-virtual)
  - [**Saindo do ambiente virtual**](#saindo-do-ambiente-virtual)
  - [**Caso de um erro no PowerShell, execute o seguinte comando**](#caso-de-um-erro-no-powershell-execute-o-seguinte-comando)
- [Fast API](#fast-api)
  - [**instalação**](#instalação)
  - [**Exemplo simples**](#exemplo-simples)
  - [**Executando**](#executando)
- [Executando diretamente pelo arquivo](#executando-diretamente-pelo-arquivo)
  - [**Link padrão**](#link-padrão)
  - [**Documentação gerada automaticamente**](#documentação-gerada-automaticamente)
  - [Subindo para produção](#subindo-para-produção)
- [Parâmetros e GET](#parâmetros-e-get)
- [Tratando exceções](#tratando-exceções)
- [Post](#post)
- [PUT](#put)
- [Delete](#delete)
- [PATH PARAMETERS](#path-parameters)
- [Query parameter](#query-parameter)
- [Valores opcionais](#valores-opcionais)
- [Header parameters](#header-parameters)
- [Melhorando a documentação automática da API](#melhorando-a-documentação-automática-da-api)
- [Usando dependência nas requisições](#usando-dependência-nas-requisições)
- [Rotas](#rotas)
- [Validação customizada](#validação-customizada)
- [SQL Alchemy](#sql-alchemy)
  - [Criando um model com SQL Alchemy](#criando-um-model-com-sql-alchemy)
  - [Criando as tabelas de dados](#criando-as-tabelas-de-dados)
- [Schemas - Serialização](#schemas---serialização)
- [SQL MODEL](#sql-model)
  - [Instalação](#instalação-1)
  - [Model](#model)
  - [Rotas](#rotas-1)
- [Autenticação](#autenticação)


# FastAPI

Notas de aula de um curso feito na Udemy :3

Link: [https://www.udemy.com/course/fastapi-apis-modernas-e-assincronas-com-python/learn/lecture/32054518?start=0#overview](https://www.udemy.com/course/fastapi-apis-modernas-e-assincronas-com-python/learn/lecture/32054518?start=0#overview)

# Venv

## **Criando ambiente** virtual

```powershell
python -m venv nome_do_ambiente
```

Geralmente é esse comando

```bash
python -m venv env
```

## **Ativando o ambiente virtual**

```powershell
\nome_do_ambiente\Scripts\activate
```

> Se lembre de selecionar o python do ambiente virtual (Vscode)
> 

## **Desativando o ambiente** virtual

```powershell
deactivate
```

## **Saindo do ambiente virtual**

```powershell
exit
```

## **Caso de um erro no PowerShell, execute o seguinte comando**

```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```

# Fast API

## **instalação**

```python
pip install fastapi uvicorn
# Versão do curso
pip install fastapi==0.75.2 uvicorn==0.17.6

#necessário para produção
pip install gunicorn
```

## **Exemplo simples**

`main.py`

```python
from fastapi import FastAPI

app = FastAPI()

@app.get('/')
async def raiz()
	return {"init" : "Hello world!"}
```

## **Executando**

```python
#Execução padrão
uvicorn main_file:app_name
#Execução com reload
uvicorn main_file:app_name --reload 

#exemplo
uvicorn main:app --reload
```

# Executando diretamente pelo arquivo

```python
from fastapi import FastApi

app = FastApi()

@app.get('/')
async def raiz():
	return {"teste": "Boooora"}

if __name__ == '__main__':
	import uvicorn

	uvicorn.run("main:app", host='0.0.0.0', port=8000, log_level='info', reload=True, debug=True)
```

**no terminal**

```powershell
python main.py
```

## **Link padrão**

http://localhost:8000

## **Documentação gerada automaticamente**

http://localhost:8000/docs

http://localhost:8000/redoc

## Subindo para produção

```powershell
gunicorn main:app -w 4 -k uvicorn.workers.UvicornWorker
#-w Workers
```

# Parâmetros e GET

Para realizar busca com parâmetros na url

```python
from fastapi import FastApi

app = FastApi()

@app.get('/{id}')
async def example(id: int): #Aqui é realizado a tratativa de parametro, utilizando o pydantic
	return id
```

# Tratando exceções

Para realizar o tratamento de exceções é necessário realizar as importações abaixo

```python
from fastapi import HTTPException
from fastapi import status
```

**Exemplo de tratamento de exceção de keyError**

Ao realizar uma busca com um id acima de 3 a exceção deve acontecer

```python
from fastapi import FastApi, HTTPException, status

app = FastApi()
exampleArray = [1,2,3,4]

@app.get('/{id}')
async def example(id: int):
	try:
		return exampleArray[id]
	except KeyError:
		raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Posição não encontrada')

```

# Post

**url**

*http://localhost:8000/*

**Dados enviado**

```json
{
	"id" : 4
}
```

**Exemplo**

```python
from fastapi import FastApi, HTTPException, status

app = FastApi()

exampleArray = [1,2,3]

@app.post('/', status_code=status.HTTP_201_CREATED)
async def postExample(id: int):
	if id not in exampleArray:
		axampleArray.append(id)
		return exampleArray
	else:
		raise HTTPException(status_code=status.HTTP_409_CONFLICT,
												detail=f"O valor {id} já existe esse valor no array ")
```

**Retorno**

```python
[1,2,3,4]
```

# PUT

**url**

*http://localhost:8000/1*

**Dado enviado**

```python
{
	"newValue": 3
}
```

**Exemplo**

```python
from fastapi import FastApi, HTTPException, status

app = FastApi()

exampleArray = [1,2,3]

@app.put('/{id}'):
async def putExample(id:int, newValue: int):
	if id in exampleArray:
		exampleArray[id] = newValue
		return exampleArray
	else:
		raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
												detail='Não existe o id procurado')
```

**Retorno**

```python
[1,3,3]
```

# Delete

**url**

*http://localhosto:8000/1*

**Exemplo**

```python
from fastapi import FastApi, HTTPException, status, Response

app = FastApi()

exampleArray = [1,2,3]

@app.delete('/{id}')
async def deleteExample(id: int):
	if id in exampleArray
		removed = exampleArray.splice(id,1)
		return Response(status_code=status.HTTP_204_NO_COTENT)
	else:
		raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, 
												detail='Id não encontrado')

```

O retorno será o status 204 caso o id seja encontrado

# PATH PARAMETERS

**Colando alguns parâmetros via Path**

```python
from fastapi import FastApi, path, status, HTTPException

app = FastApi()

exampleArray = [1,2,3]

@app.get('/{id}')
async def getExample(id: int = Path(default=None,
																		title='Id',
																		description='Deve ser entre 1 e 2',
																		gt=0,
																		lt=3)):
	if id in exampleArray:
		return exampleArray[id]
	else:
		raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Valor não encontrado')
```

- gt = Great then
- lt = Less then

# Query parameter

Parâmetros que são utilizados em requisições do tipo GET, para obter resultados. 

**Exemplo**

*http://localhost:8000/?teste=1&outroTeste=2*

| teste | 1 |
| --- | --- |
| outroTeste | 2 |

**Exemplo utilizando Query**

```python
from fastapi import FastApi, Query

app = FastApi()

@app.get('/')
async def example(a: int = Query(default=None, gt=5), 
									b: int = Query(default=None, gt=10)):
	result: int = a + b
	return {'result': result}
```

# Valores opcionais

**Exemplo**

```python
from fastapi import FastApi
from typing import Optional

app = FastApi()
@app.get('/')
async def example(a: int,b : int, c = Optional[int] = None):
	result = a + b
	if c:
		result += c

	return {'result': result}
```

# Header parameters

Exemplo

```python
from fastapi import FastApi, Header

app = FastApi()
@app.get('/')
async def example(headerParameter: str = Header(default=None)):
	return headerParameter
```

# Melhorando a documentação automática da API

Para melhorar a documentação automática, você pode colocar mais parâmetros nas requisições da API

**Exemplo**

```python
@app.get('/teste', 
         description='Retorna uma lista de objetos',
         summary='Retorna todos os objetos existentes',
         response_model=List[Objeto_exemplo],
         response_description='Objeto encontrado com sucesso!')
```

Também é possível melhorar os títulos e descrições da API

```python
app = FastAPI(title='Primeira api com fastApi', 
              description='Fazendo a Api através de um curso no Udemy', 
              version='1.0.0')
```

Assim quando você acessar sua API, verá que a documentação dela estará bem melhor :3

# Usando dependência nas requisições

É possível criar dependência com outras partes do programa, assim sempre que uma requisição é chamada, a ação deseja também será executada, lhe trazendo o resultado desejado

E**xemplo**

```python
@app.delete('/cursos/{id}')
async def delete_curso(id: int, db: Any = Depends(fake_db)):
	db.delete(id)
```

# Rotas

Delicinha, da para deixar tudo separado colocando as rotas em arquivos diferente :3

Exemplo de código com API’s separadas

**main.py**

```python
from fastapi import FastApi
from routes import userRoutes, dogRoutes

app = FastApi()

app.include_router(userRoutes.router, tags=['users'])
app.include_router(dogRoutes.router, tag=['dogs'])

if __name__ == '__main__':
	import uvicorn
	
	uvicorn.run('main:app', host='0.0.0.0', port=8000, reload=True, log_level='info')
```

**/routes/userRoutes.py**

```python
from fastapi import APIRouter

router = APIRouter()

@router.get('/users')
async def get_users():
	return {'data':'users'}
```

**/routes/dogRoutes.py**

```python
from fastapi import APIRouter

router = APIRouter()

@router.get('/dogs')
async def get_dogs():
	return {'data':'dogs'}
```

Nossa API continua funcionando normalmente :3 

**Retorno**

*http://localhost:8000/users*

```python
{'data':'users'}
```

*http://localhost:8000/dogs*

```python
{'data':'dogs'}
```

# Validação customizada

Aqui utilizamos a biblioteca do Pydantic para realizarmos as validações

```python
from pydantic import BaseModel, validator

class Example(BaseModel):
	id: int
	description: str

	@validator('description')
	def validate_description(cls, value):
		if len(value) < 10
			raise ValueError('Capricha mais nessa descrição por favor')
		return value
			
```

Logo sempre que esse campo for utilizado, as validações para tal, serão executadas.

# SQL Alchemy

Ferramenta ORM em python. Serve para facilitar a manipulação do banco de dados, deixando toda a responsabilidade do banco para o ORM.

## Criando um model com SQL Alchemy

```python
from sqlalchemy import Column, Integer, String, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base

class CursoModel(declarative_base()):
  __tablename__ = 'cursos'
  
  id: int = Column(Integer, primary_key=True, autoincrement=True)
  titulo: str = Column(String(100)) 
  aulas: int = Column(Integer)
  horas: int = Column(Integer)
```

## Criando as tabelas de dados

**engine.py**

```python
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.asyncio import create_async_engine, AsyncEngine, AsyncSession

DB_URL = "postgresql+asyncpg://admin:admin@0.0.0.0:5432/cursos"
engine: AsyncEngine = create_async_engine(DB_URL)

Session: AsyncSession = sessionmaker(
  autocommit=False,
  autoflush=False,
  expire_on_commit=False,
  class_=AsyncSession,
  bind=engine
)
```

**criarTabelas.py**

```python
from core.database import engine

async def create_tables() -> None:
  from models.cursoModel import CursoModel

  print('Criando as tabelas no banco de dados')
  async with engine.begin() as conn:
    await conn.run_sync(declarative_base().metadata.drop_all)
    await conn.run_sync(declarative_base().metadata.create_all)
  print('Tabelas criadas com sucesso!')
  
if __name__ == '__main__':
  import asyncio
  
  asyncio.run(create_tables())
```

# Schemas - Serialização

Nesse caso o schema é utilizado para permitir a comunicação entre cliente e servidor. Fazendo a ponte entre comunicação JSON (Entrada e saída dos dados) para os models, onde os dados são controlados pelo ORM, no caso aqui SQL alchemy

exemplo:

**cursoSchema.py**

```python
from typing import Optional
from pydantic import BaseModel as BaseModelSC

class CursoSchema(BaseModelSC):
  id: Optional[int]
  titulo: str
  aulas: int
  horas: int
  
  class Config:
    orm_mode=True
```

Assim você pode dizer que a entrada e saída de dados serão schemas, porém a manipulação realmente será pelo Model, para ficar mais claro, tem um exemplo de post com schema e model logo abaixo:

**cursoRouter.py**

```python
from fastapi import APIRouter, status, Depends

router = APIRouter()

@router.post('/', status_code=status.HTTP_201_CREATED, response_model=CursoSchema)
#Os dados entram e saem por meio do schema (CursoShema)
async def post_curso(curso: CursoSchema, db: AsyncSession = Depends(get_session)):
  #Model entrando em ação recebendo os dados do schema
  novo_curso = CursoModel(titulo=curso.titulo, aulas=curso.aulas, horas=curso.horas)

  db.add(novo_curso)
  await db.commit()
  
	"""Como o Model e o Schema possuem os mesmos campos, 
  não há problema em devolver um model,
  a conversão é feita automaticamente :3
  Develvendo somente os campos do schema"""
  return novo_curso
```

# SQL MODEL

É um ORM que utiliza o SqlAlchemy, então é a abstração da abstração. Mas ele não está jóia ainda para ser utilizado em 100% dos casos, então por momento, vamos lascar sqlAlchemy naquilo que ele não da conta ainda :3

## Instalação

```bash
pip install sqlmodel
```

## Model

**Exemplo de como fica o model com ele**

```python
from typing import Optional
from sqlmodel import Field, SQLModel

class CursoModel(SQLModel, table=True):
  __tablename__: str = 'cursos'
  
  id: Optional[int] = Field(primary_key=True, default=None)
  titulo: str
  aulas: int
  horas: int
```

## Rotas

Notei que fica mais fácil trabalhar com resultados com ele, pois os autocompletes ajudam bastante por conta de agora usarmos funções. (`result.scalars().all()`)

**Exemplo de rotas com ele**

```python
from typing import List
from fastapi import APIRouter, status, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from models.curso_model import CursoModel
from sqlmodel import select
from core.deps import get_session
from sqlmodel.sql.expression import Select, SelectOfScalar

SelectOfScalar.inherit_cache = True
Select.inherit_cache = True

routes = APIRouter()

@routes.post('/', status_code=status.HTTP_201_CREATED, response_model=CursoModel)
async def post_curso(curso: CursoModel, db: AsyncSession = Depends(get_session)):
  novo_curso = CursoModel(titulo=curso.titulo, aulas=curso.aulas, horas=curso.horas)
  db.add(novo_curso)
  await db.commit()
  return novo_curso

@routes.get('/', response_model=List[CursoModel])
async def get_cursos(db: AsyncSession = Depends(get_session)):
  async with db as session:
    query = select(CursoModel)
    result = await session.execute(query)
    cursos: List[CursoModel] = result.scalars().all()
    return cursos
```

# Autenticação

Para criar a parte de login na API, é necessário se autenticar no servidor de alguma forma. Uma dessas formas é a por token, que foi a utilizada nesse exemplo abaixo :3.

**Exemplo de autenticação * 0 *** 

utilizando jwt - **JWT - Json Web Token**

**core/config.py**

Configurações gerais do sistema

```python
from pydantic import BaseSettings
from sqlalchemy.ext.declarative import declarative_base

class Settings(BaseSettings):
  API_V1_STR = '/api/v1'
  DB_URL: str = "postgresql+asyncpg://admin:admin@0.0.0.0:5432/cursos"
  DBBaseModel = declarative_base()
  JWT_SECRET = "pQOaP5j6-fNdyimJhO6qc7bVl80HL3WOJtNZEAQP9AQ"
  """
  Para gerar um segredo utilizando o python faça assim:
  
  import secrets
  
  token: int = secrets.token_urlsafe(32)
  """
  ALGORITHM = 'HS256'
  ACCESS_TOKEN_EXPIRE_MINUTES: int = 60*27*7 # 7 dias
  
  
  class Config:
    case_sensitive = True
    
settings: Settings = Settings()
```

**core/auth.py**

Faz somente a parte de autenticação mesmo

```python
from pytz import timezone
from typing import Optional
from datetime import datetime, timedelta
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.future import select
from sqlalchemy.ext.asyncio import AsyncSession
from jose import jwt
from core.config import settings
from core.security import verificarSenha
from pydantic import EmailStr
from models.usuario_model import UsuarioModel

oauth2_schema = OAuth2PasswordBearer(
  tokenUrl=f"{settings.API_V1_STR}/usuarios/login"
)

async def autenticar(email: EmailStr, senha:str, db: AsyncSession) -> Optional[UsuarioModel]:
  async with db as session:
    query = select(UsuarioModel).filter(UsuarioModel.email == email)
    result = await session.execute(query)
    usuario: UsuarioModel = result.scalars().unique().one_or_none()
    
    if not usuario:
      return None
    
    if not verificarSenha(senha, usuario.senha):
      return None
    
    return usuario
  
def _criar_token(tipo_token: str, tempo_vida: timedelta, sub:str) -> str:
  payload = {}
  
  sp = timezone('America/Sao_Paulo')
  expira = datetime.now(tz=sp) + tempo_vida #Agora + 7 dias
  
  #rfc7519
  payload["type"] = tipo_token
  payload["exp"] = expira
  payload["iat"] = datetime.now(tz=sp)
  payload["sub"] = str(sub)

  return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.ALGORITHM)

def criar_token_acesso(sub:str) -> str:
  return _criar_token(
    tipo_token='access_token',
    tempo_vida=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
    sub=sub
  )
```

**core/security.py**

Utilizado na parte de criptografia, retornando e verificando os hash’s

```python
from passlib.context import CryptContext

CRIPTO = CryptContext(schemes=['bcrypt'], deprecated='auto')

def verificarSenha(senha: str, hash:str) -> bool:
  return CRIPTO.verify(senha, hash)
  
def gerarHashSenha(senha:str) -> str :
  return CRIPTO.hash(senha)
```

**core/deps.py**

Dependências que são utilizadas pelas nossas rotas

```python
from typing import Generator, Optional
from unittest import result
from fastapi import Depends, HTTPException, status
from jose import jwt, JWTError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from pydantic import BaseModel
from core.database import Session
from core.auth import oauth2_schema
from core.config import settings
from models.usuario_model import UsuarioModel

class TokenData(BaseModel): 
  username: Optional[str] = None
  
async def get_session() -> Generator:
  session: AsyncSession = Session()
  
  try:
    yield session
  finally:
    await session.close()
    
async def get_current_user(db: Session = Depends(get_session), token: str = Depends(oauth2_schema)) -> UsuarioModel:
  credential_exception: HTTPException = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail='Barradissimo meu amigo!',
    headers={'WWW-Authenticate': 'Bearer'},
  )
  
  try:
    payload = jwt.decode(
      token,
      settings.JWT_SECRET,
      algorithms=settings.ALGORITHM,
      options={
        'verify_aud': False
      }
    )
    username: str = payload.get('sub')
    if username is None:
      raise credential_exception
    
    token_data : TokenData = TokenData(username=username)
  except JWTError:
    raise credential_exception
      
  async with db as session:
    query = select(UsuarioModel).filter(UsuarioModel.id == int(token_data.username))    
    result = await session.execute(query)
    usuario: UsuarioModel = result.scalars().unique().one_or_none()
    
    if usuario is None:
       raise credential_exception
    
    return usuario
```

**core/database.py**

Configurações da base de dados para funcionar com o ORM Sql Alchemy

```python
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.asyncio import create_async_engine, AsyncEngine, AsyncSession
from core.config import settings

engine: AsyncEngine = create_async_engine(settings.DB_URL)

Session: AsyncSession = sessionmaker(
  autocommit=False,
  autoflush=False,
  expire_on_commit=False,
  class_=AsyncSession,
  bind=engine
)
```

**models/usuarioModel.py**

```python
from sqlalchemy import Integer, String, Column
from core.config import settings

class UsuarioModel(settings.DBBaseModel):
  __tablename__ = 'usuarios'
  
  id = Column(Integer, primary_key=True, autoincrement=True)
  nome = Column(String(256), nullable=True)
  email = Column(String(256), nullable=False, unique=True, index=True)
  senha = Column(String(256), nullable=False)

```

**routes/usuarioRoute.py**

Aqui fica a lógica para checar e realizar a autenticação de uma usuário 

```python
from fastapi import APIRouter, status, Depends, HTTPException, Response
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from models.usuario_model import UsuarioModel
from schemas.usuarioSchema import *
from core.deps import get_session, get_current_user
from core.security import gerarHashSenha
from core.auth import autenticar, criar_token_acesso

@router.post('/login')
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: AsyncSession = Depends(get_session)):
  usuario = await autenticar(email=form_data.username, senha=form_data.password, db=db)

  if not usuario:
    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='Dados de acesso incorretos')
  
  return JSONResponse(
    content={
      'access_token': criar_token_acesso(sub=usuario.id),
      'token_type': 'bearer'
    }, status_code=status.HTTP_200_OK
  )

@router.get('/checkLogin', response_model=UsuarioSchemaBase)
async def get_logado(usuario_logado: UsuarioModel = Depends(get_current_user)):
  return usuario_logado
```

**api.py**

Juntando as rotas da API

```python
from fastapi import APIRouter
from api.v1.endpoints import artigo, usuario

router = APIRouter()

router.include_router(artigo.router, prefix='/artigo', tags=['artigo'])
router.include_router(usuario.router, prefix='/usuario', tags=['usuario'])
```

**main.py**

```python
from fastapi import FastAPI
from api.v1.api import router
from core.config import settings
app = FastAPI()

app.include_router(router, prefix=settings.API_V1_STR)

if __name__ == '__main__' :
  import uvicorn
  
  uvicorn.run('main:app', host='0.0.0.0', port=8000, reload=True, log_level='info')
```