from pydantic import BaseModel
from fastapi import HTTPException, FastAPI, Response, Depends
from uuid import UUID, uuid4
from fastapi_sessions.backends.implementations import InMemoryBackend
from fastapi_sessions.session_verifier import SessionVerifier
from fastapi_sessions.frontends.implementations import SessionCookie, CookieParameters
from fastapi.responses import HTMLResponse
from datetime import datetime
from paswwords import verify_password, get_password_hash
import uvicorn

class SessionData(BaseModel):
    username: str


cookie_params = CookieParameters()

# Uses UUID
cookie = SessionCookie(
    cookie_name="cookie",
    identifier="general_verifier",
    auto_error=True,
    secret_key="DONOTUSE",
    cookie_params=cookie_params,
)
backend = InMemoryBackend[UUID, SessionData]()
mysessions = {}
myusers = {}
messages = []

class BasicVerifier(SessionVerifier[UUID, SessionData]):
    def __init__(
        self,
        *,
        identifier: str,
        auto_error: bool,
        backend: InMemoryBackend[UUID, SessionData],
        auth_http_exception: HTTPException,
    ):
        self._identifier = identifier
        self._auto_error = auto_error
        self._backend = backend
        self._auth_http_exception = auth_http_exception

    @property
    def identifier(self):
        return self._identifier

    @property
    def backend(self):
        return self._backend

    @property
    def auto_error(self):
        return self._auto_error

    @property
    def auth_http_exception(self):
        return self._auth_http_exception

    def verify_session(self, model: SessionData) -> bool:
        """If the session exists, it is valid"""
        return True

verifier = BasicVerifier(
    identifier="general_verifier",
    auto_error=True,
    backend=backend,
    auth_http_exception=HTTPException(status_code=403, detail="invalid session"),
)

app = FastAPI()

@app.get("/")
def home():
    return HTMLResponse("<h1>Go to <a href='/docs'>/docs</a> to proceed with the application</h1>")

@app.post("/login")
async def login(name: str, password: str, response: Response):
    if myusers.get(name) is not None:
        if verify_password(password, myusers[name]):
            session_id = uuid4()
            data = SessionData(username=name)
            mysessions[session_id] = name
            if mysessions.get(name) is None:
                mysessions[name] = []
            now = datetime.now()
            messages.append(name + " logged in at " + now.strftime('%H:%M:%S %d/%m/%Y'))
            mysessions[name].append(session_id)
            cookie.attach_to_response(response, session_id)
            await backend.create(session_id, data)

            return {"name": name, "session": str(session_id)}
        else:
            return {"error": "Invalid password"}
    else:
        return {"error": "Invalid username or password"}

@app.get("/create_user")
async def create_user(name: str, password: str):
    if myusers.get(name) is None:
        myusers[name] = get_password_hash(password)
        return {"detail": f"User {name} created"}
    else:
        return {"error": "Username already exists"}

@app.get("/whoami", dependencies=[Depends(cookie)])
async def whoami(session_id: UUID = Depends(cookie),session_data: SessionData = Depends(verifier)):
    # print(session_id)
    return session_data


@app.delete("/logout")
async def logout(response: Response, session_id: UUID = Depends(cookie)):
    session = await backend.read(session_id)
    if(session is not None):
        await backend.delete(session_id)
        cookie.delete_from_response(response)
        now = datetime.now()
        messages.append(session.username + " logged out at " +now.strftime('%H:%M:%S %d/%m/%Y'))
        return {"detail": "Logged out"}
    return {"error": "Invalid session"}

@app.put("/delete_session/{id}")
async def del_session(id: str, name: str, response: Response,session_id: UUID = Depends(cookie)):
    # session = await backend.read(session_id)
    session1 = await backend.read(session_id)
    session2 = None

    if mysessions.get(name) is not None:
        session2 = mysessions[name]
    if (session2 is None):
        return {"error": "invalid session"}

    if session1.username != name:
        return {"error": "Not your session / Unauthorized"}

    if mysessions.get(name) is not None:
        if(UUID(id) in mysessions[name]):
            mysessions[name].remove(UUID(id))
            await backend.delete(UUID(id))
        else:
            return {"error": "invalid session id"}
    # cookie.delete_from_response(response)

    return {"detail": "session deleted"}

@app.get("/get_sessions")
async def get_sessions(response: Response, session_id: UUID = Depends(cookie)):
    session = await backend.read(session_id)
    # print(mysessions)
    if not session:
        response.status_code = 404
        return {"detail": "No Session Found"}

    return mysessions[session.username]

@app.get("/broadcast")
async def broadcast(response:Response, session_id: UUID = Depends(cookie)):
    session = await backend.read(session_id)
    if not session:
        response.status_code = 404
        return {"detail": "No Session Found"}

    return {"Messages":messages}

@app.post("/broadcast/{message}")
async def broadcast(message: str, session_id: UUID = Depends(cookie)):
    session = await backend.read(session_id)
    if not session:
        return {"detail": "No Session Found"}
    now = datetime.now()
    messages.append(f"{session.username} ({now.strftime('%H:%M:%S %d/%m/%Y')}) : {message}")
    return {"detail": "message sent"}

# added a line for testing purposes
# to check the integration with 
# with github