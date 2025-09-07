import os
import time
from datetime import timedelta
from pathlib import Path

from dotenv import load_dotenv
from flask import Flask, request, jsonify, send_from_directory, Response
from flask_cors import CORS
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from sqlalchemy import (
    create_engine, Column, Integer, String, Text, ForeignKey, CheckConstraint
)
from sqlalchemy.orm import declarative_base, sessionmaker, scoped_session

# ---------- Config ----------
load_dotenv()
PORT = int(os.getenv("PORT", "5000"))
BASE_URL = os.getenv("BASE_URL", f"http://127.0.0.1:{PORT}")
UPLOAD_ROOT = Path(os.getenv("UPLOAD_ROOT", "uploads")).resolve()
SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret")
JWT_SECRET = os.getenv("JWT_SECRET", "dev-jwt-secret")
MAX_UPLOAD_MB = int(os.getenv("MAX_UPLOAD_MB", "20"))
ALLOWED_EXTENSIONS = {"pdf", "jpg", "jpeg", "png", "doc", "docx", "txt"}

UPLOAD_ROOT.mkdir(parents=True, exist_ok=True)

# ---------- Flask ----------
app = Flask(__name__)
app.config["SECRET_KEY"] = SECRET_KEY
app.config["JWT_SECRET_KEY"] = JWT_SECRET
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(days=7)
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_MB * 1024 * 1024

CORS(app, supports_credentials=True)
jwt = JWTManager(app)

# ---------- DB (SQLite) ----------
Base = declarative_base()
engine = create_engine("sqlite:///granduer.db", echo=False, future=True)
SessionLocal = scoped_session(sessionmaker(bind=engine, autoflush=False, autocommit=False))


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    email = Column(String(255), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    name = Column(String(255))
    created_at = Column(Integer, nullable=False)


class Room(Base):
    __tablename__ = "rooms"
    id = Column(Integer, primary_key=True)
    name = Column(String(255), nullable=False)
    client_type = Column(String(30), nullable=False)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(Integer, nullable=False)
    __table_args__ = (CheckConstraint("client_type in ('student','visitor','worker')"),)


class Membership(Base):
    __tablename__ = "memberships"
    user_id = Column(Integer, ForeignKey("users.id"), primary_key=True)
    room_id = Column(Integer, ForeignKey("rooms.id"), primary_key=True)
    role = Column(String(30), nullable=False)  # 'admin' or 'client'
    __table_args__ = (CheckConstraint("role in ('admin','client')"),)


class Message(Base):
    __tablename__ = "messages"
    id = Column(Integer, primary_key=True)
    room_id = Column(Integer, ForeignKey("rooms.id"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    text = Column(Text)
    file_url = Column(Text)
    file_name = Column(String(255))
    created_at = Column(Integer, nullable=False)


Base.metadata.create_all(engine)

# ---------- Helpers ----------
def db():
    return SessionLocal()


def now_ms():
    return int(time.time() * 1000)


def allowed_file(filename: str) -> bool:
    if "." not in filename:
        return False
    ext = filename.rsplit(".", 1)[1].lower()
    return ext in ALLOWED_EXTENSIONS


def current_user_obj(session):
    ident = get_jwt_identity()
    if not ident:
        return None
    # token stores identity as string; convert back to int
    try:
        ident_int = int(ident)
    except (TypeError, ValueError):
        return None
    return session.get(User, ident_int)


def is_member(session, user_id, room_id):
    return session.get(Membership, {"user_id": user_id, "room_id": room_id}) is not None


# ---------- Homepage (embedded client) ----------
CLIENT_HTML = r"""<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>Granduer Investments — Portal (Flask)</title>
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <style>
    :root{--brand:#1f78ff;--brand-dark:#0f49b4;--ink:#0f172a;--muted:#475569;--ring:#e2e8f0;--bg:#f8fafc;--card:#fff}
    *{box-sizing:border-box} body{margin:0;font-family:system-ui,Segoe UI,Roboto,Arial;background:var(--bg);color:var(--ink)}
    header{position:sticky;top:0;background:#fff;border-bottom:1px solid var(--ring)}
    .container{max-width:1100px;margin:auto;padding:14px 20px}
    .brand{font-weight:800;display:flex;align-items:center;gap:.6rem}
    .logo{width:28px;height:28px;border-radius:8px;background:linear-gradient(135deg,var(--brand),#8ab6ff)}
    .row{display:flex;gap:10px;flex-wrap:wrap}
    .card{background:var(--card);border:1px solid var(--ring);border-radius:14px;box-shadow:0 8px 24px rgba(2,8,23,.06);padding:14px}
    .btn{background:var(--brand);color:#fff;border:none;border-radius:12px;padding:10px 14px;font-weight:600;cursor:pointer}
    .btn.alt{background:#fff;color:var(--brand);border:1px solid var(--ring)}
    .input,select,textarea{border:1px solid var(--ring);border-radius:10px;padding:10px 12px;font:inherit}
    .grid{display:grid;gap:14px}.two{grid-template-columns:1fr 1fr}
    .list{max-height:360px;overflow:auto}
    .msg{border:1px solid var(--ring);border-radius:10px;padding:8px 10px;margin-top:8px;background:#fff}
    .muted{color:var(--muted);font-size:12px}
    .badge{display:inline-flex;align-items:center;padding:6px 10px;border-radius:999px;background:#e6f0ff;color:#0f49b4;font-size:12px}
    @media(max-width:900px){.two{grid-template-columns:1fr}}
  </style>
</head>
<body>
<header>
  <div class="container row" style="align-items:center;justify-content:space-between">
    <div class="brand"><span class="logo"></span> Granduer Investments</div>
    <div class="row">
      <input id="base" class="input" style="width:260px" placeholder="Server base URL" />
      <span id="who" class="badge" style="display:none"></span>
      <button id="showAuth" class="btn alt">Sign in / up</button>
      <button id="signOut" class="btn alt" style="display:none">Sign out</button>
    </div>
  </div>
</header>

<main class="container grid two" style="margin-top:16px">
  <section class="card">
    <h3 style="margin:6px 0 10px">Rooms</h3>
    <div class="row">
      <select id="clientType" class="input">
        <option value="student">Student</option>
        <option value="visitor">Visitor</option>
        <option value="worker">Worker</option>
      </select>
      <input id="roomName" class="input" placeholder="Room name (e.g., Jane Doe)" style="min-width:220px" />
      <button id="newRoom" class="btn">Create</button>
      <button id="listRoomsBtn" class="btn alt">Refresh</button>
    </div>
    <div id="rooms" class="list" style="margin-top:10px"></div>
  </section>

  <section class="card">
    <div class="row" style="justify-content:space-between;align-items:center">
      <div>
        <div class="muted">Room</div>
        <h3 id="roomTitle" style="margin:6px 0">None selected</h3>
      </div>
      <div class="row">
        <input id="inviteEmail" class="input" placeholder="Invite by email" />
        <select id="inviteRole" class="input">
          <option value="client">client</option>
          <option value="admin">admin</option>
        </select>
        <button id="inviteBtn" class="btn alt">Add Member</button>
      </div>
    </div>

    <div id="chatArea" style="display:none">
      <div id="messages" class="list" style="height:280px"></div>
      <div class="row" style="margin-top:10px">
        <input id="msgText" class="input" placeholder="Type a message…" style="flex:1" />
        <button id="send" class="btn">Send</button>
      </div>
      <div class="row" style="margin-top:10px;align-items:center">
        <input id="file" type="file" class="input" />
        <button id="upload" class="btn">Upload</button>
      </div>
      <div class="muted" style="margin-top:6px">Files are stored on the server under /uploads/&lt;roomId&gt;/…</div>
    </div>

    <div id="blocked" class="muted">Sign in and select a room to start.</div>
  </section>
</main>

<!-- Auth modal -->
<div id="modal" class="card" style="position:fixed;inset:auto 0 0 0;max-width:520px;margin:auto;display:none">
  <div class="row" style="justify-content:space-between;align-items:center">
    <h3 style="margin:6px 0">Sign in / Sign up</h3>
    <button id="closeModal" class="btn alt">Close</button>
  </div>
  <div class="grid two" style="margin-top:8px">
    <div>
      <h4>Sign up</h4>
      <input id="suEmail" class="input" type="email" placeholder="Email" />
      <input id="suName" class="input" type="text" placeholder="Name" />
      <input id="suPass" class="input" type="password" placeholder="Password" />
      <button id="doSignUp" class="btn" style="margin-top:6px">Create account</button>
    </div>
    <div>
      <h4>Sign in</h4>
      <input id="siEmail" class="input" type="email" placeholder="Email" />
      <input id="siPass" class="input" type="password" placeholder="Password" />
      <button id="doSignIn" class="btn" style="margin-top:6px">Sign in</button>
    </div>
  </div>
  <div id="authErr" class="muted" style="color:#b91c1c;margin-top:8px"></div>
</div>

<script>
  // ---- State
  let token = localStorage.getItem('gi_token') || '';
  let base = localStorage.getItem('gi_base') || window.location.origin;
  let activeRoomId = null;

  // ---- Elements
  const $ = id => document.getElementById(id);
  $('base').value = base;

  const modal = $('modal'), showAuth = $('showAuth'), closeModal = $('closeModal');
  const who = $('who'), signOut = $('signOut'), authErr = $('authErr');
  const roomsEl = $('rooms'), roomTitle = $('roomTitle'), chatArea = $('chatArea'), blocked = $('blocked');
  const clientType = $('clientType'), roomName = $('roomName'), newRoom = $('newRoom'), listRoomsBtn = $('listRoomsBtn');
  const messagesEl = $('messages'), msgText = $('msgText'), sendBtn = $('send'), fileInput = $('file'), uploadBtn = $('upload');
  const inviteEmail = $('inviteEmail'), inviteRole = $('inviteRole'), inviteBtn = $('inviteBtn');

  // ---- Helpers
  function setBase(v){ base = v.trim() || base; localStorage.setItem('gi_base', base); }
  $('base').addEventListener('change', e => setBase(e.target.value));

  function setToken(t){
    token = t || '';
    if (token) localStorage.setItem('gi_token', token); else localStorage.removeItem('gi_token');
    who.style.display = token ? 'inline-flex' : 'none';
    showAuth.style.display = token ? 'none' : 'inline-flex';
    signOut.style.display = token ? 'inline-flex' : 'none';
  }
  setToken(token);

  async function api(method, path, body, isForm=false){
    const headers = token ? { Authorization: `Bearer ${token}` } : {};
    if (!isForm) headers['Content-Type'] = 'application/json';
    const res = await fetch(`${base}${path}`, { method, headers, body: isForm ? body : (body?JSON.stringify(body):undefined) });
    const txt = await res.text();
    try { return JSON.parse(txt); } catch { return { raw: txt, status: res.status }; }
  }
  function renderRooms(list){
    roomsEl.innerHTML = '';
    if (!list.length){ roomsEl.innerHTML = '<div class="muted">No rooms yet.</div>'; return; }
    for (const r of list){
      const b = document.createElement('button');
      b.className = 'btn alt'; b.style.margin='6px 6px 0 0';
      b.textContent = `${r.name} — ${r.clientType}`;
      b.onclick = ()=> setActiveRoom(r.id, `${r.name} — ${r.clientType}`);
      roomsEl.appendChild(b);
    }
  }
  async function setActiveRoom(id, title){
    activeRoomId = id; roomTitle.textContent = title;
    chatArea.style.display = 'block'; blocked.style.display = 'none';
    await loadMessages();
  }
  function renderMessages(arr){
    messagesEl.innerHTML = '';
    for (const m of arr){
      const div = document.createElement('div'); div.className='msg';
      let html = `<div class="muted">${new Date(m.createdAt).toLocaleString()} • ${m.displayName || ''}</div>`;
      if (m.text) html += `<div>${m.text}</div>`;
      if (m.fileUrl) html += `<div><a href="${m.fileUrl}" target="_blank">📎 ${m.fileName||'Attachment'}</a></div>`;
      div.innerHTML = html; messagesEl.appendChild(div);
    }
    messagesEl.scrollTop = messagesEl.scrollHeight;
  }

  // ---- Auth modal
  showAuth.onclick = ()=> modal.style.display='block';
  closeModal.onclick = ()=> (modal.style.display='none');
  $('doSignUp').onclick = async ()=>{
    authErr.textContent='';
    const res = await api('POST','/auth/signup', { email:$('suEmail').value, password:$('suPass').value, name:$('suName').value });
    if (res.token){ setToken(res.token); who.textContent = res.user.email; modal.style.display='none'; await listRooms(); }
    else authErr.textContent = JSON.stringify(res);
  };
  $('doSignIn').onclick = async ()=>{
    authErr.textContent='';
    const res = await api('POST','/auth/login', { email:$('siEmail').value, password:$('siPass').value });
    if (res.token){ setToken(res.token); who.textContent = res.user.email; modal.style.display='none'; await listRooms(); }
    else authErr.textContent = JSON.stringify(res);
  };
  signOut.onclick = ()=>{ setToken(''); activeRoomId=null; chatArea.style.display='none'; blocked.style.display='block'; roomsEl.innerHTML=''; };

  // ---- Rooms / Chat
  async function listRooms(){
    if (!token) return alert('Sign in first');
    const res = await api('GET','/rooms');
    if (Array.isArray(res)) renderRooms(res); else alert(JSON.stringify(res));
  }
  listRoomsBtn.onclick = listRooms;

  newRoom.onclick = async ()=>{
    if (!token) return alert('Sign in first');
    const name = roomName.value.trim(); if (!name) return alert('Enter room name');
    const res = await api('POST','/rooms', { name, clientType: clientType.value });
    if (res.id){ roomName.value=''; await listRooms(); await setActiveRoom(res.id, `${res.name} — ${res.clientType}`); }
    else alert(JSON.stringify(res));
  };

  async function loadMessages(){
    if (!activeRoomId) return;
    const res = await api('GET', `/rooms/${activeRoomId}/messages`);
    if (Array.isArray(res)) renderMessages(res); else alert(JSON.stringify(res));
  }
  $('send').onclick = async ()=>{
    if (!activeRoomId) return alert('Select a room');
    const t = msgText.value.trim(); if (!t) return;
    const res = await api('POST', `/rooms/${activeRoomId}/messages`, { text: t });
    if (res.id){ msgText.value=''; await loadMessages(); } else alert(JSON.stringify(res));
  };
  $('upload').onclick = async ()=>{
    if (!activeRoomId) return alert('Select a room');
    const f = fileInput.files[0]; if (!f) return alert('Choose a file');
    const fd = new FormData(); fd.append('file', f);
    const res = await api('POST', `/rooms/${activeRoomId}/upload`, fd, true);
    if (res.fileUrl){ fileInput.value=''; await loadMessages(); } else alert(JSON.stringify(res));
  };

  // ---- Invite member
  $('inviteBtn').onclick = async ()=>{
    if (!activeRoomId) return alert('Select a room');
    const email = $('inviteEmail').value.trim(); if(!email) return alert('Enter an email');
    const res = await api('POST', `/rooms/${activeRoomId}/members`, { userEmail: email, role: $('inviteRole').value });
    if (res.ok){ alert('Member added (user must have signed up).'); $('inviteEmail').value=''; } else alert(JSON.stringify(res));
  };

  // boot
  if (token) { who.textContent = 'Signed in'; listRooms(); }
</script>
</body>
</html>
"""

@app.get("/")
def root():
    # Serve the embedded UI
    return Response(CLIENT_HTML, mimetype="text/html")


@app.get("/healthz")
def healthz():
    return {"status": "ok"}

# ---------- Auth ----------
@app.post("/auth/signup")
def signup():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = (data.get("password") or "").strip()  # trimmed to avoid whitespace issues
    name = (data.get("name") or "").strip()
    if not email or not password:
        return jsonify({"error": "Email & password required"}), 400
    session = db()
    try:
        if session.query(User).filter_by(email=email).first():
            return jsonify({"error": "Email already exists"}), 409
        user = User(
            email=email,
            password_hash=generate_password_hash(password),
            name=name or None,
            created_at=now_ms(),
        )
        session.add(user)
        session.commit()
        # IMPORTANT: identity must be a STRING for PyJWT
        token = create_access_token(identity=str(user.id))
        return jsonify({"token": token, "user": {"id": user.id, "email": user.email, "name": user.name}})
    finally:
        session.close()


@app.post("/auth/login")
def login():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = (data.get("password") or "").strip()
    if not email or not password:
        return jsonify({"error": "Email & password required"}), 400
    session = db()
    try:
        user = session.query(User).filter_by(email=email).first()
        if not user or not check_password_hash(user.password_hash, password):
            return jsonify({"error": "Invalid credentials"}), 401
        token = create_access_token(identity=str(user.id))  # string identity
        return jsonify({"token": token, "user": {"id": user.id, "email": user.email, "name": user.name}})
    finally:
        session.close()


@app.get("/me")
@jwt_required()
def me():
    session = db()
    try:
        u = current_user_obj(session)
        return jsonify({"user": {"id": u.id, "email": u.email, "name": u.name}})
    finally:
        session.close()


# ---------- Rooms ----------
@app.post("/rooms")
@jwt_required()
def create_room():
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    client_type = (data.get("clientType") or "").strip()
    if not name or client_type not in {"student", "visitor", "worker"}:
        return jsonify({"error": "name & clientType required"}), 400
    session = db()
    try:
        u = current_user_obj(session)
        room = Room(name=name, client_type=client_type, owner_id=u.id, created_at=now_ms())
        session.add(room)
        session.flush()
        session.add(Membership(user_id=u.id, room_id=room.id, role="admin"))
        session.commit()
        return jsonify({"id": room.id, "name": room.name, "clientType": room.client_type})
    finally:
        session.close()


@app.get("/rooms")
@jwt_required()
def list_my_rooms():
    session = db()
    try:
        u = current_user_obj(session)
        rows = (
            session.query(Room, Membership)
            .join(Membership, Membership.room_id == Room.id)
            .filter(Membership.user_id == u.id)
            .order_by(Room.created_at.desc())
            .all()
        )
        out = [
            {
                "id": r.Room.id,
                "name": r.Room.name,
                "clientType": r.Room.client_type,
                "createdAt": r.Room.created_at,
                "role": r.Membership.role,
            }
            for r in rows
        ]
        return jsonify(out)
    finally:
        session.close()


@app.post("/rooms/<int:room_id>/members")
@jwt_required()
def add_member(room_id):
    data = request.get_json(silent=True) or {}
    user_email = (data.get("userEmail") or "").strip().lower()
    role = (data.get("role") or "client").strip()
    if not user_email or role not in {"admin", "client"}:
        return jsonify({"error": "userEmail & role required"}), 400
    session = db()
    try:
        u = current_user_obj(session)
        me = session.get(Membership, {"user_id": u.id, "room_id": room_id})
        if not me or me.role != "admin":
            return jsonify({"error": "Admin only"}), 403
        user = session.query(User).filter_by(email=user_email).first()
        if not user:
            return jsonify({"error": "User must sign up first"}), 404
        if not session.get(Membership, {"user_id": user.id, "room_id": room_id}):
            session.add(Membership(user_id=user.id, room_id=room_id, role=role))
            session.commit()
        return jsonify({"ok": True})
    finally:
        session.close()


# ---------- Messages ----------
@app.get("/rooms/<int:room_id>/messages")
@jwt_required()
def get_messages(room_id):
    session = db()
    try:
        u = current_user_obj(session)
        if not is_member(session, u.id, room_id):
            return jsonify({"error": "Not a member"}), 403
        rows = (
            session.query(Message, User)
            .join(User, User.id == Message.user_id)
            .filter(Message.room_id == room_id)
            .order_by(Message.created_at.asc())
            .all()
        )
        out = []
        for m, u2 in rows:
            out.append(
                {
                    "id": m.id,
                    "text": m.text,
                    "fileUrl": m.file_url,
                    "fileName": m.file_name,
                    "createdAt": m.created_at,
                    "displayName": u2.name or u2.email,
                    "email": u2.email,
                }
            )
        return jsonify(out)
    finally:
        session.close()


@app.post("/rooms/<int:room_id>/messages")
@jwt_required()
def post_message(room_id):
    data = request.get_json(silent=True) or {}
    text = (data.get("text") or "").strip()
    if not text:
        return jsonify({"error": "text required"}), 400
    session = db()
    try:
        u = current_user_obj(session)
        if not is_member(session, u.id, room_id):
            return jsonify({"error": "Not a member"}), 403
        msg = Message(room_id=room_id, user_id=u.id, text=text, created_at=now_ms())
        session.add(msg)
        session.commit()
        return jsonify({"id": msg.id, "text": msg.text})
    finally:
        session.close()


# ---------- Uploads ----------
@app.post("/rooms/<int:room_id>/upload")
@jwt_required()
def upload(room_id):
    session = db()
    try:
        u = current_user_obj(session)
        if not is_member(session, u.id, room_id):
            return jsonify({"error": "Not a member"}), 403
        if "file" not in request.files:
            return jsonify({"error": "file required"}), 400
        f = request.files["file"]
        if f.filename == "":
            return jsonify({"error": "filename empty"}), 400
        if not allowed_file(f.filename):
            return jsonify({"error": "file type not allowed"}), 400

        room_dir = UPLOAD_ROOT / str(room_id)
        room_dir.mkdir(parents=True, exist_ok=True)
        safe = secure_filename(f.filename)
        fname = f"{int(time.time()*1000)}-{safe}"
        path = room_dir / fname
        f.save(path)

        file_url = f"/uploads/{room_id}/{fname}"
        msg = Message(room_id=room_id, user_id=u.id, file_url=file_url, file_name=f.filename, created_at=now_ms())
        session.add(msg)
        session.commit()
        return jsonify({"fileUrl": f"{BASE_URL}{file_url}", "fileName": f.filename})
    finally:
        session.close()


@app.get("/uploads/<int:room_id>/<path:filename>")
def serve_upload(room_id, filename):
    directory = UPLOAD_ROOT / str(room_id)
    return send_from_directory(directory, filename, as_attachment=False)


# ---------- Main ----------
if __name__ == "__main__":
    print(f"Granduer Flask server running on {BASE_URL}")
    app.run(host="0.0.0.0", port=PORT, debug=True)
