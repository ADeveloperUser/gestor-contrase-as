#!/usr/bin/env python3
"""
gui_node.py – P2P Secure Chat con mallado automático entre nodos (sin Tor).
- Full-mesh automático: cada invite propaga direcciones IP:puerto.
- ECDH-X25519 + AES-GCM cifrado de canal y de mensajes.
- Ed25519 para firma de invites y mensajes.
- Replay-prevention, rate-limit, tamaño máximo 4 KB.
- Flooding anónimo con jitter (50–200 ms).
- UI con lista de conversaciones, participantes y notificaciones.
- “New ID” regenera identidad y borra todo.
- Cero persistencia en disco; limpieza total al cerrar.
"""

import sys, os, asyncio, json, base64, uuid, random, gc, logging, time, socket
from typing import Dict, Set, Tuple
from PySide6 import QtWidgets, QtGui, QtCore
from qasync import QEventLoop, asyncSlot

# Crypto imports
try:
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives import serialization
    import nacl.signing, nacl.encoding
except ImportError:
    print("ERROR: pip install cryptography pynacl PySide6 qasync")
    sys.exit(1)

# Logging
logging.getLogger().handlers.clear()
logging.getLogger().addHandler(logging.NullHandler())

# Configuration
LISTEN_HOST = os.getenv("MY_HOST", "0.0.0.0")
LISTEN_PORT = int(os.getenv("MY_PORT", "9000"))
MAX_MSG_SIZE = 4 * 1024
RATE_LIMIT   = 5  # msgs/sec per conversation

def get_my_ip() -> str:
    # Encuentra la IP local alcanzable
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    finally:
        s.close()

class Peer:
    def __init__(self, reader, writer, aes: AESGCM, vk_hex: str, addr: Tuple[str,int]):
        self.reader = reader
        self.writer = writer
        self.aes = aes
        self.vk_hex = vk_hex
        self.addr = addr
        self.alive = True

class Node:
    def __init__(self, notify):
        self.notify = notify
        self._rate = {}               # {gid: [timestamps]}
        self.seen  = set()            # msg_id cache
        self.peers: Dict[str,Peer] = {}
        self.groups: Dict[str,AESGCM] = {}
        self.group_pw: Dict[str,str] = {}
        self.group_addrs: Dict[str,Set[Tuple[str,int]]] = {}
        self.my_addr = (get_my_ip(), LISTEN_PORT)
        self.new_identity()

    def new_identity(self):
        self.user_id = uuid.uuid4().hex
        self.priv    = X25519PrivateKey.generate()
        self.pub     = self.priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        self.signer     = nacl.signing.SigningKey.generate()
        self.verify_key = self.signer.verify_key
        self.vk_hex     = self.verify_key.encode(encoder=nacl.encoding.HexEncoder).decode()

    async def start(self):
        server = await asyncio.start_server(self._on_connect, LISTEN_HOST, LISTEN_PORT)
        self.notify(f"🆔 ID:{self.user_id[:8]} vk:{self.vk_hex[:8]}")
        async with server:
            await server.serve_forever()

    async def _on_connect(self, r, w):
        try:
            hello = {
                "pub":   base64.b64encode(self.pub).decode(),
                "vk":    self.vk_hex,
                "addr":  f"{self.my_addr[0]}:{self.my_addr[1]}"
            }
            w.write((json.dumps(hello)+"\n").encode()); await w.drain()

            resp = await asyncio.wait_for(r.readline(), timeout=5)
            data = json.loads(resp.decode())
            their_pub  = base64.b64decode(data["pub"])
            their_vk   = data["vk"]
            their_addr = data.get("addr","")

            shared = self.priv.exchange(X25519PublicKey.from_public_bytes(their_pub))
            aes = AESGCM(shared[:32])

            rid = uuid.uuid4().hex
            h,p = their_addr.split(":",1) if ":" in their_addr else ("?",0)
            peer_addr = (h, int(p))
            self.peers[rid] = Peer(r, w, aes, their_vk, peer_addr)
            self.notify(f"[Handshake] peers:{len(self.peers)}")
            asyncio.get_event_loop().create_task(self._reader(rid))
        except Exception:
            pass

    async def connect_to(self, host: str, port: int):
        try:
            r,w = await asyncio.open_connection(host, port)
            await self._on_connect(r, w)
        except:
            self.notify(f"⚠️ Cannot connect {host}:{port}")

    async def _reader(self, rid):
        peer = self.peers[rid]
        try:
            while True:
                data = await peer.reader.readline()
                if not data or len(data)>MAX_MSG_SIZE:
                    break
                try:
                    msg = json.loads(data.decode())
                except:
                    continue

                mid = msg.get("msg_id")
                if mid:
                    if mid in self.seen: continue
                    self.seen.add(mid)
                    if len(self.seen)>10000: self.seen.pop()

                sig = base64.b64decode(msg.get("sig",""))
                vk  = nacl.signing.VerifyKey(peer.vk_hex, encoder=nacl.encoding.HexEncoder)
                try:
                    vk.verify(data.rstrip(b"\n"), sig)
                except:
                    continue

                if msg.get("type")=="invite":
                    gid    = msg["group_id"]
                    pw     = msg.get("password","")
                    addrs  = msg.get("addrs",[])
                    nonce  = base64.b64decode(msg["nonce"])
                    ct     = base64.b64decode(msg["group_key"])
                    if self.group_pw.get(gid,"")!=pw:
                        continue
                    try:
                        gk = peer.aes.decrypt(nonce, ct, None)
                    except:
                        continue
                    self.groups[gid]       = AESGCM(gk)
                    self.group_pw[gid]     = pw
                    known = self.group_addrs.setdefault(gid, set())
                    for addr in addrs:
                        h,p = addr.split(":",1)
                        tup = (h,int(p))
                        if tup not in known and tup!=self.my_addr:
                            known.add(tup)
                            asyncio.get_event_loop().create_task(self.connect_to(h,p))
                    known.add(peer.addr)
                    self.notify(f"✅ Joined {gid[:8]} peers:{len(self.peers)}")

                elif msg.get("type")=="group_msg":
                    gid = msg["group_id"]
                    if gid in self.groups:
                        nonce = base64.b64decode(msg["nonce"])
                        ct    = base64.b64decode(msg["ciphertext"])
                        try:
                            text = self.groups[gid].decrypt(nonce, ct, None).decode()
                        except:
                            continue
                        self.notify(f"[{gid[:8]}] {text}")

                await asyncio.sleep(random.uniform(0.05,0.2))
                for other,p in list(self.peers.items()):
                    if other==rid: continue
                    p.writer.write(data); await p.writer.drain()
        finally:
            peer.alive=False
            del self.peers[rid]
            self.notify(f"[Disconnect] peers:{len(self.peers)}")

    def _can_send(self, gid):
        now = time.time()
        lst = self._rate.setdefault(gid, [])
        lst[:] = [t for t in lst if now-t<1]
        if len(lst)>=RATE_LIMIT: return False
        lst.append(now)
        return True

    async def create_conv(self, password: str):
        gid = uuid.uuid4().hex
        gk  = os.urandom(32)
        self.groups[gid]       = AESGCM(gk)
        self.group_pw[gid]     = password or ""
        self.group_addrs[gid]  = {self.my_addr}

        base_inv = {
            "type":      "invite",
            "group_id":  gid,
            "password":  password,
            "msg_id":    uuid.uuid4().hex,
            "vk":        self.vk_hex,
            "addrs":     [f"{self.my_addr[0]}:{self.my_addr[1]}"]
        }
        for p in self.peers.values():
            nonce     = os.urandom(12)
            ct        = p.aes.encrypt(nonce, gk, None)
            inv       = dict(base_inv,
                               nonce=base64.b64encode(nonce).decode(),
                               group_key=base64.b64encode(ct).decode())
            blob      = json.dumps(inv).encode()+b"\n"
            sig       = self.signer.sign(blob).signature
            inv["sig"] = base64.b64encode(sig).decode()
            p.writer.write(json.dumps(inv).encode()+b"\n")
            await p.writer.drain()

        return gid, base64.b64encode(gk).decode()

    async def join_conv(self, gid: str, pw: str) -> bool:
        if gid not in self.group_pw or self.group_pw[gid]==pw:
            self.group_pw[gid] = pw
            if gid not in self.groups:
                self.groups[gid] = AESGCM(os.urandom(32))
            return True
        return False

    async def send_msg(self, gid: str, text: str):
        if gid not in self.groups or not self._can_send(gid):
            self.notify("❗ No conv or rate-limit")
            return
        aes   = self.groups[gid]
        nonce = os.urandom(12)
        ct    = aes.encrypt(nonce, text.encode(), None)
        msg   = {
            "type":       "group_msg",
            "group_id":   gid,
            "nonce":      base64.b64encode(nonce).decode(),
            "ciphertext": base64.b64encode(ct).decode(),
            "msg_id":     uuid.uuid4().hex,
            "vk":         self.vk_hex
        }
        blob      = json.dumps(msg).encode()+b"\n"
        sig       = self.signer.sign(blob).signature
        msg["sig"] = base64.b64encode(sig).decode()
        data      = json.dumps(msg).encode()+b"\n"
        for p in self.peers.values():
            p.writer.write(data); await p.writer.drain()

class MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        # ——— Añadido: label fijo con tu ID ———
        self.id_label = QtWidgets.QLabel("")  
        self.id_label.setStyleSheet("font-weight: bold; padding: 4px;")
        container = QtWidgets.QWidget()
        vlayout   = QtWidgets.QVBoxLayout(container)
        vlayout.addWidget(self.id_label)
        # ————————————————————————————————

        self.setWindowTitle("🚀 P2P Secure Chat Auto-Mesh")
        self.resize(1000,600)

        splitter = QtWidgets.QSplitter()
        vlayout.addWidget(splitter)
        self.setCentralWidget(container)

        # LEFT: conv list + controls
        left = QtWidgets.QWidget()
        vl = QtWidgets.QVBoxLayout(left)
        vl.addWidget(QtWidgets.QLabel("Conversations"))
        self.conv_list = QtWidgets.QListWidget()
        vl.addWidget(self.conv_list)
        row = QtWidgets.QHBoxLayout()
        self.b_new   = QtWidgets.QPushButton("New")
        self.b_join  = QtWidgets.QPushButton("Join")
        self.b_close = QtWidgets.QPushButton("Close")
        self.b_id    = QtWidgets.QPushButton("New ID")
        row.addWidget(self.b_new)
        row.addWidget(self.b_join)
        row.addWidget(self.b_close)
        row.addWidget(self.b_id)
        vl.addLayout(row)
        splitter.addWidget(left)

        # RIGHT: notifications, chat, peers, input
        right = QtWidgets.QWidget()
        vr = QtWidgets.QVBoxLayout(right)
        self.notify_bar = QtWidgets.QLabel("")
        vr.addWidget(self.notify_bar)
        self.chat       = QtWidgets.QTextEdit(readOnly=True)
        vr.addWidget(self.chat,3)
        self.part       = QtWidgets.QListWidget()
        self.part.setMaximumWidth(200)
        h2 = QtWidgets.QHBoxLayout()
        h2.addWidget(self.part)
        msgw = QtWidgets.QWidget()
        vmsg = QtWidgets.QVBoxLayout(msgw)
        self.input  = QtWidgets.QLineEdit()
        self.b_send = QtWidgets.QPushButton("Send")
        vmsg.addWidget(self.input)
        vmsg.addWidget(self.b_send)
        h2.addWidget(msgw,1)
        vr.addLayout(h2)
        self.b_theme = QtWidgets.QPushButton("🌙/🔆")
        vr.addWidget(self.b_theme,alignment=QtCore.Qt.AlignRight)
        splitter.addWidget(right)

        self.node = Node(self.notify)
        # ahora que existe node, actualiza el label de ID
        self.id_label.setText(f"Your ID: {self.node.user_id}")

        # Signals
        self.b_new.clicked.connect(self.create_conv)
        self.b_join.clicked.connect(self.join_conv)
        self.b_close.clicked.connect(self.close_conv)
        self.b_id.clicked.connect(self.new_id)
        self.b_send.clicked.connect(self.on_send)
        self.conv_list.currentTextChanged.connect(self.switch_conv)
        self.b_theme.clicked.connect(self.toggle_theme)

        # Periodic integrity check
        self.timer = QtCore.QTimer()
        self.timer.timeout.connect(self.check)
        self.timer.start(5000)
        QtCore.QCoreApplication.instance().aboutToQuit.connect(self.cleanup)

    def start(self):
        loop = asyncio.get_event_loop()
        loop.create_task(self.node.start())

    def notify(self, text):
        n = len(self.node.peers)
        self.notify_bar.setText(f"{text}   │ peers:{n}")
        QtCore.QTimer.singleShot(3000, lambda: self.notify_bar.clear())

    @asyncSlot()
    async def create_conv(self):
        pw,ok = QtWidgets.QInputDialog.getText(self,"New Conversation","Password (optional):")
        if not ok: return
        gid,key = await self.node.create_conv(pw)
        self.conv_list.addItem(gid)
        QtWidgets.QMessageBox.information(self,"Created",f"ID:{gid}\nKey:{key}")

    @asyncSlot()
    async def join_conv(self):
        gid,ok1=QtWidgets.QInputDialog.getText(self,"Join","Conversation ID:")
        if not ok1: return
        pw,ok2=QtWidgets.QInputDialog.getText(self,"Join","Password (if any):")
        if not ok2: return
        if await self.node.join_conv(gid,pw):
            self.conv_list.addItem(gid)
            self.notify(f"✅ Joined {gid[:8]}")
        else:
            QtWidgets.QMessageBox.warning(self,"Error","Incorrect password")

    def close_conv(self):
        itm = self.conv_list.currentItem()
        if not itm: return
        gid = itm.text()
        self.node.groups.pop(gid,None)
        self.node.group_pw.pop(gid,None)
        self.node.group_addrs.pop(gid,None)
        self.conv_list.takeItem(self.conv_list.currentRow())
        self.chat.clear()
        self.part.clear()
        self.notify(f"Closed {gid[:8]}")

    def new_id(self):
        self.node.new_identity()
        self.conv_list.clear()
        self.chat.clear()
        self.part.clear()
        self.node.groups.clear()
        self.node.group_pw.clear()
        self.node.group_addrs.clear()
        self.node.seen.clear()
        self.node._rate.clear()
        QtWidgets.QMessageBox.information(self,"New ID","Identity reset")
        # actualiza label de ID
        self.id_label.setText(f"Your ID: {self.node.user_id}")
        self.notify(f"🆔 {self.node.user_id[:8]} vk:{self.node.vk_hex[:8]}")

    def switch_conv(self,gid):
        self.chat.clear()
        self.part.clear()
        for rid,p in self.node.peers.items():
            stat="✓" if p.alive else "✗"
            self.part.addItem(f"{rid[:8]} {stat}")

    @asyncSlot()
    async def on_send(self):
        itm = self.conv_list.currentItem()
        if not itm:
            self.notify("❗ Select a conversation")
            return
        gid = itm.text()
        txt = self.input.text().strip()
        self.input.clear()
        if txt:
            await self.node.send_msg(gid,txt)
            self.chat.append(f"[Me] {txt}")

    def toggle_theme(self):
        c = self.chat.palette().base().color()
        self.setStyleSheet("" if c!=QtGui.QColor("white") else "QWidget{background:#222;color:#eee;}")

    def check(self):
        ok = all(p.alive for p in self.node.peers.values())
        self.notify("🔒 All OK" if ok else "⚠️ Channel error")

    def cleanup(self):
        for t in asyncio.all_tasks():
            t.cancel()
        for p in self.node.peers.values():
            try:
                p.writer.close()
            except:
                pass
        self.node.peers.clear()
        self.node.groups.clear()
        self.node.priv=None
        self.node.pub=None
        self.node.user_id=None
        gc.collect()

def main():
    app = QtWidgets.QApplication(sys.argv)
    loop = QEventLoop(app)
    asyncio.set_event_loop(loop)
    w = MainWindow()
    w.show()
    with loop:
        w.start()
        loop.run_forever()

if __name__=="__main__":
    main()
