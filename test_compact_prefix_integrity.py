"""归档前缀完整性校验(防"篡改被归档洗白")端到端验证。

覆盖需求:
- 从当前锚点按既有哈希规范核对拟删除前缀的序号连续性、prev_hash 衔接、内容哈希;
- 首个断点在拟归档前缀内时, 实际归档与 dry_run 均 409, 回传断点
  seq/event_id/reason(取值同 /integrity), 事件/日计数视图/锚点保持原状;
- 断点不在拟归档前缀内时仍可按既有边界归档, 已覆盖区间幂等;
- 无断点时保留原有 dry_run / 成功响应 / /integrity 约定。
"""
import json
import os
import sqlite3
import tempfile

_tmp = tempfile.mkdtemp()
os.environ["DB_PATH"] = os.path.join(_tmp, "compact_prefix.db")

from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402
from app import db  # noqa: E402

_client_ctx = TestClient(app)
client = _client_ctx.__enter__()
ok = 0
fail = 0


def check(name, cond, extra=""):
    global ok, fail
    if cond:
        ok += 1
        print(f"PASS {name}")
    else:
        fail += 1
        print(f"FAIL {name} {extra}")


def raw():
    conn = sqlite3.connect(os.environ["DB_PATH"])
    conn.row_factory = sqlite3.Row
    return conn


def make_events(n, prefix="e"):
    for i in range(1, n + 1):
        r = client.post("/events", json={
            "event_id": f"{prefix}-{i}",
            "occurred_at": f"2026-10-01T10:{i:02d}:00Z",
            "payload": {"v": i},
        })
        assert r.status_code == 201, r.text


def event_count(conn):
    return conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]


def anchor(conn):
    row = conn.execute("SELECT anchor_seq, anchor_hash FROM chain_anchor WHERE id = 1").fetchone()
    return None if row is None else (row[0], row[1])


# ---------- 1. 内容篡改(hash_mismatch): dry_run 与实际执行都 409, 状态不变 ----------
make_events(5)
# 建全量视图, 用于确认 409 后视图不被扣减
r = client.post("/views", json={"name": "all"})
check("view backfilled 5", r.status_code == 201 and r.json()["total"] == 5, r.text)

conn = raw()
orig_payload = conn.execute("SELECT payload FROM events WHERE id = 2").fetchone()[0]
conn.execute("UPDATE events SET payload = ? WHERE id = 2", (json.dumps({"v": 200}),))
conn.commit(); conn.close()

r = client.get("/integrity").json()
check("integrity detects tamper before compact",
      r["verified"] is False and r["first_break"] ==
      {"seq": 2, "event_id": "e-2", "reason": "hash_mismatch"}, r)

r = client.post("/retention/compact", json={"cutoff_seq": 5, "dry_run": True})
check("dry_run on tampered prefix -> 409 + break",
      r.status_code == 409 and r.json()["first_break"] ==
      {"seq": 2, "event_id": "e-2", "reason": "hash_mismatch"}, r.text)

conn = raw()
check("dry_run 409 keeps all events", event_count(conn) == 5, event_count(conn))
check("dry_run 409 keeps anchor untouched", anchor(conn) is None, anchor(conn))
conn.close()
check("dry_run 409 keeps views untouched",
      client.get("/views/all").json()["total"] == 5)

r = client.post("/retention/compact", json={"cutoff_seq": 5})
check("real compact on tampered prefix -> 409 + break",
      r.status_code == 409 and r.json()["first_break"] ==
      {"seq": 2, "event_id": "e-2", "reason": "hash_mismatch"}, r.text)
check("409 body echoes detail + cutoff_seq",
      r.json()["detail"] == "integrity check failed within archive prefix"
      and r.json()["cutoff_seq"] == 5, r.text)

conn = raw()
check("real compact 409 keeps all events", event_count(conn) == 5, event_count(conn))
check("real compact 409 keeps anchor untouched", anchor(conn) is None, anchor(conn))
# 被篡改记录的 ID 占用仍在
occupied = {x[0] for x in conn.execute("SELECT event_id FROM received_event_ids")}
check("409 keeps id occupancy intact", occupied == {f"e-{i}" for i in range(1, 6)}, occupied)
conn.close()
check("real compact 409 keeps views untouched",
      client.get("/views/all").json()["total"] == 5)

# 篡改依旧可被 /integrity 检出(没有被洗白)
r = client.get("/integrity").json()
check("tamper still detectable after rejected compact",
      r["verified"] is False and r["first_break"]["seq"] == 2, r)

# 修复篡改内容后恢复正常
conn = raw()
conn.execute("UPDATE events SET payload = ? WHERE id = 2", (orig_payload,))
conn.commit(); conn.close()
check("restore -> verified", client.get("/integrity").json()["verified"] is True)

# ---------- 2. cutoff 只覆盖断点之前的干净前缀: 可按既有边界归档 ----------
# 再次篡改 seq=4; cutoff_seq=3 不含断点, 应允许归档 1..3
conn = raw()
conn.execute("UPDATE events SET payload = ? WHERE id = 4", (json.dumps({"v": 404}),))
conn.commit(); conn.close()
check("integrity break now at seq 4",
      client.get("/integrity").json()["first_break"]["seq"] == 4)

r = client.post("/retention/compact", json={"cutoff_seq": 3, "dry_run": True})
check("dry_run cutoff before break -> ok, would_delete 3",
      r.status_code == 200 and r.json()["status"] == "dry_run"
      and r.json()["would_delete"] == 3 and r.json()["through_seq"] == 3, r.text)

r = client.post("/retention/compact", json={"cutoff_seq": 3})
check("compact clean prefix before break -> 200 anchor 3",
      r.status_code == 200 and r.json()["status"] == "compacted"
      and r.json()["deleted"] == 3 and r.json()["anchor_seq"] == 3, r.text)

# 视图随归档扣减 3(剩 e-4/e-5)
check("view decremented by archived clean prefix (total 2)",
      client.get("/views/all").json()["total"] == 2)

# 锚点推进后, seq=4 的篡改仍被 /integrity 检出(从锚点继续校验)
r = client.get("/integrity").json()
check("tamper at seq 4 still detected after anchor advanced to 3",
      r["verified"] is False and r["first_break"] ==
      {"seq": 4, "event_id": "e-4", "reason": "hash_mismatch"}, r)
# 干净前缀校验数为 0(已归档), 首条现存即断点
check("checked counts only verified rows before break", r["checked"] == 0, r)

# 含断点的归档仍被拒(cutoff_seq=4 覆盖断点)
r = client.post("/retention/compact", json={"cutoff_seq": 4})
check("compact covering remaining break -> 409",
      r.status_code == 409 and r.json()["first_break"]["seq"] == 4, r.text)

# 幂等: cutoff_seq <= 锚点(3)仍 noop, 即使链上有断点
r = client.post("/retention/compact", json={"cutoff_seq": 3})
check("idempotent noop at anchor despite break",
      r.status_code == 200 and r.json()["status"] == "noop"
      and r.json()["deleted"] == 0 and r.json()["anchor_seq"] == 3, r.text)
r = client.post("/retention/compact", json={"cutoff_seq": 2, "dry_run": True})
check("idempotent dry_run within covered interval",
      r.status_code == 200 and r.json()["status"] == "dry_run"
      and r.json()["would_delete"] == 0, r.text)

conn = raw(); conn.close()

# ---------- 3. prev_hash_mismatch ----------
db3 = os.path.join(_tmp, "b.db")
os.environ["DB_PATH"] = db3
db.DB_PATH = db3
db.init_db()  # 新库: startup 只初始化过首个库, 切换后需显式建表
# TestClient 复用同一 app, 连接路径在每次 get_conn 时读取模块全局 DB_PATH
make_events(3, prefix="p")
conn = sqlite3.connect(db3)
# SHA-256 十六进制本就小写, 必须改成确定不同的值才算篡改 prev_hash
conn.execute("UPDATE events SET prev_hash = ? WHERE id = 2", ("0" * 64,))
conn.commit(); conn.close()
r = client.post("/retention/compact", json={"cutoff_seq": 3})
check("prev_hash tamper -> 409 prev_hash_mismatch",
      r.status_code == 409 and r.json()["first_break"] ==
      {"seq": 2, "event_id": "p-2", "reason": "prev_hash_mismatch"}, r.text)

# ---------- 4. seq_gap(物理删除中间事件) ----------
db4 = os.path.join(_tmp, "c.db")
os.environ["DB_PATH"] = db4
db.DB_PATH = db4
db.init_db()
make_events(4, prefix="g")
conn = sqlite3.connect(db4)
# 删除 seq=2 但保留占用(模拟直接对 events 行的删除式篡改)
conn.execute("DELETE FROM events WHERE id = 2")
conn.commit(); conn.close()
r = client.get("/integrity").json()
check("integrity seq_gap at 3",
      r["verified"] is False and r["first_break"] ==
      {"seq": 3, "event_id": "g-3", "reason": "seq_gap"}, r)
# dry_run 与实际执行都拒绝覆盖断点的归档
r = client.post("/retention/compact", json={"cutoff_seq": 4, "dry_run": True})
check("dry_run seq_gap -> 409 seq_gap",
      r.status_code == 409 and r.json()["first_break"]["reason"] == "seq_gap"
      and r.json()["first_break"]["seq"] == 3, r.text)
r = client.post("/retention/compact", json={"cutoff_seq": 4})
check("real seq_gap -> 409 seq_gap, events untouched",
      r.status_code == 409 and r.json()["first_break"]["reason"] == "seq_gap", r.text)
conn = sqlite3.connect(db4)
check("seq_gap 409 leaves remaining rows in place",
      conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 3, )
check("seq_gap 409 leaves anchor untouched",
      conn.execute("SELECT 1 FROM chain_anchor").fetchone() is None)
conn.close()
# 断点在拟归档前缀之外(此处指 seq_gap 的下一条 seq=3 > cutoff=1): 仍可归档首条
r = client.post("/retention/compact", json={"cutoff_seq": 1})
check("compact up to gap (cutoff=1) -> 200 anchor 1",
      r.status_code == 200 and r.json()["anchor_seq"] == 1
      and r.json()["deleted"] == 1, r.text)
# 锚点推进后 seq_gap 仍被检出
r = client.get("/integrity").json()
check("seq_gap still detected past new anchor",
      r["verified"] is False and r["first_break"]["reason"] == "seq_gap", r)
# 归档 seq=1 后再试图归档跨过空洞 -> 409(首现存 seq=3 != anchor+1=2)
r = client.post("/retention/compact", json={"cutoff_seq": 3})
check("cannot compact across gap after advancing anchor -> 409",
      r.status_code == 409 and r.json()["first_break"]["reason"] == "seq_gap", r.text)

# ---------- 5. 安全边界优先: 未确认事件不能因校验逻辑变化而可删 ----------
db5 = os.path.join(_tmp, "d.db")
os.environ["DB_PATH"] = db5
db.DB_PATH = db5
db.init_db()
make_events(4, prefix="s")
# consumer 只确认到 2(limit 取前两条)
r = client.post("/consumers/w/pull", json={"lease_seconds": 60, "limit": 2})
check("pull limit 2", len(r.json()["events"]) == 2, r.text)
tok = r.json()["lease_token"]
client.post("/consumers/w/ack", json={"lease_token": tok})
r = client.post("/retention/compact", json={"cutoff_seq": 4})
check("safe boundary still enforced -> 409 safe_through_seq=2",
      r.status_code == 409 and r.json()["detail"] ==
      "cutoff_seq exceeds safe retention boundary"
      and r.json()["safe_through_seq"] == 2, r.text)
# 边界内且链完好 -> 正常归档
r = client.post("/retention/compact", json={"cutoff_seq": 2})
check("compact within boundary + intact chain -> 200",
      r.status_code == 200 and r.json()["anchor_seq"] == 2, r.text)

# ---------- 6. 无断点: 原有 dry_run / compacted / 空库约定不变 ----------
db6 = os.path.join(_tmp, "e.db")
os.environ["DB_PATH"] = db6
db.DB_PATH = db6
db.init_db()
# 空库 dry_run
r = client.post("/retention/compact", json={"cutoff_seq": 0, "dry_run": True})
check("empty DB dry_run cutoff 0 -> noop-style dry_run",
      r.status_code == 200 and r.json()["status"] == "dry_run"
      and r.json()["would_delete"] == 0, r.text)
make_events(3, prefix="n")
r = client.post("/retention/compact", json={"cutoff_seq": 3, "dry_run": True})
check("intact dry_run response shape",
      r.status_code == 200 and r.json() == {
          "status": "dry_run", "dry_run": True, "would_delete": 3,
          "from_seq": 1, "through_seq": 3, "safe_through_seq": 3}, r.text)
r = client.post("/retention/compact", json={"cutoff_seq": 3})
body = r.json()
check("intact compacted response shape",
      r.status_code == 200 and body["status"] == "compacted"
      and body["deleted"] == 3 and body["anchor_seq"] == 3
      and len(body["anchor_hash"]) == 64
      and body["from_seq"] == 1 and body["through_seq"] == 3
      and body["safe_through_seq"] == 3, body)
r = client.get("/integrity").json()
check("integrity after full intact compact -> verified checked=0",
      r == {"verified": True, "checked": 0, "first_break": None, "anchor_seq": 3}, r)
# 再写新事件, 从锚点续链, verified
r = client.post("/events", json={
    "event_id": "n-4", "occurred_at": "2026-10-01T11:00:00Z", "payload": {}})
check("post-archive new event 201", r.status_code == 201, r.text)
r = client.get("/integrity").json()
check("chain continues from anchor verified",
      r["verified"] is True and r["checked"] == 1 and r["anchor_seq"] == 3, r)

# 恢复主 DB_PATH(其他测试若再追加)
os.environ["DB_PATH"] = os.path.join(_tmp, "compact_prefix.db")
db.DB_PATH = os.environ["DB_PATH"]

print(f"\n{ok} passed, {fail} failed")
_client_ctx.__exit__(None, None, None)
raise SystemExit(1 if fail else 0)
