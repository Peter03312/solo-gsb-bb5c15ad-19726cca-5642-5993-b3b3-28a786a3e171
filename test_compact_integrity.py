"""归档前缀完整性校验的端到端验证。

回归问题: 待删事件被改动后, /retention/compact 仍推进链锚点, 把 /integrity
本可检出的篡改"盖过去", 归档后 verified 反而变成 true。

修复约定:
- 从当前锚点按 /integrity 同一规范(序号连续性/前后哈希衔接/内容哈希)逐条核对
  拟删除前缀 (anchor, cutoff];
- 首个断点落在拟归档前缀内: 实际归档与 dry_run 都返回 409 及断点
  seq/event_id/reason(reason 同 /integrity), 事件、日计数视图、锚点保持原状;
- 断点不在拟归档前缀内(seq 晚于 cutoff): 仍按既有连续边界归档;
- cutoff <= anchor 的已覆盖区间保持幂等(不校验、直接 noop);
- 无断点时原 dry_run / 成功响应与 /integrity 约定不变。
"""
import json
import os
import sqlite3
import tempfile

_tmp = tempfile.mkdtemp()
os.environ["DB_PATH"] = os.path.join(_tmp, "anchor.db")

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


def use_db(name):
    """切换到全新临时库并建表, 返回路径(全局 client 复连新库)。"""
    path = os.path.join(_tmp, name)
    if os.path.exists(path):
        os.remove(path)
    for suffix in ("", "-wal", "-shm"):
        p = path + suffix
        if os.path.exists(p):
            os.remove(p)
    db.DB_PATH = path
    db.init_db()
    return path


def sql(path, query, args=()):
    con = sqlite3.connect(path)
    cur = con.execute(query, args)
    con.commit()
    rows = cur.fetchall()
    con.close()
    return rows


def seed(path, n, *, consumer=None, ack=True):
    # 每个库用独立 consumer 名: 共享同一个 TestClient 进程时, pull 会在内存侧
    # 记住上一个库的活动租约(按 consumer_id 复用), 跨库重名会让"未确认"场景
    # 误走上一库的旧租约分支。真实部署只有一个库, 不存在此问题。
    if consumer is None:
        consumer = f"worker-{os.path.basename(path)}"
    for i in range(1, n + 1):
        r = client.post(
            "/events",
            json={
                "event_id": f"e{i}",
                "occurred_at": f"2026-09-29T10:00:{i:02d}Z",
                "payload": {"v": i},
            },
        )
        assert r.status_code == 201, r.text
    # 归档前建全量视图, 用于验证 409 不扣减日计数
    r = client.post("/views", json={"name": "all"})
    assert r.status_code == 201, r.text
    # 总是拉取(建立 consumer、游标 0); ack=False 仅表示不确认, 用于安全边界场景
    pull = client.post(f"/consumers/{consumer}/pull", json={"lease_seconds": 300})
    assert pull.status_code == 200, pull.text
    if ack:
        r = client.post(
            f"/consumers/{consumer}/ack",
            json={"lease_token": pull.json()["lease_token"]},
        )
        assert r.status_code == 200, r.text


def anchor_row(path):
    return tuple(sql(path, "SELECT anchor_seq, anchor_hash FROM chain_anchor"))


def event_count(path):
    return sql(path, "SELECT COUNT(*) FROM events")[0][0]


def view_total():
    return client.get("/views/all").json()["total"]


def state_sig(path):
    """409 前后必须完全一致的状态指纹。"""
    return {
        "events": event_count(path),
        "ids": sql(path, "SELECT COUNT(*) FROM received_event_ids")[0][0],
        "anchor": anchor_row(path),
        "view_total": view_total(),
        "integrity": client.get("/integrity").json(),
    }


def expect_break(r, *, status_name, seq, event_id, reason, checked, cutoff, safe):
    body = r.json()
    return (
        r.status_code == 409
        and body["detail"] == "chain integrity break in compact prefix"
        and body["cutoff_seq"] == cutoff
        and body["safe_through_seq"] == safe
        and body["checked"] == checked
        and body["first_break"]
        == {"seq": seq, "event_id": event_id, "reason": reason},
        f"{status_name} {r.status_code} {body}",
    )


# ---------- 1. 内容篡改(payload): dry_run 与实际归档都 409, 状态原样 ----------
path = use_db("payload_tamper.db")
seed(path, 4)
check("integrity clean baseline", client.get("/integrity").json()["verified"])
orig_payload = sql(path, "SELECT payload FROM events WHERE id=2")[0][0]
# 直接改库模拟磁盘篡改(绕过 API): seq=2 的内容与其存储 hash 不再一致
sql(path, "UPDATE events SET payload=? WHERE id=2", (json.dumps({"v": 999}),))
br = client.get("/integrity").json()
check(
    "/integrity detects payload tamper first",
    not br["verified"]
    and br["checked"] == 1
    and br["first_break"] == {"seq": 2, "event_id": "e2", "reason": "hash_mismatch"},
    br,
)
before = state_sig(path)

r = client.post("/retention/compact", json={"cutoff_seq": 4, "dry_run": True})
cond, extra = expect_break(
    r, status_name="dry_run", seq=2, event_id="e2", reason="hash_mismatch",
    checked=1, cutoff=4, safe=4,
)
check("dry_run -> 409 with first break", cond, extra)

r = client.post("/retention/compact", json={"cutoff_seq": 4})
cond, extra = expect_break(
    r, status_name="execute", seq=2, event_id="e2", reason="hash_mismatch",
    checked=1, cutoff=4, safe=4,
)
check("execute -> 409 with first break", cond, extra)

after = state_sig(path)
check("state unchanged after rejected compact", before == after,
      f"before={before} after={after}")
check("no anchor advanced", anchor_row(path) == (), anchor_row(path))

# 篡改消除后恢复原有成功路径
sql(path, "UPDATE events SET payload=? WHERE id=2", (orig_payload,))
check("integrity verified after restore", client.get("/integrity").json()["verified"])
r = client.post("/retention/compact", json={"cutoff_seq": 4, "dry_run": True})
check("restored dry_run 200 would_delete=4",
      r.status_code == 200 and r.json()["would_delete"] == 4, r.text)
r = client.post("/retention/compact", json={"cutoff_seq": 4})
body = r.json()
check("restored compact succeeds",
      r.status_code == 200 and body["status"] == "compacted"
      and body["deleted"] == 4 and body["anchor_seq"] == 4, body)
check("integrity verified after clean compact",
      client.get("/integrity").json()["verified"])


# ---------- 2. prev_hash 篡改: reason=prev_hash_mismatch ----------
path = use_db("prev_hash_tamper.db")
seed(path, 4)
sql(path, "UPDATE events SET prev_hash=? WHERE id=3", ("deadbeef",))
br = client.get("/integrity").json()
check(
    "/integrity detects prev_hash tamper",
    br["checked"] == 2
    and br["first_break"]
    == {"seq": 3, "event_id": "e3", "reason": "prev_hash_mismatch"},
    br,
)
before = state_sig(path)
r = client.post("/retention/compact", json={"cutoff_seq": 4, "dry_run": True})
cond, extra = expect_break(
    r, status_name="dry_run", seq=3, event_id="e3",
    reason="prev_hash_mismatch", checked=2, cutoff=4, safe=4,
)
check("dry_run -> 409 prev_hash_mismatch", cond, extra)
r = client.post("/retention/compact", json={"cutoff_seq": 4})
cond, extra = expect_break(
    r, status_name="execute", seq=3, event_id="e3",
    reason="prev_hash_mismatch", checked=2, cutoff=4, safe=4,
)
check("execute -> 409 prev_hash_mismatch", cond, extra)
check("state unchanged (prev_hash tamper)", before == state_sig(path),
      f"{before} != {state_sig(path)}")


# ---------- 3. 仅改存储 hash: reason=hash_mismatch(prev 仍衔接) ----------
path = use_db("hash_tamper.db")
seed(path, 4)
sql(path, "UPDATE events SET hash=? WHERE id=2", ("0" * 64,))
br = client.get("/integrity").json()
check(
    "/integrity detects stored-hash tamper",
    br["checked"] == 1
    and br["first_break"] == {"seq": 2, "event_id": "e2", "reason": "hash_mismatch"},
    br,
)
r = client.post("/retention/compact", json={"cutoff_seq": 4})
cond, extra = expect_break(
    r, status_name="execute", seq=2, event_id="e2",
    reason="hash_mismatch", checked=1, cutoff=4, safe=4,
)
check("execute -> 409 hash_mismatch", cond, extra)


# ---------- 4. 首条即篡改: checked=0 ----------
path = use_db("first_tamper.db")
seed(path, 3)
sql(path, "UPDATE events SET payload=? WHERE id=1", (json.dumps({"v": 1, "x": 1}),))
r = client.post("/retention/compact", json={"cutoff_seq": 3})
cond, extra = expect_break(
    r, status_name="execute", seq=1, event_id="e1",
    reason="hash_mismatch", checked=0, cutoff=3, safe=3,
)
check("first record break -> 409 checked=0", cond, extra)
check("nothing archived on first-record break", event_count(path) == 3)


# ---------- 5. seq 断档(直接删一条): 前缀内 409 seq_gap, 断点之外可按边界归档 ----------
path = use_db("seq_gap.db")
seed(path, 5)
# 直接删除 seq=3 制造序号空洞(模拟绕过正常流程的删除/丢失)
sql(path, "DELETE FROM events WHERE id=3")
br = client.get("/integrity").json()
check(
    "/integrity detects seq_gap",
    br["checked"] == 2
    and br["first_break"] == {"seq": 4, "event_id": "e4", "reason": "seq_gap"},
    br,
)
before = state_sig(path)
# cutoff=5 覆盖断点 seq=4: dry/real 都必须 409
r = client.post("/retention/compact", json={"cutoff_seq": 5, "dry_run": True})
cond, extra = expect_break(
    r, status_name="dry_run", seq=4, event_id="e4",
    reason="seq_gap", checked=2, cutoff=5, safe=5,
)
check("dry_run covering gap -> 409 seq_gap", cond, extra)
r = client.post("/retention/compact", json={"cutoff_seq": 5})
cond, extra = expect_break(
    r, status_name="execute", seq=4, event_id="e4",
    reason="seq_gap", checked=2, cutoff=5, safe=5,
)
check("execute covering gap -> 409 seq_gap", cond, extra)
check("state unchanged on seq_gap reject", before == state_sig(path))

# 断点不在拟归档前缀内: cutoff=2 只动 (anchor=0, 2], 断点 seq=4 在其后,
# 仍可按既有边界归档 1..2
r = client.post("/retention/compact", json={"cutoff_seq": 2, "dry_run": True})
body = r.json()
check("dry_run before gap -> 200 would_delete=2",
      r.status_code == 200 and body["would_delete"] == 2
      and body["from_seq"] == 1 and body["through_seq"] == 2, body)
r = client.post("/retention/compact", json={"cutoff_seq": 2})
body = r.json()
check("archive before gap succeeds",
      r.status_code == 200 and body["status"] == "compacted"
      and body["anchor_seq"] == 2 and body["deleted"] == 2, body)

# 已覆盖区间幂等: 即使锚点之后仍有断点, cutoff<=anchor 直接 noop, 不校验
r = client.post("/retention/compact", json={"cutoff_seq": 2})
check("covered interval noop (break after anchor)",
      r.status_code == 200 and r.json()["status"] == "noop"
      and r.json()["deleted"] == 0 and r.json()["anchor_seq"] == 2, r.text)
r = client.post("/retention/compact", json={"cutoff_seq": 1})
check("smaller cutoff still noop",
      r.status_code == 200 and r.json()["status"] == "noop", r.text)

# 断点仍可被 /integrity 检出(归档没有盖掉它); 失败响应按既有约定不带 anchor_seq。
# 校验从新锚点 seq=2 起算, 现存首条即断点 seq=4, 故 checked=0。
br = client.get("/integrity").json()
check(
    "gap still detected after archiving clean prefix",
    not br["verified"]
    and br["checked"] == 0
    and br["first_break"] == {"seq": 4, "event_id": "e4", "reason": "seq_gap"},
    br,
)
# 现在再想把断点纳入归档: 仍然 409
r = client.post("/retention/compact", json={"cutoff_seq": 5})
cond, extra = expect_break(
    r, status_name="execute", seq=4, event_id="e4",
    reason="seq_gap", checked=0, cutoff=5, safe=5,
)
check("archive including gap after partial compact -> 409", cond, extra)


# ---------- 6. 断点晚于 cutoff: 干净前缀正常归档, 篡改仍在之后被检出 ----------
path = use_db("break_beyond_cutoff.db")
seed(path, 5)
sql(path, "UPDATE events SET payload=? WHERE id=4", (json.dumps({"v": -1}),))
# cutoff=3 不包含被篡改的 seq=4: 正常归档 1..3
r = client.post("/retention/compact", json={"cutoff_seq": 3})
body = r.json()
check("clean prefix archived despite later break",
      r.status_code == 200 and body["status"] == "compacted"
      and body["anchor_seq"] == 3 and body["deleted"] == 3, body)
br = client.get("/integrity").json()
check(
    "later break still detected from new anchor",
    not br["verified"] and br["checked"] == 0
    and br["first_break"] == {"seq": 4, "event_id": "e4", "reason": "hash_mismatch"},
    br,
)
# 视图只扣了已删的 1..3, 剩 e4/e5 计数 2
check("view decremented only by archived clean events", view_total() == 2)
# 再扩到包含断点的区间即被拒
r = client.post("/retention/compact", json={"cutoff_seq": 5})
cond, extra = expect_break(
    r, status_name="execute", seq=4, event_id="e4",
    reason="hash_mismatch", checked=0, cutoff=5, safe=5,
)
check("expanding compact over break -> 409", cond, extra)
# 已覆盖的 1..3 仍幂等
r = client.post("/retention/compact", json={"cutoff_seq": 3})
check("already covered stays idempotent",
      r.status_code == 200 and r.json()["status"] == "noop", r.text)


# ---------- 7. 无断点: dry_run / 成功响应字段与既有约定保持不变 ----------
path = use_db("clean.db")
seed(path, 3)
stored_hash_3 = sql(path, "SELECT hash FROM events WHERE id=3")[0][0]
r = client.post("/retention/compact", json={"cutoff_seq": 3, "dry_run": True})
body = r.json()
check(
    "clean dry_run response shape",
    r.status_code == 200
    and body == {
        "status": "dry_run", "dry_run": True, "would_delete": 3,
        "from_seq": 1, "through_seq": 3, "safe_through_seq": 3,
    },
    body,
)
check("dry_run writes nothing", event_count(path) == 3 and anchor_row(path) == ())
r = client.post("/retention/compact", json={"cutoff_seq": 3})
body = r.json()
check(
    "clean compact response shape",
    r.status_code == 200
    and body["status"] == "compacted"
    and body["dry_run"] is False
    and body["deleted"] == 3
    and body["from_seq"] == 1
    and body["through_seq"] == 3
    and body["anchor_seq"] == 3
    and body["anchor_hash"] == stored_hash_3
    and body["safe_through_seq"] == 3,
    body,
)
check("integrity convention intact after compact",
      client.get("/integrity").json()
      == {"verified": True, "checked": 0, "first_break": None, "anchor_seq": 3})

# cutoff_seq=0(<= 锚点 0)幂等空操作, 且不做任何校验
r = client.post("/retention/compact", json={"cutoff_seq": 0})
check("cutoff 0 noop", r.status_code == 200 and r.json()["status"] == "noop", r.text)
r = client.post("/retention/compact", json={"cutoff_seq": 0, "dry_run": True})
check("cutoff 0 dry_run empty",
      r.status_code == 200 and r.json()["status"] == "dry_run"
      and r.json()["would_delete"] == 0, r.text)


# ---------- 8. 安全边界 409 保持原约定(且先于完整性校验) ----------
path = use_db("boundary.db")
seed(path, 3, ack=False)  # 拉取不确认: consumer cursor=0, 安全上界为 0
r = client.post("/retention/compact", json={"cutoff_seq": 3})
body = r.json()
check(
    "safe boundary still enforced",
    r.status_code == 409
    and body["detail"] == "cutoff_seq exceeds safe retention boundary"
    and body["cutoff_seq"] == 3 and body["safe_through_seq"] == 0,
    body,
)
check("boundary reject leaves anchor untouched", anchor_row(path) == ())


_client_ctx.__exit__(None, None, None)
print(f"\n{ok} passed, {fail} failed")
raise SystemExit(1 if fail else 0)
