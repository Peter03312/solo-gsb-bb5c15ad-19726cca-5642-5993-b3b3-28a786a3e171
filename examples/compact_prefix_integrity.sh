#!/usr/bin/env bash
# 归档前缀完整性校验(防"篡改被归档洗白")—— 端到端调用示例。
#
# 背景: 修复前 /retention/compact 只核对序号连续性, 被篡改的待删事件仍会被
#       物理删除并推进链锚点, 原本能被 GET /integrity 检出的篡改在归档后变成
#       verified=true。修复后归档前会从当前锚点按哈希链规范逐条核对拟删除
#       前缀; 首个断点在拟归档前缀内时 dry_run 与实际执行都返回 409 并给出
#       断点 seq/event_id/reason(取值同 /integrity), 事件、日计数视图与锚点
#       保持原状。
#
# 本示例演示:
#   1) 接收 3 个事件 -> GET /integrity verified=true
#   2) 直接改库篡改 seq=2 的内容(模拟存储层篡改)
#   3) GET /integrity 检出 hash_mismatch
#   4) dry_run 归档 -> 409 + first_break(不写库)
#   5) 实际归档     -> 409 + first_break(事件/视图/锚点不变, 篡改仍可检出)
#   6) 修复篡改内容后 dry_run -> 200、实际归档 -> 200, /integrity 仍 verified
#
# 用法:
#   1) 启动服务(二选一):
#        docker compose up --build
#        pip install -r requirements.txt && uvicorn app.main:app --port 8000
#   2) 运行:
#        BASE=http://localhost:8000 DB=events.db bash examples/compact_prefix_integrity.sh
#
# 说明: 篡改与还原需要直接写 SQLite(篡改本就发生在存储层, 不经过 HTTP API);
#       DB 指向服务使用的同一个数据库文件(容器默认 /data/events.db,
#       本地开发默认 events.db;可用 DB 环境变量覆盖)。需要本机有 sqlite3 CLI。
set -euo pipefail

BASE="${BASE:-http://localhost:8000}"
DB="${DB:-events.db}"
TS="2026-10-01T12:00"

if ! command -v sqlite3 >/dev/null 2>&1; then
  echo "本示例的篡改/还原步骤需要 sqlite3 CLI(直接写数据库); 未找到 sqlite3。" >&2
  echo "纯 HTTP 部分可参考 test_compact_prefix_integrity.py(用 Python sqlite3 篡改)。" >&2
  exit 2
fi
if [ ! -f "$DB" ]; then
  echo "数据库文件 $DB 不存在; 请先在服务使用该 DB_PATH 启动并产生数据(见文件头用法)。" >&2
  exit 2
fi

post() { curl -sS -w $'\n[%{http_code}]\n' -X POST "$BASE$1" -H 'Content-Type: application/json' -d "$2"; }
get()  { curl -sS -w $'\n[%{http_code}]\n' "$BASE$1"; }

echo '== 0. 健康检查 =='
get /health

echo '== 1. 接收 c-1 / c-2 / c-3 =='
post /events "{\"event_id\":\"c-1\",\"occurred_at\":\"${TS}:00Z\",\"payload\":{\"v\":1}}"
post /events "{\"event_id\":\"c-2\",\"occurred_at\":\"${TS}:01Z\",\"payload\":{\"v\":2}}"
post /events "{\"event_id\":\"c-3\",\"occurred_at\":\"${TS}:02Z\",\"payload\":{\"v\":3}}"

echo '== 2. 归档前完整性校验: verified=true =='
get /integrity

echo '== 3. 直接写库篡改 seq=2 的 payload(模拟存储层篡改) =='
# 备份原内容, 示例结束后可用同一语句还原(第 6 步会自动还原)
ORIG=$(sqlite3 "$DB" "SELECT payload FROM events WHERE event_id='c-2';")
echo "    原 payload: $ORIG"
sqlite3 "$DB" "UPDATE events SET payload='{\"v\":200}' WHERE event_id='c-2';"
echo "    篡改后: $(sqlite3 "$DB" "SELECT payload FROM events WHERE event_id='c-2';")"

echo '== 4. /integrity 检出首个断点: seq=2 reason=hash_mismatch =='
get /integrity

echo '== 5a. dry_run 归档(cutoff_seq=3): 409 + first_break, 不写库 =='
post /retention/compact '{"cutoff_seq":3,"dry_run":true}'

echo '== 5b. 实际归档(cutoff_seq=3): 同样 409, 事件/视图/锚点保持原状 =='
post /retention/compact '{"cutoff_seq":3}'
echo "    events 仍为: $(sqlite3 "$DB" 'SELECT COUNT(*) FROM events;') 条(未被删除)"
echo "    chain_anchor: $(sqlite3 "$DB" 'SELECT COALESCE(anchor_seq, 0) FROM chain_anchor WHERE id=1;' || echo '(无行, 锚点未推进)')"

echo '== 5c. 断点不在拟归档前缀内时仍可按边界归档(此处仅演示 409 响应中的断点定位) =='
echo '    上面的 first_break.seq=2 落在 (锚点0, cutoff_seq=3] 内, 故拒绝;'
echo '    若把 cutoff_seq 改为断点之前(且链在该范围内完好)的序号, 则照常归档。'

echo '== 6. 还原篡改内容 -> /integrity 恢复 verified, dry_run/实际归档成功 =='
sqlite3 "$DB" "UPDATE events SET payload='$ORIG' WHERE event_id='c-2';"
get /integrity
post /retention/compact '{"cutoff_seq":3,"dry_run":true}'
post /retention/compact '{"cutoff_seq":3}'

echo '== 7. 归档后 /integrity 从锚点继续校验, verified=true(checked=0) =='
get /integrity
