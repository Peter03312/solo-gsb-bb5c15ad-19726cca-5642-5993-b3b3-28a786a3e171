#!/usr/bin/env bash
# 归档前缀完整性校验 —— 端到端调用示例。
#
# 背景修复: 旧版本在待删事件已被改动时仍推进链锚点, 使 /integrity 本可检出的
# 篡改在归档后"消失"(verified 反而变 true)。现在 /retention/compact 在删除前
# 从当前锚点按 /integrity 的同一规范逐条核对拟删除前缀(序号连续性、前后哈希
# 衔接、内容哈希); 首个断点落在拟归档前缀内时, dry_run 与实际归档都返回
# 409 及断点 seq/event_id/reason, 事件、日计数视图与锚点保持原状。
#
# 除"模拟磁盘篡改"一步直接改本地 SQLite 文件(线上没有对应的 HTTP 篡改接口)
# 外, 其余全部走 HTTP API。
#
# 用法:
#   1) 启动服务:  uvicorn app.main:app --port 8000
#      (或 docker compose up --build)
#   2) 运行示例:  BASE=http://localhost:8000 DB=events.db \
#                 bash examples/compact_integrity.sh
#      (容器部署时把 DB 指向容器内的 /data/events.db, 或省略 DB 步骤改用已有库)
set -euo pipefail

BASE="${BASE:-http://localhost:8000}"
CONSUMER="${CONSUMER:-tamper-demo}"
TS="2026-09-29T12:00"
DB="${DB:-events.db}"   # 需与服务端 DB_PATH 一致, 仅第 6 步模拟篡改时使用

post() { curl -sS -w $'\n[%{http_code}]\n' -X POST "$BASE$1" -H 'Content-Type: application/json' -d "$2"; }
get()  { curl -sS -w $'\n[%{http_code}]\n' "$BASE$1"; }

# 接收 n 条事件, 然后用 $CONSUMER 拉取并确认整批(把游标推到 n, 满足安全边界)
receive_and_ack() {
  local n="$1"
  for i in $(seq 1 "$n"); do
    local ss
    ss=$(printf '%02d' "$i")
    curl -sS -o /dev/null -X POST "$BASE/events" -H 'Content-Type: application/json' \
      -d "{\"event_id\":\"tam-e$i\",\"occurred_at\":\"${TS}:${ss}Z\",\"payload\":{\"v\":$i}}"
  done
  local batch token
  batch=$(curl -sS -X POST "$BASE/consumers/$CONSUMER/pull" \
    -H 'Content-Type: application/json' -d '{"lease_seconds":120}')
  token=$(printf '%s' "$batch" | python3 -c 'import sys,json;print(json.load(sys.stdin)["lease_token"])')
  curl -sS -o /dev/null -X POST "$BASE/consumers/$CONSUMER/ack" \
    -H 'Content-Type: application/json' -d "{\"lease_token\":\"$token\"}"
}

echo '== 1. 接收 4 条事件并全部确认(自动续接哈希链) =='
receive_and_ack 4
get /integrity

echo '== 2. 无篡改时 dry_run 正常(原有约定不变) =='
post /retention/compact '{"cutoff_seq":4,"dry_run":true}'

echo '== 3. 模拟磁盘篡改: 直接把 seq=2 的 payload 改掉(仅演示, 非 API 操作) =='
python3 - "$DB" <<'PY'
import sqlite3, sys
con = sqlite3.connect(sys.argv[1])
con.execute("UPDATE events SET payload=? WHERE id=2", ('{"v": 999}',))
con.commit()
con.close()
print('tampered events.id=2 payload -> {"v":999}')
PY

echo '== 4. /integrity: 在 seq=2 检出 hash_mismatch =='
get /integrity

echo '== 5. dry_run 被拒: 409 + 断点(seq/event_id/reason 同 /integrity) =='
post /retention/compact '{"cutoff_seq":4,"dry_run":true}'

echo '== 6. 实际归档同样 409; 事件、视图、锚点保持原状 =='
post /retention/compact '{"cutoff_seq":4}'
get /integrity

echo '== 7. 断点不在拟归档前缀内时: 只归档干净的 seq<=1 仍成功 =='
post /retention/compact '{"cutoff_seq":1}'

echo '== 8. 校验从新锚点续起: 断点 seq=2 仍被检出, 不会被归档盖过去 =='
get /integrity

echo '== 9. 已覆盖区间幂等: cutoff<=anchor 直接 noop, 不再校验 =='
post /retention/compact '{"cutoff_seq":1}'

echo '== 10. 想把断点纳入归档仍被 409 拒绝 =='
post /retention/compact '{"cutoff_seq":4}'
