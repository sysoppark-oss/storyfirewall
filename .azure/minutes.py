#!/usr/bin/env python3
# Azure 무료 호스팅 사용 시간(월 1,800분) 보고. Azure 로그인 없이 GitHub ci-logs 브랜치의 meta.txt 로 센다.
#   git fetch origin ci-logs && python3 .azure/minutes.py [YYYY-MM]
# meta.txt 의 job_start(작업자 프로세스 시작 ≈ job 시작)~time(로그 올린 시각)을 job 시간으로 본다. 체크아웃·정리 몇 분은 빠진다(추정치).
# job_start 가 없는 예전 기록과 노트북 자체 실행기(agent=laptop…, 무료 분에 안 셈)는 따로 센다.
import subprocess
import sys
from collections import defaultdict
from datetime import datetime

LIMIT = 1800
month = sys.argv[1] if len(sys.argv) > 1 else datetime.utcnow().strftime("%Y-%m")


def git(*a: str) -> str:
    return subprocess.run(["git", *a], capture_output=True, text=True, check=True).stdout


def ts(s: str) -> datetime:
    return datetime.strptime(s.rstrip("Z"), "%Y-%m-%dT%H:%M:%S")


paths = [p for p in git("ls-tree", "-r", "--name-only", "origin/ci-logs", "azure").splitlines() if p.endswith("/meta.txt")]
mins: dict[str, float] = defaultdict(float)
runs: dict[str, int] = defaultdict(int)
unknown: dict[str, int] = defaultdict(int)
for p in paths:
    meta = dict(l.split("=", 1) for l in git("show", f"origin/ci-logs:{p}").splitlines() if "=" in l)
    t = meta.get("time", "")
    if not t.startswith(month):
        continue
    name = p.split("/")[1]
    if meta.get("agent", "").lower().startswith("laptop"):
        name += "(노트북, 무료 분 아님)"
    runs[name] += 1
    if meta.get("job_start"):
        mins[name] += max(0.0, (ts(t) - ts(meta["job_start"])).total_seconds() / 60)
    else:
        unknown[name] += 1

hosted = sum(v for k, v in mins.items() if "노트북" not in k)
print(f"Azure 호스팅 사용 시간 {month} (ci-logs 기준 추정)")
for k in sorted(runs):
    extra = f", 시간 모름 {unknown[k]}건" if unknown[k] else ""
    print(f"  {k:28s} 실행 {runs[k]:3d}건  {mins[k]:7.1f}분{extra}")
print(f"  합계(호스팅) {hosted:.0f}분 / {LIMIT}분 ({hosted / LIMIT:.0%})  — 시간 모름 건은 빠짐")
