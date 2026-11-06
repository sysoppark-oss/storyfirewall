#!/bin/sh
# 공개 저장소 dev-builds -> 비공개 dev-builds (노트북 작업 실행기는 비공개 저장소를 받는다)
set -e
cd /home/claude/story-firewall
git fetch -q https://github.com/sysoppark-oss/storyfirewall dev-builds
git show FETCH_HEAD:manifest.txt | head -1
git push -f -q origin FETCH_HEAD:refs/heads/dev-builds-gh 2>/dev/null || true
git push -f -q origin FETCH_HEAD:refs/heads/dev-builds 2>/dev/null || true
git ls-remote origin dev-builds-gh dev-builds
