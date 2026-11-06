// 설치 화면(설치 엑스레이, 기획서 14판 20-3)의 순수 도우미. DOM 없음 — 단위 시험 대상.
// 판정하지 않는다: 사실의 개수와 목록만 말한다(점수·의심 표현 없음).

/// 서비스 installs.list 의 한 항목 (crates/graph/src/install.rs InstallRun)
export interface InstallRun {
  root: number;
  image: string;
  pid: number | null;
  /// FILETIME(100ns)
  start_ts: number;
  last_ts: number;
  /// 내려받은 곳(호스트 또는 URL), 알 때만
  origin: string | null;
  /// 묶음의 프로세스 이미지 경로(뿌리 포함)
  procs: string[];
  /// 만든 파일(수집 범위: 실행 파일·스크립트, 사용자 쓰기 가능 경로)
  files: string[];
  /// 자동 실행 등록 [위치, 대상]
  autoruns: [string, string][];
  /// 접속한 곳 [이름, 횟수] — 많은 순
  remotes: [string, number][];
  commands: string[];
  truncated: boolean;
  /// L060: 자리잡기 명령(예약 작업 만들기·서비스 등록 …) 사실 줄
  persistence?: string[];
  /// L060: 부모 연결 없이 2분 안에 이어 시작해 함께 묶은 설치 과정(실행 파일 경로)
  grouped?: string[];
}

/// 조회 범위(일). 서비스 허용 범위 1..30
export const INSTALL_DAYS = [1, 7, 30] as const;
export type InstallDays = (typeof INSTALL_DAYS)[number];

/// "하루" / "7일" / "30일"
export function daysLabel(days: number): string {
  return days === 1 ? "하루" : `${days}일`;
}

/// 빈 상태 문장: "최근 7일 동안 찾은 설치가 없습니다."
export function emptyText(days: number): string {
  return `최근 ${daysLabel(days)} 동안 찾은 설치가 없습니다.`;
}

/// 설치를 어떻게 찾는지(빈 상태 보조 줄). 서버 규칙 is_installer_image 와 같은 내용
export const HOW_FOUND = "이름에 'setup' 또는 'install'이 들어간 실행 파일과 msiexec 실행을 설치로 셉니다. 제거 프로그램과 Windows 폴더 안의 구성 요소는 뺍니다.";

/// 자동 실행의 대조 범위 (L060)
export const AUTORUN_SCOPE = "대조 범위: Run 키 등록, 예약 작업·서비스 등록 명령(명령줄을 받은 경우)";

/// 시간으로 묶은 설치 과정 안내 (L060)
export const GROUPED_NOTE = "부모 연결은 없지만 2분 안에 이어서 시작해 이 설치로 함께 묶었습니다.";

/// 만든 파일의 수집 범위 — Program Files 등에 쓴 파일은 세지 않음을 알린다
export const FILES_SCOPE = "수집 범위: 실행 파일·스크립트, 사용자 쓰기 가능 폴더 (Program Files 등에 쓴 파일은 세지 않습니다)";

/// 경로에서 파일 이름만. 구분자 \ 와 / 둘 다, 끝의 구분자는 무시
export function baseName(path: string): string {
  const p = path.replace(/[\\/]+$/, "");
  const i = Math.max(p.lastIndexOf("\\"), p.lastIndexOf("/"));
  return i >= 0 ? p.slice(i + 1) : p;
}

/// 경로 비교용 정규화(대소문자·구분자 무시 — Windows 경로)
function normPath(p: string): string {
  return p.replace(/\//g, "\\").toLowerCase();
}

/// 함께 실행된 프로그램: 뿌리(설치 프로그램 자신) 한 번을 뺀 나머지.
/// 뿌리와 같은 경로의 다른 프로세스(설치 프로그램이 자기를 다시 띄운 경우)는 남긴다
export function childProcs(run: Pick<InstallRun, "image" | "procs">): string[] {
  const out = [...run.procs];
  const i = out.findIndex((p) => normPath(p) === normPath(run.image));
  if (i >= 0) out.splice(i, 1);
  return out;
}

/// 내려받은 곳 표시: URL 이면 호스트만, 아니면 그대로. 비었으면 null
export function originHost(origin: string | null | undefined): string | null {
  const s = (origin ?? "").trim();
  if (!s) return null;
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) {
    try {
      const h = new URL(s).hostname;
      if (h) return h;
    } catch {
      // URL 이 아니면 아래에서 그대로
    }
  }
  return s;
}

/// 한 줄 요약: "프로그램 3개 실행 · 파일 2개 만듦 · 자동 실행 1개 등록 · 접속한 곳 2곳".
/// 0인 항목은 뺀다. 모두 0이면 그렇다고 말한다(판정 아님)
export function summaryText(run: Pick<InstallRun, "image" | "procs" | "files" | "autoruns" | "remotes" | "persistence">): string {
  const parts: string[] = [];
  const procs = childProcs(run).length;
  if (procs) parts.push(`프로그램 ${procs}개 실행`);
  if (run.files.length) parts.push(`파일 ${run.files.length}개 만듦`);
  const auto = run.autoruns.length + (run.persistence?.length ?? 0);
  if (auto) parts.push(`자동 실행 관련 ${auto}건`);
  if (run.remotes.length) parts.push(`접속한 곳 ${run.remotes.length}곳`);
  // 검수 1번: "아무 일도 안 했다"로 읽히지 않게 — 모은 범위의 기록이 없다는 사실과 한계를 함께
  return parts.length
    ? parts.join(" · ")
    : "이 설치 프로그램과 그 자손에서 모은 기록이 없습니다 (Program Files 에 쓴 파일, 따로 뜬 설치 과정은 잡히지 않을 수 있습니다)";
}

/// 같은 경로를 한 줄로 합친다(검수 3번): [경로, 횟수] — 처음 나온 순서. 대소문자·구분자 무시
export function countPaths(paths: string[]): [string, number][] {
  const out: [string, number][] = [];
  const idx = new Map<string, number>();
  for (const p of paths) {
    const k = normPath(p);
    const i = idx.get(k);
    if (i === undefined) {
      idx.set(k, out.length);
      out.push([p, 1]);
    } else out[i]![1] += 1;
  }
  return out;
}

/// 접속한 곳 한 줄: "example.com ×3" (1번이면 횟수 생략)
export function remoteText([name, count]: [string, number]): string {
  return count > 1 ? `${name} ×${count}` : name;
}

/// 최신 먼저(start_ts 내림차순). 원본은 바꾸지 않는다
export function sortInstalls<T extends { start_ts: number }>(xs: T[]): T[] {
  return [...xs].sort((a, b) => b.start_ts - a.start_ts);
}
