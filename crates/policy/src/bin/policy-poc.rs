//! A5 러너용: WFP 차단 PoC (명세 5차 검증 의뢰서 2-6 시나리오)
//!
//! 사용
//!   policy-poc block <exe경로> <ids.json>        Provider·Sublayer 보장 + 아웃바운드 차단(V4·V6) 트랜잭션, ID 저장
//!   policy-poc list                               우리 Provider 의 필터 목록 (영구성 대리 확인)
//!   policy-poc watch <초> <ids.json>              삭제 구독 → 재등록(자가 치유) + 차단 이벤트 출력
//!   policy-poc delete <id>                        (공격자 역할) 필터 하나 삭제
//!   policy-poc unblock <ids.json>                 ID 들 삭제
//!   policy-poc cleanup                            모든 우리 필터·Sublayer·Provider 삭제
//!   policy-poc guardtest                          규칙 8 거부 확인
//! 관리자 권한 필요. 러너 에이전트는 보호 목록(가드)에 하드코딩 — 러너 고립 방지 (5차 검증 Q7).

#[cfg(any(windows, feature = "host-check"))]
fn fail(e: &dyn std::fmt::Display) -> ! {
    eprintln!("[error] {e}");
    std::process::exit(2);
}

#[cfg(any(windows, feature = "host-check"))]
fn main() {
    use policy::guard::Guard;
    use policy::spec::{BlockSpec, Direction};
    use policy::wfp::Engine;
    use std::collections::HashMap;
    use std::time::{Duration, Instant};

    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(|s| s.as_str()).unwrap_or("");
    // 보호 목록: 우리 자신 + 러너 에이전트 (제품에서는 자신 + 규칙 8 만)
    let guard = Guard::new(&[
        "policy-poc.exe",
        "story-firewall-svc.exe",
        "Runner.Listener.exe",
        "Runner.Worker.exe",
        "hosted-compute-agent.exe",
        "hosted-compute-agent",
    ]);
    let now_ft = || -> i64 {
        let unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        unix.as_nanos() as i64 / 100 + 116_444_736_000_000_000
    };

    match cmd {
        "block" => {
            let exe = args.get(2).expect("exe path");
            let out = args.get(3).expect("ids.json");
            let long = policy_long_path(exe);
            let spec = BlockSpec::app("poc", &long, Direction::Out);
            if let Err(e) = guard.check(&spec) {
                fail(&e);
            }
            let eng = Engine::open().unwrap_or_else(|e| fail(&e));
            eng.ensure_provider_sublayer().unwrap_or_else(|e| fail(&e));
            let t0 = Instant::now();
            let added = eng.apply(&[spec]).unwrap_or_else(|e| fail(&e));
            println!(
                "block: {} filters in {:?} for {long}",
                added.len(),
                t0.elapsed()
            );
            let map: HashMap<u64, BlockSpec> = added.into_iter().collect();
            std::fs::write(out, serde_json::to_string_pretty(&map).unwrap()).unwrap();
            for id in map.keys() {
                println!("filter_id={id}");
            }
        }
        "list" => {
            let eng = Engine::open().unwrap_or_else(|e| fail(&e));
            let ours = eng.list_ours().unwrap_or_else(|e| fail(&e));
            println!("ours={}", ours.len());
            for (id, name, _) in ours {
                println!("  {id} {name}");
            }
        }
        "watch" => {
            let secs: u64 = args.get(2).and_then(|a| a.parse().ok()).unwrap_or(15);
            let path = args.get(3).expect("ids.json");
            let mut map: HashMap<u64, BlockSpec> =
                serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
            let mut eng = Engine::open().unwrap_or_else(|e| fail(&e));
            eng.subscribe_deletes().unwrap_or_else(|e| fail(&e));
            eng.enable_net_events().unwrap_or_else(|e| fail(&e));
            let start_ft = now_ft();
            let mut seen_drops = 0usize;
            let mut healed = 0usize;
            let end = Instant::now() + Duration::from_secs(secs);
            let mut last_drop_ts = start_ft;
            while Instant::now() < end {
                std::thread::sleep(Duration::from_millis(200));
                let (deleted, sub_gone, prov_gone) = eng.take_deleted();
                for id in deleted {
                    if let Some(spec) = map.remove(&id) {
                        let t0 = Instant::now();
                        // 정식 삭제 목록이 없는 PoC: 모든 삭제를 변조로 본다
                        if sub_gone || prov_gone {
                            eng.ensure_provider_sublayer().unwrap_or_else(|e| fail(&e));
                        }
                        match eng.apply(&[spec.clone()]) {
                            Ok(added) => {
                                healed += 1;
                                let ids: Vec<u64> = added.iter().map(|(i, _)| *i).collect();
                                println!("TAMPER: filter {id} deleted externally -> re-added as {ids:?} in {:?} (sublayer_gone={sub_gone} provider_gone={prov_gone})", t0.elapsed());
                                for (i, s) in added {
                                    map.insert(i, s);
                                }
                            }
                            Err(e) => println!("TAMPER: filter {id} deleted, re-add FAILED: {e}"),
                        }
                    } else {
                        println!("note: unknown filter {id} deleted (not ours in map)");
                    }
                }
                match eng.drops_since(last_drop_ts) {
                    Ok(drops) => {
                        for d in drops {
                            if d.ts > last_drop_ts {
                                last_drop_ts = d.ts;
                            }
                            let ours = map.contains_key(&d.filter_id);
                            seen_drops += 1;
                            if seen_drops <= 40 {
                                println!(
                                    "DROP filter={} ours={} layer={} proto={} remote={:?}:{} app={}",
                                    d.filter_id, ours, d.layer_id, d.protocol, d.remote_v4, d.remote_port, d.app_id
                                );
                            }
                        }
                    }
                    Err(e) => println!("drops_since error: {e}"),
                }
            }
            std::fs::write(path, serde_json::to_string_pretty(&map).unwrap()).unwrap();
            println!(
                "watch done: healed={healed} drops_seen={seen_drops} current_ids={:?}",
                map.keys().collect::<Vec<_>>()
            );
        }
        "delete" => {
            let id: u64 = args.get(2).and_then(|a| a.parse().ok()).expect("id");
            let eng = Engine::open().unwrap_or_else(|e| fail(&e));
            eng.delete(&[id]).unwrap_or_else(|e| fail(&e));
            println!("deleted {id}");
        }
        // replace <ids.json> <exe> <out.json> [fail] : 한 트랜잭션으로 ids 삭제 + exe 차단 추가. fail 이면 추가 명세에
        // 가드가 아니라 BFE 가 거부할 값(잘못된 포트 범위 hi<lo)을 섞어 abort 를 유도 → 이전 필터가 그대로 남아야 한다
        "replace" => {
            let old_path = args.get(2).expect("ids.json");
            let exe = args.get(3).expect("exe path");
            let out = args.get(4).expect("out.json");
            let inject_fail = args.get(5).map_or(false, |f| f == "fail");
            let map: HashMap<u64, BlockSpec> =
                serde_json::from_str(&std::fs::read_to_string(old_path).unwrap()).unwrap();
            let old_ids: Vec<u64> = map.keys().copied().collect();
            let long = policy_long_path(exe);
            let mut spec = BlockSpec::app("poc-replace", &long, Direction::Out);
            if inject_fail {
                spec.remote_ports = vec![policy::spec::PortRange { lo: 443, hi: 80 }];
                // BFE 가 FWP_E_INVALID_PARAMETER 로 거부(기대)
            }
            let eng = Engine::open().unwrap_or_else(|e| fail(&e));
            let t0 = Instant::now();
            match eng.replace(&old_ids, &[spec]) {
                Ok(added) => {
                    println!(
                        "replace: removed {} added {} in {:?}",
                        old_ids.len(),
                        added.len(),
                        t0.elapsed()
                    );
                    let map: HashMap<u64, BlockSpec> = added.into_iter().collect();
                    std::fs::write(out, serde_json::to_string_pretty(&map).unwrap()).unwrap();
                }
                Err(e) => {
                    println!(
                        "replace: FAILED ({e}) — transaction aborted, old filters must remain"
                    );
                }
            }
            let ours = eng.list_ours().unwrap_or_default();
            let still_old = old_ids
                .iter()
                .filter(|id| ours.iter().any(|(x, _, _)| x == *id))
                .count();
            println!(
                "replace: old filters still present = {still_old}/{}, ours total = {}",
                old_ids.len(),
                ours.len()
            );
        }
        "unblock" => {
            let path = args.get(2).expect("ids.json");
            let map: HashMap<u64, BlockSpec> =
                serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
            let eng = Engine::open().unwrap_or_else(|e| fail(&e));
            let ids: Vec<u64> = map.keys().copied().collect();
            eng.delete(&ids).unwrap_or_else(|e| fail(&e));
            println!("unblock: deleted {} filters", ids.len());
        }
        "cleanup" => {
            let eng = Engine::open().unwrap_or_else(|e| fail(&e));
            let n = eng.remove_all().unwrap_or_else(|e| fail(&e));
            let left = eng.list_ours().unwrap_or_default();
            println!("cleanup: deleted {n} filters, remaining={}", left.len());
        }
        // ACL 정책 관리(2026-11-06) 실측: acltest <인터페이스 별칭> <이 PC IPv4> — curl.exe → 1.1.1.1 로
        // ① 인터페이스·이 PC 주소 조건 차단이 걸리는지 ② 없는 인터페이스 이름은 적용 실패인지
        // ③ 번호 순서: 허용(1번)+차단(2번)이면 통과, 차단(1번)+허용(2번)이면 막힘 ④ ICMPv4 필터 추가 가능
        "acltest" => {
            let alias = args.get(2).expect("interface alias").clone();
            let local: std::net::Ipv4Addr = args.get(3).expect("local ipv4").parse().expect("ipv4");
            let curl = r"C:\Windows\System32\curl.exe";
            let one: std::net::Ipv4Addr = "1.1.1.1".parse().unwrap();
            let rng = |a: std::net::Ipv4Addr| policy::spec::V4Range { lo: a, hi: a };
            let eng = Engine::open().unwrap_or_else(|e| fail(&e));
            eng.ensure_provider_sublayer().unwrap_or_else(|e| fail(&e));
            let reach = || -> bool {
                std::process::Command::new(curl)
                    .args(["-sS", "-o", "NUL", "-m", "5", "https://1.1.1.1"])
                    .status()
                    .map(|s| s.success())
                    .unwrap_or(false)
            };
            let mut bad = 0;
            let mut check = |ok: bool, what: &str| {
                println!("{} {what}", if ok { "PASS" } else { "FAIL" });
                if !ok {
                    bad += 1;
                }
            };
            check(reach(), "before: curl reaches 1.1.1.1");
            let mut base = BlockSpec::app("acl", curl, Direction::Out);
            base.remote_v4 = vec![rng(one)];
            base.ip_family = Some(policy::spec::IpFamily::V4);
            // ① 인터페이스 + 이 PC 주소
            let mut a = base.clone();
            a.interface = Some(alias.clone());
            a.local_v4 = vec![rng(local)];
            let ids = eng.apply(&[a]).unwrap_or_else(|e| fail(&e));
            check(!reach(), "interface+local address block stops curl");
            eng.delete(&ids.iter().map(|x| x.0).collect::<Vec<_>>())
                .unwrap_or_else(|e| fail(&e));
            check(reach(), "after delete: curl reaches again");
            // ①' 다른 이 PC 주소면 걸리지 않는다(조건이 실제로 들어갔는지)
            let mut a2 = base.clone();
            a2.local_v4 = vec![rng("10.255.255.254".parse().unwrap())];
            let ids = eng.apply(&[a2]).unwrap_or_else(|e| fail(&e));
            check(reach(), "other local address: not blocked");
            eng.delete(&ids.iter().map(|x| x.0).collect::<Vec<_>>())
                .unwrap_or_else(|e| fail(&e));
            // ② 없는 인터페이스
            let mut b = base.clone();
            b.interface = Some("no-such-interface-xyz".into());
            check(eng.apply(&[b]).is_err(), "unknown interface alias rejected");
            // ③ 번호 순서
            let w = |n: u64| 0x8000_0000_0000_0000u64 - (n << 40);
            let mut allow = base.clone();
            allow.action = policy::spec::Action::Permit;
            let mut block = base.clone();
            allow.weight = Some(w(1));
            block.weight = Some(w(2));
            let ids = eng
                .apply(&[allow.clone(), block.clone()])
                .unwrap_or_else(|e| fail(&e));
            check(reach(), "allow #1 above block #2: reachable");
            eng.delete(&ids.iter().map(|x| x.0).collect::<Vec<_>>())
                .unwrap_or_else(|e| fail(&e));
            allow.weight = Some(w(2));
            block.weight = Some(w(1));
            let ids = eng.apply(&[allow, block]).unwrap_or_else(|e| fail(&e));
            check(!reach(), "block #1 above allow #2: blocked");
            eng.delete(&ids.iter().map(|x| x.0).collect::<Vec<_>>())
                .unwrap_or_else(|e| fail(&e));
            // ③' 번호 없는 보안 차단(끊기 등, weight 구간 14)은 ACL 허용 1번보다 위 — ACL 로 끊기를 뚫지 못한다
            let mut allow1 = base.clone();
            allow1.action = policy::spec::Action::Permit;
            allow1.weight = Some(w(1));
            let mut sec = base.clone();
            sec.weight = None;
            let ids = eng.apply(&[allow1, sec]).unwrap_or_else(|e| fail(&e));
            check(!reach(), "unnumbered security block beats ACL allow #1");
            eng.delete(&ids.iter().map(|x| x.0).collect::<Vec<_>>())
                .unwrap_or_else(|e| fail(&e));
            // ④ ICMPv4 필터(1.1.1.1 만, 앱 조건 없음)
            let mut ic = base.clone();
            ic.app_path = None;
            ic.protocols = vec![1];
            match guard.check(&ic).and_then(|_| eng.apply(&[ic])) {
                Ok(ids) => {
                    check(true, "icmpv4 filter added");
                    eng.delete(&ids.iter().map(|x| x.0).collect::<Vec<_>>())
                        .unwrap_or_else(|e| fail(&e));
                }
                Err(e) => check(false, &format!("icmpv4 filter added ({e})")),
            }
            let left = eng.list_ours().unwrap_or_default();
            check(left.is_empty(), "no filters left");
            println!("acltest: {bad} failed");
            if bad > 0 {
                std::process::exit(1);
            }
        }
        "guardtest" => {
            let cases: Vec<(&str, BlockSpec)> = vec![
                ("loopback", {
                    let mut s =
                        BlockSpec::app("g", r"C:\Windows\System32\curl.exe", Direction::Out);
                    s.remote_v4 = vec![policy::spec::V4Range {
                        lo: "127.0.0.0".parse().unwrap(),
                        hi: "127.255.255.255".parse().unwrap(),
                    }];
                    s
                }),
                ("icmp", {
                    let mut s =
                        BlockSpec::app("g", r"C:\Windows\System32\curl.exe", Direction::Out);
                    s.protocols = vec![1];
                    s
                }),
                ("svchost+53", {
                    let mut s =
                        BlockSpec::app("g", r"C:\Windows\System32\svchost.exe", Direction::Out);
                    s.remote_ports = vec![policy::spec::PortRange { lo: 53, hi: 53 }];
                    s
                }),
                (
                    "svchost-wide",
                    BlockSpec::app("g", r"C:\Windows\System32\svchost.exe", Direction::Out),
                ),
                (
                    "runner-agent",
                    BlockSpec::app(
                        "g",
                        r"C:\actions-runner\bin\Runner.Listener.exe",
                        Direction::Out,
                    ),
                ),
                (
                    "self",
                    BlockSpec::app("g", r"C:\x\policy-poc.exe", Direction::Out),
                ),
                ("dhcp", {
                    let mut s =
                        BlockSpec::app("g", r"C:\Windows\System32\curl.exe", Direction::Out);
                    s.remote_ports = vec![policy::spec::PortRange { lo: 67, hi: 68 }];
                    s.protocols = vec![17];
                    s
                }),
            ];
            let mut rejected = 0;
            for (name, s) in &cases {
                match guard.check(s) {
                    Err(e) => {
                        rejected += 1;
                        println!("GUARD {name}: rejected ({e})");
                    }
                    Ok(()) => println!("GUARD {name}: ACCEPTED (unexpected)"),
                }
            }
            println!("guardtest: rejected {rejected}/{}", cases.len());
        }
        _ => {
            eprintln!("usage: policy-poc block|list|watch|delete|unblock|cleanup|guardtest ...");
            std::process::exit(1);
        }
    }

    /// 8.3 → 긴 경로 (5차 검증 Q3). FwpmGetAppIdFromFileName0 전에 반드시.
    fn policy_long_path(p: &str) -> String {
        use windows_sys::Win32::Storage::FileSystem::GetLongPathNameW;
        let wide: Vec<u16> = p.encode_utf16().chain(std::iter::once(0)).collect();
        let mut buf = vec![0u16; 1024];
        let n =
            unsafe { GetLongPathNameW(wide.as_ptr(), buf.as_mut_ptr(), buf.len() as u32) } as usize;
        if n == 0 || n >= buf.len() {
            p.to_string()
        } else {
            String::from_utf16_lossy(&buf[..n])
        }
    }
}

#[cfg(not(any(windows, feature = "host-check")))]
fn main() {
    eprintln!("policy-poc 는 Windows 전용입니다.");
}
