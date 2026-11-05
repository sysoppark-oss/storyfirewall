//! 포트·프로토콜 → 사람이 아는 용도. 이름 없는 IP 접속을 읽기 쉽게 만든다.
//!
//! 사실을 바꾸지 않는다: "168.63.129.16:53 에 접속" 은 "DNS 서버 168.63.129.16 에 주소를 물음" 으로
//! 바뀌지만, 근거·대상·시각은 그대로다. 용도를 모르는 포트는 포트 번호를 그대로 쓴다.

use graph::event::Proto;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Purpose {
    /// 짧은 이름 (예: "DNS 서버", "웹 서버")
    pub name: &'static str,
    /// 동사구 (예: "에 주소를 물었습니다")
    pub plain_verb: &'static str,
    /// 전문가 화법용 꼬리표 (예: "DNS")
    pub tag: &'static str,
    /// 위험 포트 여부 (리스닝 포트 점검에서 강조할 것)
    pub risky_listen: bool,
}

pub fn purpose(proto: Proto, port: u16) -> Option<Purpose> {
    Some(match (proto, port) {
        (Proto::Udp, 53) | (Proto::Tcp, 53) => Purpose {
            name: "DNS 서버",
            plain_verb: "에 주소를 물었습니다",
            tag: "DNS",
            risky_listen: false,
        },
        (Proto::Tcp, 80) => Purpose {
            name: "웹 서버",
            plain_verb: "에 접속했습니다 (암호화 안 된 웹)",
            tag: "HTTP",
            risky_listen: false,
        },
        (Proto::Tcp, 443) | (Proto::Udp, 443) => Purpose {
            name: "웹 서버",
            plain_verb: "에 접속했습니다",
            tag: "HTTPS",
            risky_listen: false,
        },
        (Proto::Tcp, 445) => Purpose {
            name: "파일 공유",
            plain_verb: "의 파일 공유에 접속했습니다",
            tag: "SMB",
            risky_listen: true,
        },
        (Proto::Tcp, 139) => Purpose {
            name: "파일 공유",
            plain_verb: "의 파일 공유에 접속했습니다",
            tag: "NetBIOS",
            risky_listen: true,
        },
        (Proto::Tcp, 3389) => Purpose {
            name: "원격 데스크톱",
            plain_verb: "의 원격 데스크톱에 접속했습니다",
            tag: "RDP",
            risky_listen: true,
        },
        (Proto::Tcp, 5985) | (Proto::Tcp, 5986) => Purpose {
            name: "원격 관리",
            plain_verb: "의 원격 관리(WinRM)에 접속했습니다",
            tag: "WinRM",
            risky_listen: true,
        },
        (Proto::Tcp, 22) => Purpose {
            name: "SSH",
            plain_verb: "에 SSH 로 접속했습니다",
            tag: "SSH",
            risky_listen: true,
        },
        (Proto::Tcp, 23) => Purpose {
            name: "텔넷",
            plain_verb: "에 텔넷(암호화 없음)으로 접속했습니다",
            tag: "Telnet",
            risky_listen: true,
        },
        (Proto::Tcp, 21) => Purpose {
            name: "FTP",
            plain_verb: "에 FTP(암호화 없음)로 접속했습니다",
            tag: "FTP",
            risky_listen: true,
        },
        (Proto::Tcp, 25) | (Proto::Tcp, 587) | (Proto::Tcp, 465) => Purpose {
            name: "메일 발송",
            plain_verb: "으로 메일을 보냈습니다",
            tag: "SMTP",
            risky_listen: false,
        },
        (Proto::Tcp, 993) | (Proto::Tcp, 143) => Purpose {
            name: "메일함",
            plain_verb: "의 메일함에 접속했습니다",
            tag: "IMAP",
            risky_listen: false,
        },
        (Proto::Udp, 123) => Purpose {
            name: "시간 서버",
            plain_verb: "에 시각을 맞췄습니다",
            tag: "NTP",
            risky_listen: false,
        },
        (Proto::Udp, 67) | (Proto::Udp, 68) => Purpose {
            name: "주소 배정",
            plain_verb: "에서 IP 주소를 받았습니다",
            tag: "DHCP",
            risky_listen: false,
        },
        (Proto::Tcp, 1433) => Purpose {
            name: "데이터베이스",
            plain_verb: "의 데이터베이스에 접속했습니다",
            tag: "MSSQL",
            risky_listen: true,
        },
        (Proto::Tcp, 3306) => Purpose {
            name: "데이터베이스",
            plain_verb: "의 데이터베이스에 접속했습니다",
            tag: "MySQL",
            risky_listen: true,
        },
        (Proto::Tcp, 5900) => Purpose {
            name: "원격 화면",
            plain_verb: "의 원격 화면(VNC)에 접속했습니다",
            tag: "VNC",
            risky_listen: true,
        },
        _ => return None,
    })
}

/// 리스닝 포트 점검에서 강조할 포트인가
pub fn is_risky_listen(proto: Proto, port: u16) -> bool {
    purpose(proto, port).map_or(false, |p| p.risky_listen)
}
