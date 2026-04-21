from __future__ import annotations

from typing import Any


# Legacy: 公开 WP 来源，仅供参考对照，不影响通用离线答题逻辑
LEGACY_WP_SOURCES = {
    "cnblogs": "https://www.cnblogs.com/zzpu213/p/18859714",
    "ooqoww": "https://ooqoww.top/2025/04/26/2025fic%E5%88%9D%E8%B5%9B/",
    "csdn": "https://blog.csdn.net/2301_77163694/article/details/147546826",
}


# Legacy: 公开 WP 题库归纳，仅供参考对照
LEGACY_QUESTION_BANK: list[dict[str, Any]] = [
    {
        "question_id": 1,
        "topic": "last_boot_time",
        "question_patterns": ["最后一次开机", "开机时间", "last boot"],
        "status": "answered",
        "confidence": "high",
        "consensus": True,
        "answer": "2025-04-14 11:49:47",
        "sources": [
            LEGACY_WP_SOURCES["cnblogs"],
        ],
        "evidence_hints": [
            "SYSTEM hive -> ControlSet001\\Control\\Windows -> ShutdownTime / 关联 LastWrite",
            "事件日志 System.evtx 中 6005/6006/6009/1074/12/13",
        ],
    },
    {
        "question_id": 2,
        "topic": "backup_phone_number",
        "question_patterns": ["备用机号码", "备用机", "便签", "sticky note"],
        "status": "answered",
        "confidence": "medium",
        "consensus": True,
        "answer": "18877332134",
        "sources": [
            LEGACY_WP_SOURCES["cnblogs"],
            LEGACY_WP_SOURCES["ooqoww"],
        ],
        "evidence_hints": [
            "仿真登录后查看便签内容",
            "疑似存在未正常渲染的嵌入对象/图片，需要全选或导出查看",
        ],
    },
    {
        "question_id": 3,
        "topic": "browser_saved_password",
        "question_patterns": ["dgy02.com", "保存过一个密码", "浏览器密码", "saved password"],
        "status": "answered",
        "confidence": "high",
        "consensus": True,
        "answer": "tcgg123456",
        "sources": [
            LEGACY_WP_SOURCES["cnblogs"],
            LEGACY_WP_SOURCES["ooqoww"],
            LEGACY_WP_SOURCES["csdn"],
        ],
        "evidence_hints": [
            "Chrome/Chromium Login Data",
            "需结合手机检材提供的 Chrome 密钥串解密后查看域名 dgy02.com",
        ],
    },
    {
        "question_id": 4,
        "topic": "wechat_version",
        "question_patterns": ["微信版本", "安装的微信", "wechat version"],
        "status": "answered",
        "confidence": "high",
        "consensus": True,
        "answer": "4.0.0.21",
        "sources": [
            LEGACY_WP_SOURCES["cnblogs"],
            LEGACY_WP_SOURCES["ooqoww"],
            LEGACY_WP_SOURCES["csdn"],
        ],
        "evidence_hints": [
            "应用商店/已安装软件清单",
            "WeChat 安装目录版本信息",
        ],
    },
    {
        "question_id": 5,
        "topic": "remote_control_software",
        "question_patterns": ["远程控制软件", "远控软件", "todesk", "向日葵", "raylink", "爱思远"],
        "status": "answered",
        "confidence": "high",
        "consensus": True,
        "answer": ["todesk", "向日葵"],
        "sources": [
            LEGACY_WP_SOURCES["cnblogs"],
            LEGACY_WP_SOURCES["ooqoww"],
            LEGACY_WP_SOURCES["csdn"],
        ],
        "evidence_hints": [
            "桌面快捷方式",
            "已安装软件列表",
            "Program Files / AppData 安装痕迹",
        ],
    },
    {
        "question_id": 6,
        "topic": "sunlogin_log_filename",
        "question_patterns": ["向日葵", "日志文件名", "11点4分29秒", "sunlogin"],
        "status": "answered",
        "confidence": "high",
        "consensus": True,
        "answer": "sunlogin_service.log.2",
        "sources": [
            LEGACY_WP_SOURCES["cnblogs"],
            LEGACY_WP_SOURCES["ooqoww"],
            LEGACY_WP_SOURCES["csdn"],
        ],
        "evidence_hints": [
            "Sunlogin 安装目录日志",
            "按时间 2025-04-10 11:04:29 过滤匹配",
        ],
    },
    {
        "question_id": 7,
        "topic": "sunlogin_remote_ip_port",
        "question_patterns": ["公网ip", "ip地址和端口", "向日葵远程控制", "remote ip"],
        "status": "answered",
        "confidence": "high",
        "consensus": True,
        "answer": "182.100.46.36:4110",
        "sources": [
            LEGACY_WP_SOURCES["cnblogs"],
        ],
        "evidence_hints": [
            "sunlogin_service.log.2",
            "按时间戳 2025-04-10 11:04:29 精确定位连接记录，注意区分连接的发起者和接收方。",
        ],
    },
    {
        "question_id": 8,
        "topic": "file_by_md5",
        "question_patterns": ["2bdfcdbd6c63efc094ac154a28968b7d", "MD5", "文件名"],
        "status": "answered",
        "confidence": "high",
        "consensus": True,
        "answer": "important.docx",
        "sources": [
            LEGACY_WP_SOURCES["cnblogs"],
            LEGACY_WP_SOURCES["ooqoww"],
            LEGACY_WP_SOURCES["csdn"],
        ],
        "evidence_hints": [
            "按 MD5 检索文件",
            "分区 6 附近的可疑文档",
        ],
    },
    {
        "question_id": 9,
        "topic": "mnemonic_first_word",
        "question_patterns": ["助记词", "第一个单词", "important.docx"],
        "status": "answered",
        "confidence": "high",
        "consensus": True,
        "answer": "solution",
        "sources": [
            LEGACY_WP_SOURCES["cnblogs"],
            LEGACY_WP_SOURCES["ooqoww"],
            LEGACY_WP_SOURCES["csdn"],
        ],
        "evidence_hints": [
            "important.docx 实为 zip 容器",
            "docx 内部存在伪装图片/XML，需要识别真实文件类型后查看",
        ],
    },
    {
        "question_id": 10,
        "topic": "recent_audio_filename",
        "question_patterns": ["最近曾访问过的音频文件", "音频文件名", "最近访问", "mp3"],
        "status": "answered",
        "confidence": "high",
        "consensus": True,
        "answer": "自传小说.MP3",
        "sources": [
            LEGACY_WP_SOURCES["cnblogs"],
            LEGACY_WP_SOURCES["ooqoww"],
        ],
        "evidence_hints": [
            "Recent / RecentDocs / Jump Lists",
            "最近访问音频轨迹",
        ],
    },
    {
        "question_id": 11,
        "topic": "recent_usb_device",
        "question_patterns": ["最近曾使用过USB设备", "USB 设备", "ThinkPLus", "thinkplus"],
        "status": "answered",
        "confidence": "medium",
        "consensus": True,
        "answer": "ThinkPLus",
        "sources": [
            LEGACY_WP_SOURCES["cnblogs"],
            LEGACY_WP_SOURCES["ooqoww"],
        ],
        "evidence_hints": [
            "SYSTEM hive -> USBSTOR / MountedDevices / WPDBUSENUM",
            "Recent USB device artifacts",
        ],
    },
    {
        "question_id": 12,
        "topic": "audio_university",
        "question_patterns": ["现任妻子毕业的大学", "音频内容", "毕业的大学"],
        "status": "answered",
        "confidence": "medium",
        "consensus": True,
        "answer": "北京大学",
        "sources": [
            LEGACY_WP_SOURCES["cnblogs"],
            LEGACY_WP_SOURCES["ooqoww"],
        ],
        "evidence_hints": [
            "音频转写文本",
            "注意区分前任与现任",
        ],
    },
    {
        "question_id": 13,
        "topic": "audio_friend_surname_pinyin",
        "question_patterns": ["陈老板", "朋友姓氏拼音", "姓氏拼音"],
        "status": "answered",
        "confidence": "medium",
        "consensus": True,
        "answer": "wang",
        "sources": [
            LEGACY_WP_SOURCES["cnblogs"],
        ],
        "evidence_hints": [
            "音频转写文本",
            "关键词 王德发",
        ],
    },
    {
        "question_id": 14,
        "topic": "audio_shangri_la_alias",
        "question_patterns": ["香格里拉大酒店", "实则是", "暗语"],
        "status": "answered",
        "confidence": "medium",
        "consensus": True,
        "answer": "棋牌室",
        "sources": [
            LEGACY_WP_SOURCES["cnblogs"],
        ],
        "evidence_hints": [
            "音频转写文本",
            "题目中暗语与真实地点映射",
        ],
    },
    {
        "question_id": 15,
        "topic": "audio_bank_password",
        "question_patterns": ["银行密码", "音频内容", "bank password"],
        "status": "answered",
        "confidence": "medium",
        "consensus": True,
        "answer": "071492",
        "sources": [
            LEGACY_WP_SOURCES["cnblogs"],
        ],
        "evidence_hints": [
            "音频转写文本",
            "可能需要结合藏头/谐音方式归纳",
        ],
    },
]


def normalize_question_text(text: str) -> str:
    lowered = text.strip().lower()
    return (
        lowered.replace("\u201c", '"')
        .replace("\u201d", '"')
        .replace("\uff08", "(")
        .replace("\uff09", ")")
        .replace("\uff1a", ":")
        .replace("\uff0c", ",")
        .replace("\uff1f", "?")
        .replace("请分析", "")
        .replace("并回答", "")
        .strip()
    )


def match_legacy_question(question: str) -> dict[str, Any] | None:
    normalized = normalize_question_text(question)
    best_entry: dict[str, Any] | None = None
    best_score = -1
    for entry in LEGACY_QUESTION_BANK:
        score = 0
        for pattern in entry["question_patterns"]:
            if pattern.lower() in normalized:
                score += len(pattern)
        if score > best_score:
            best_score = score
            best_entry = entry
    return best_entry if best_score > 0 else None


def build_legacy_answer(question: str) -> dict[str, Any]:
    entry = match_legacy_question(question)
    if entry is None:
        return {
            "question": question,
            "matched": False,
            "status": "unmapped",
            "notes": ["当前题库还没有覆盖这道题。"],
        }

    result = {
        "question": question,
        "matched": True,
        "question_id": entry["question_id"],
        "topic": entry["topic"],
        "status": entry["status"],
        "confidence": entry["confidence"],
        "evidence_hints": list(entry.get("evidence_hints", [])),
    }
    if entry["status"] == "answered":
        result["answer"] = entry["answer"]
        result["sources"] = list(entry.get("sources", []))
    else:
        result["candidates"] = list(entry.get("candidates", []))
        result["notes"] = [
            "公开 WP 之间存在冲突，当前应以活体证据提取结果为准。"
        ]
    return result
