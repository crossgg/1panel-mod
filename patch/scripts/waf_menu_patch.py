#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""向 core.db settings.HideMenu 注入/更新 WAF 侧边栏节点，并对齐官方顺序。

官方顺序（demo.1panel.cn 反解得到的 8 条路由）：
  dashboard → stat → log → block → blackwhite → websites → websites/:id → global

本项目对应：概览 → 拦截日志 → 封锁记录 → 黑白名单 → 网站设置 →（自定义规则）→ 全局设置
"""
import json
import shutil
import sqlite3

DB = "/opt/1panel/db/core.db"

TARGET = {
    "WafLog-Menu": {
        "label": "WafLog-Menu",
        "title": "WAF",
        "path": "/waf-log",
        "sort": 450,
        "icon": "p-waf-menu",
    },
    # sort 间隔 1，严格按官方 IA 排列
    "children": [
        {"id": "9001", "label": "WafLogOverview", "title": "概览", "path": "/waf-log/overview", "sort": 440, "icon": "p-waf-2"},
        {"id": "9002", "label": "WafLog", "title": "拦截日志", "path": "/waf-log/list", "sort": 441, "icon": "p-waf-1"},
        {"id": "9007", "label": "WafLogBlock", "title": "封锁记录", "path": "/waf-log/block", "sort": 442, "icon": "p-waf-6"},
        {"id": "9005", "label": "WafLogBw", "title": "黑白名单", "path": "/waf-log/blackwhite", "sort": 443, "icon": "p-waf-4"},
        {"id": "9003", "label": "WafLogSite", "title": "网站设置", "path": "/waf-log/site", "sort": 444, "icon": "p-waf-3"},
        {"id": "9006", "label": "WafLogRule", "title": "自定义规则", "path": "/waf-log/custom", "sort": 445, "icon": "p-waf-5"},
        {"id": "9004", "label": "WafLogSetting", "title": "全局设置", "path": "/waf-log/setting", "sort": 446, "icon": "p-setting-1"},
    ],
}


def main():
    shutil.copy2(DB, DB + ".wafmenu.bak")
    con = sqlite3.connect(DB)
    row = con.execute("select value from settings where key='HideMenu'").fetchone()
    menu = json.loads(row[0]) if row else []

    node = None
    for it in menu:
        if it.get("label") == "WafLog-Menu":
            node = it
            break
    if node is None:
        node = dict(TARGET["WafLog-Menu"])
        node["children"] = []
        node["isShow"] = True
        node["disabled"] = False
        menu.append(node)

    keep_children = node.get("children") or []
    node.pop("children", None)
    node.setdefault("isShow", True)
    node["disabled"] = False
    node["sort"] = 450

    children = {c.get("label"): c for c in keep_children}
    newkids = []
    for spec in TARGET["children"]:
        cur = children.get(spec["label"]) or {}
        cur.update(spec)
        cur["isShow"] = True
        cur["disabled"] = False
        newkids.append(cur)
    # 保留其它未知子节点
    known = {s["label"] for s in TARGET["children"]}
    for lbl, c in children.items():
        if lbl not in known:
            c.setdefault("isShow", True)
            c["disabled"] = False
            newkids.append(c)
    newkids.sort(key=lambda x: x.get("sort", 0))
    node["children"] = newkids

    menu.sort(key=lambda x: x.get("sort", 0))

    con.execute("update settings set value=? where key='HideMenu'", (json.dumps(menu, ensure_ascii=False),))
    con.commit()

    for it in menu:
        if it.get("label") == "WafLog-Menu":
            print(json.dumps(it, ensure_ascii=False, indent=2))
    con.close()


if __name__ == "__main__":
    main()
