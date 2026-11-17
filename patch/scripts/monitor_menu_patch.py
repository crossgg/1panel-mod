#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""向 core.db settings.HideMenu 注入「网站监控」独立一级菜单节点。"""
import json
import shutil
import sqlite3

DB = "/opt/1panel/db/core.db"

NODE = {
    "label": "WafMonitor-Menu",
    "title": "网站监控",
    "path": "/waf-monitor",
    "sort": 451,
    "icon": "p-waf-3",
}


def main():
    shutil.copy2(DB, DB + ".wafmenu.bak")
    con = sqlite3.connect(DB)
    row = con.execute("select value from settings where key='HideMenu'").fetchone()
    menu = json.loads(row[0]) if row else []

    node = None
    for it in menu:
        if it.get("label") == NODE["label"]:
            node = it
            break
    if node is None:
        node = dict(NODE)
        node["isShow"] = True
        node["disabled"] = False
        menu.append(node)
    node.update({k: NODE[k] for k in ("title", "path", "sort", "icon")})
    node["isShow"] = True
    node["disabled"] = False
    node.setdefault("children", [])
    for c in node["children"]:
        c["isShow"] = True
        c["disabled"] = False

    menu.sort(key=lambda x: x.get("sort", 0))
    con.execute("update settings set value=? where key='HideMenu'", (json.dumps(menu, ensure_ascii=False),))
    con.commit()
    print("WafMonitor-Menu injected; siblings:")
    for it in menu:
        print("  sort=%s %s (%s)" % (it.get("sort"), it.get("label"), it.get("title")))
    con.close()


if __name__ == "__main__":
    main()
