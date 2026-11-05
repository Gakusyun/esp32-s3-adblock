# 面板产物 data/index.html.gz 不入库（见 .gitignore），刷文件系统前先构建，
# 否则设备上只有 page.h 那个"面板未烧录"的兜底页。这里只在缺失时提醒，不中断构建。
import os

Import("env")  # noqa: F821

_path = os.path.join(env.subst("$PROJECT_DIR"), "data", "index.html.gz")  # noqa: F821


def _warn_missing(source, target, env):  # noqa: ARG001
    if not os.path.exists(_path):
        print(
            "\n[s3-adblock] 注意：data/index.html.gz 不存在。\n"
            "             先执行 `cd web && npm install && npm run build`，"
            "再 `pio run -e s3 -t uploadfs`。\n"
            "             否则设备只会显示内置的兜底提示页。\n"
        )


env.AddPreAction("buildfs", _warn_missing)  # noqa: F821
env.AddPreAction("uploadfs", _warn_missing)  # noqa: F821
