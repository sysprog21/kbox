# scripts/gdb/kbox-events.py
# 事件式條件斷點:用 Python 的 stop() 取代 GDB 原生條件,
# 支援原生條件做不到的判斷(字串比對、走訪 task 結構)。
# 載入方式:GDB 內  source scripts/gdb/kbox-events.py

import gdb


def _safe_eval(expr):
    """求值失敗(prologue 中、符號不可見)時回 None,不丟例外。"""
    try:
        return gdb.parse_and_eval(expr)
    except gdb.error:
        return None


class KboxBreakOnPid(gdb.Breakpoint):
    """在 FUNC 停,但只有當 TASK_EXPR->pid == 目標 PID 時才真的中斷。"""
    def __init__(self, func, pid, task_expr):
        super().__init__(func)
        self.target_pid = int(pid)
        self.task_expr = task_expr        # 例如 __schedule 內的 "prev"

    def stop(self):
        task = _safe_eval(self.task_expr)
        if task is None:
            return False                  # 引數尚不可見(prologue)就放行
        try:
            return int(task["pid"]) == self.target_pid
        except (gdb.error, gdb.MemoryError):
            return False


class KboxBreakPidCmd(gdb.Command):
    """kbox-break-pid PID FUNC TASK_EXPR
       例:kbox-break-pid 42 __schedule prev"""
    def __init__(self):
        super().__init__("kbox-break-pid", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        parts = arg.split()
        if len(parts) != 3:
            print("用法:kbox-break-pid PID FUNC TASK_EXPR")
            return
        pid, func, task_expr = parts
        bp = KboxBreakOnPid(func, pid, task_expr)
        print(f"Breakpoint {bp.number}: 停在 {func},當 {task_expr}->pid == {pid}")


class KboxBreakOnOpen(gdb.Breakpoint):
    """在 do_sys_openat2 停,但只有開啟路徑含指定子字串時才中斷。"""
    def __init__(self, needle):
        super().__init__("do_sys_openat2")
        self.needle = needle

    def stop(self):
        fn = _safe_eval("filename")
        if fn is None:
            return False
        try:
            path = fn.string()
        except (gdb.error, gdb.MemoryError):
            return False
        if self.needle in path:
            print(f"[kbox-events] openat 命中: {path}")
            return True
        return False


class KboxBreakOpenCmd(gdb.Command):
    """kbox-break-openat SUBSTR
       例:kbox-break-openat /etc/hostname"""
    def __init__(self):
        super().__init__("kbox-break-openat", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        needle = arg.strip()
        if not needle:
            print("用法:kbox-break-openat SUBSTR(路徑子字串)")
            return
        bp = KboxBreakOnOpen(needle)
        print(f"Breakpoint {bp.number}: 停在 do_sys_openat2,當開啟路徑含 '{needle}'")


KboxBreakPidCmd()
KboxBreakOpenCmd()
print("kbox-events.py 已載入:kbox-break-pid、kbox-break-openat")
