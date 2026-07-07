# scripts/drgn/kbox_tasks.py
# 走訪 LKL task list,印 PID / COMM / STATE,用於與 lx-ps / kbox-task-walk 交叉驗證。
from drgn.helpers.linux.pid import for_each_task

STATE_NAMES = {
    0x0000: "RUNNING",
    0x0001: "INTERRUPTIBLE",
    0x0002: "UNINTERRUPTIBLE",
    0x0004: "STOPPED",
    0x0008: "TRACED",
    0x0402: "IDLE",              # TASK_UNINTERRUPTIBLE | TASK_NOLOAD
}

def state_name(task):
    try:
        s = task.member_("__state").value_()
    except Exception:
        return "?"
    return STATE_NAMES.get(s, hex(s))

print(f"{'PID':>5}  {'COMM':<18} STATE")
print("-" * 42)
count = 0
for task in for_each_task(prog):
    print(f"{task.pid.value_():>5}  {task.comm.string_().decode():<18} {state_name(task)}")
    count += 1
print(f"\n共 {count} 個 task")
