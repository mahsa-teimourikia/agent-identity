from enum import Enum
class State(str,Enum):
    DRAFT="draft"; PENDING="pending_approval"; APPROVED="approved"; ACTIVE="active"
    SUSPENDED="suspended"; QUARANTINED="quarantined"; RETIRED="retired"; REVOKED="revoked"
ALLOWED={
 State.DRAFT:{State.PENDING},
 State.PENDING:{State.APPROVED,State.REVOKED},
 State.APPROVED:{State.ACTIVE,State.REVOKED},
 State.ACTIVE:{State.SUSPENDED,State.QUARANTINED,State.RETIRED,State.REVOKED},
 State.SUSPENDED:{State.ACTIVE,State.RETIRED,State.REVOKED},
 State.QUARANTINED:{State.SUSPENDED,State.REVOKED},
 State.RETIRED:{State.REVOKED},
 State.REVOKED:set()
}
def transition(current,target):
    current,target=State(current),State(target)
    if target not in ALLOWED[current]: raise ValueError(f"illegal transition {current}->{target}")
    return target.value
