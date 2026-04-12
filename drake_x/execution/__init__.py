"""Drake-X execution foundation (v1.0, experimental).

A minimal job/queue/worker abstraction intended as the seam for a
future queue+workers deployment. v1.0 ships a local SQLite-backed
queue and a local synchronous worker only. No RPC, no remote
executors, no cluster scheduler.

The abstraction is real: every analysis that wants to be queueable
can declare a ``JobHandler`` callable and submit ``Job`` objects to a
``Queue``. The in-tree local worker drains them. Replacing the queue
with a remote implementation later is an additive change — the job
model and handler registry stay stable.

**Status: experimental.** Do not build production pipelines on this
surface yet; the interfaces may evolve before v1.1.
"""

from .jobs import Job, JobStatus, new_job
from .queue import LocalQueue, Queue
from .worker import LocalWorker, register_handler, registered_handlers

__all__ = [
    "Job", "JobStatus", "new_job",
    "Queue", "LocalQueue",
    "LocalWorker", "register_handler", "registered_handlers",
]
