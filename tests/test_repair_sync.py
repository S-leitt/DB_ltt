import os
import sys
from datetime import datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# 使用SQLite测试模式，避免依赖真实数据库驱动
os.environ.setdefault("DB_MODE", "sqlite")

from app import main
from app.models import Exam, Question, Score, User


class DummyQuery:
    def __init__(self, items):
        self._items = items

    def all(self):
        return list(self._items)


class DummySession:
    def __init__(self, data_map):
        self._data_map = data_map
        self.added = []
        self.exec_calls = []
        self.committed = False
        self.rolled_back = False
        self.closed = False

    def query(self, model):
        return DummyQuery(self._data_map.get(model, []))

    def add(self, obj):
        self.added.append(obj)

    def execute(self, *args, **kwargs):
        self.exec_calls.append((args, kwargs))

    def commit(self):
        self.committed = True

    def rollback(self):
        self.rolled_back = True

    def close(self):
        self.closed = True


def test_repair_sync_completes_without_attribute_errors(monkeypatch):
    now = datetime.utcnow()

    mysql_session = DummySession(
        {
            User: [
                User(
                    id=1,
                    username="tester",
                    email="tester@example.com",
                    password_hash="hashed",
                    role="ADMIN",
                    created_at=now,
                    updated_at=now,
                )
            ],
            Exam: [
                Exam(
                    id=1,
                    name="Midterm",
                    start_time=now,
                    end_time=now,
                    created_at=now,
                    updated_at=now,
                )
            ],
            Question: [
                Question(
                    id=1,
                    guid="q-1",
                    content="Example?",
                    answer="Yes",
                    score=5.0,
                    created_at=now,
                    updated_at=now,
                )
            ],
            Score: [
                Score(
                    id=1,
                    user_id=1,
                    exam_id=1,
                    score_value=95.0,
                    created_at=now,
                    updated_at=now,
                )
            ],
        }
    )

    target_session = DummySession({})

    def fake_get_session(db_name):
        session = mysql_session if db_name == "mysql" else target_session

        def _generator():
            try:
                yield session
            finally:
                session.close()

        return _generator()

    monkeypatch.setattr(main, "get_session", fake_get_session)

    response = main.repair_sync(
        main.RepairSyncRequest(db_name="oracle", event_type="full")
    )

    assert response["status"] == "success"
    assert target_session.committed is True

    score_obj = next(obj for obj in target_session.added if isinstance(obj, Score))
    assert score_obj.exam_id == 1

    exam_obj = next(obj for obj in target_session.added if isinstance(obj, Exam))
    assert exam_obj.name == "Midterm"
    assert exam_obj.start_time == now
    assert exam_obj.end_time == now
