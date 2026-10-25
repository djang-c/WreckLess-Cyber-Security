import re

import pytest

from wreckless import mascots as m

ESC = re.compile(r"\x1b\[[0-9;]*m")


@pytest.mark.parametrize("mode", ["truecolor", "256", "none"])
def test_every_role_task_mood_renders_same_size(mode):
    sizes = set()
    for role in m.ROLE_COLORS:
        for task in m.TASKS:
            for mood in m.MOODS:
                for t in (0.0, 0.1, 0.2, 0.3, 1.0, 3.1):
                    lines = m.render(m.pixels(role, task, mood, t), mode)
                    sizes.add((len(lines), max(len(ESC.sub("", ln)) for ln in lines)))
    assert sizes == {((m.HAT_H + m.BODY_H + 2) // 2, m.W)}


def test_plain_mode_has_no_escapes_and_keeps_the_eyes():
    for role in m.ROLE_COLORS:
        grid = m.pixels(role, "idle", "idle", 1.0)
        lines = m.render(grid, "none")
        assert not any("\x1b" in ln for ln in lines)
        no_eyes = [[None if c in (m.INK["e"], m.INK["E"]) else c for c in row] for row in grid]
        assert any(c == m.INK["e"] for row in grid for c in row)
        assert m.render(no_eyes, "none") == lines  # eyes render as holes, not blocks
        assert m.render([[c and m.ROLE_COLORS[role][0] for c in row] for row in grid], "none") != lines


def test_every_hat_and_task_is_wired():
    assert all(hat in m.HATS and prop in m.PROPS for hat, prop, _ in m.TASKS.values())
    assert set(m.TASK_OF.values()) <= set(m.TASKS)
    assert all(task in m.TASKS and mood in m.MOODS
               for story in m.STORY.values() for task, mood, _ in story)


def test_every_role_has_its_own_silhouette():
    assert len({tuple(s["body"]) for s in m.SHAPES.values()}) == len(m.ROLE_COLORS)


def test_story_roles_stay_in_lockstep():
    lengths = {sum(d for *_, d in s) for s in m.STORY.values()}
    assert len(lengths) == 1


def test_flock_follows_the_pipeline():
    f = m.Flock()
    f.apply({"t": 0, "actor": "purple", "kind": "mascot", "task": "intel"})
    f.apply({"t": 0, "actor": "core", "kind": "enqueue", "source": "purple"})
    assert f.now(0.5)["purple"] == ("done", "happy")
    f.apply({"t": 0, "actor": "red", "kind": "mascot", "task": "exploit"})
    f.apply({"t": 1, "actor": "red", "kind": "task", "task": "sandbox"})
    assert f.now(1)["red"] == ("sandbox", "work")
    f.apply({"t": 2, "actor": "gate", "kind": "transition", "to": "verified"})
    assert f.now(3)["red"] == f.now(3)["gate"] == ("done", "happy")
    assert f.now(10)["red"] == ("idle", "idle")  # the cheer wears off
    f.apply({"t": 11, "actor": "blue", "kind": "mascot", "task": None})
    assert f.now(11)["blue"] == ("patch", "work")
    f.apply({"t": 12, "actor": "blue", "kind": "transition", "to": "patch_failed"})
    assert f.now(13)["blue"] == ("idle", "sad")


def test_flock_stands_down_when_an_item_ends():
    f = m.Flock()
    f.apply({"t": 0, "actor": "red", "kind": "mascot", "task": "exploit"})
    f.apply({"t": 1, "actor": "gate", "kind": "transition", "to": "rejected"})
    assert f.now(2)["red"] == ("idle", "sad")
    assert f.now(2)["blue"] == ("idle", "idle")


def test_labels_fit():
    assert all(len(label) <= m.LABEL_W for *_, label in m.TASKS.values())
    assert set(m.STAGE_TASK) == set(m.ROLE_COLORS)


def test_monocle_ring_is_whole_in_every_mood():
    for role in m.ROLE_COLORS:
        for mood in m.MOODS:
            g = m.pixels(role, "read", mood, 1.0)
            assert sum(row.count(m.INK["y"]) for row in g) == 6, (role, mood)
